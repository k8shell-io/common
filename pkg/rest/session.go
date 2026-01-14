package rest

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/k8shell-io/common/pkg/logger"
	natsc "github.com/k8shell-io/common/pkg/nats"
)

type CookieConfig struct {
	Name          string `yaml:"name"`
	Path          string `yaml:"path"`
	Domain        string `yaml:"domain"`
	Secure        bool   `yaml:"secure"`
	SameSite      string `yaml:"sameSite"`
	HttpOnly      bool   `yaml:"httpOnly"`
	MaxAgeSeconds int    `yaml:"maxAgeSeconds"`
	SlideTTL      bool   `yaml:"slideTTL"`

	sameSite http.SameSite
}

// key is the context key type for storing the session in the request context.
type key int

// sessionCtxKey is the context key for storing the session in the request context.
const sessionCtxKey key = 0

// Session represents a user session with methods to manage session data.
type Session struct {
	id        string
	values    map[string]any
	dirty     bool
	destroyed bool
	renewed   bool
}

func (s *Session) ID() string               { return s.id }
func (s *Session) Get(k string) (any, bool) { v, ok := s.values[k]; return v, ok }
func (s *Session) Set(k string, v any)      { s.values[k] = v; s.dirty = true }
func (s *Session) Del(k string)             { delete(s.values, k); s.dirty = true }
func (s *Session) All() map[string]any      { return s.values }
func (s *Session) Destroy()                 { s.destroyed = true }

// RegenerateID generates a new session ID for the session.
func (s *Session) RegenerateID() (string, error) {
	nid, err := newSessionID()
	if err != nil {
		return "", err
	}
	s.id, s.renewed = nid, true
	return nid, nil
}

// NewMiddleware returns a Gin middleware that provides session management using JetStream.
func (a *RESTAPI) SessionMiddleware(kv *natsc.JetStreamKV) gin.HandlerFunc {

	log := logger.NewLogger("session")

	return func(c *gin.Context) {
		s := &Session{values: make(map[string]any)}
		if sid, err := c.Cookie(a.httpConfig.Cookie.Name); err == nil && sid != "" {
			if it, err := kv.Get(sid); err == nil {
				_ = json.Unmarshal(it.Value(), &s.values)
				s.id = sid
			}
		}
		if s.id == "" {
			if nid, err := newSessionID(); err == nil {
				s.id = nid
				s.dirty = true
			} else {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "session init failed"})
				return
			}
		}
		ctx := context.WithValue(c.Request.Context(), sessionCtxKey, s)
		c.Request = c.Request.WithContext(ctx)

		sw := &commitWriter{
			ResponseWriter: c.Writer,
			commit: func() {
				err := persist(c, kv, s, a.httpConfig.Cookie)
				if err != nil {
					log.Warn().Err(err).Msgf("Failed to persist session: %v", err)
				}
			},
		}
		c.Writer = sw

		c.Next()

		if !sw.committed {
			sw.commit()
			sw.committed = true
		}
	}
}

// commitWriter wraps gin.ResponseWriter to commit session changes before writing response.
type commitWriter struct {
	gin.ResponseWriter
	committed bool
	commit    func()
}

// WriteHeader writes the HTTP header with the given status code.
func (w *commitWriter) WriteHeader(code int) {
	if !w.committed {
		w.commit()
		w.committed = true
	}
	w.ResponseWriter.WriteHeader(code)
}

// Write writes the data to the connection as part of an HTTP reply.
func (w *commitWriter) Write(b []byte) (int, error) {
	if !w.committed {
		w.commit()
		w.committed = true
	}
	return w.ResponseWriter.Write(b)
}

// persist saves or deletes the session in JetStream and manages the session cookie.
func persist(c *gin.Context, kv *natsc.JetStreamKV, s *Session, cookie CookieConfig) error {
	if s.destroyed {
		_ = kv.Delete(s.id)
		expireCookie(c, cookie)
		return nil
	}

	var err error
	if s.dirty || s.renewed || cookie.SlideTTL {
		b, _ := json.Marshal(s.values)
		_, err = kv.Set(s.id, b)
		if err != nil {
			err = fmt.Errorf("failed to persist session: %w", err)
		}
		writeCookie(c, cookie, s.id, time.Now().Add(time.Duration(cookie.MaxAgeSeconds)*time.Second))
	}
	return err
}

// writeCookie sets the session cookie in the HTTP response.
func writeCookie(c *gin.Context, cookie CookieConfig, val string, exp time.Time) {
	if useCookie, exists := c.Get("use_cookie"); exists && useCookie.(bool) {
		sameSite, _ := ParseSameSite(cookie.SameSite)
		http.SetCookie(c.Writer, &http.Cookie{
			Name:     cookie.Name,
			Value:    val,
			Path:     cookie.Path,
			Domain:   cookie.Domain,
			Expires:  exp,
			MaxAge:   int(time.Until(exp).Seconds()),
			HttpOnly: cookie.HttpOnly,
			SameSite: sameSite,
			Secure:   cookie.Secure,
		})
	}
}

// expireCookie expires the session cookie in the HTTP response.
func expireCookie(c *gin.Context, cookie CookieConfig) {
	saeSite, _ := ParseSameSite(cookie.SameSite)
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     cookie.Name,
		Value:    "",
		Path:     cookie.Path,
		Domain:   cookie.Domain,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: cookie.HttpOnly,
		SameSite: saeSite,
		Secure:   cookie.Secure,
	})
}

// GetSessionFromContext retrieves the session from the Gin context.
func GetSessionFromContext(c *gin.Context) *Session {
	if v := c.Request.Context().Value(sessionCtxKey); v != nil {
		if s, ok := v.(*Session); ok {
			return s
		}
	}
	return nil
}

// MustGetSessionFromContext retrieves the session from the Gin context or returns an error if not found.
func MustGetSessionFromContext(c *gin.Context) (*Session, error) {
	s := GetSessionFromContext(c)
	if s == nil {
		return nil, errors.New("session not found in context")
	}
	return s, nil
}

// newSessionID generates a new secure random session ID.
func newSessionID() (string, error) {
	b := make([]byte, 32) // 256-bit
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// parseSameSite converts a string representation of SameSite to http.SameSite type.
func ParseSameSite(v string) (http.SameSite, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "lax":
		return http.SameSiteLaxMode, nil
	case "strict":
		return http.SameSiteStrictMode, nil
	case "none":
		return http.SameSiteNoneMode, nil
	case "default", "":
		return http.SameSiteDefaultMode, nil
	default:
		return http.SameSiteDefaultMode, fmt.Errorf("invalid SameSite value: %s", v)
	}
}
