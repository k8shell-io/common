// Copyright 2025 the k8Shell authors

package rest

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/k8shell-io/common/pkg/logger"
	"github.com/k8shell-io/common/pkg/models"
	"github.com/rs/zerolog"

	"github.com/gin-gonic/gin"
)

type HTTPConfig struct {
	Port   int          `yaml:"port"`
	Cookie CookieConfig `yaml:"cookie"`

	Logging HTTPLoggingConfig `yaml:"logging"`
}

// HTTPLoggingConfig controls request/response logging behavior.
type HTTPLoggingConfig struct {
	Enabled         bool `yaml:"enabled"`
	RequestHeaders  bool `yaml:"requestHeaders"`
	ResponseHeaders bool `yaml:"responseHeaders"`
}

type Handler interface {
	InitializeRoutes(r *gin.Engine)
	GetUser(ctx context.Context, token string) (*models.User, error)
}

// RESTApiService represents the REST API service
type RESTAPI struct {
	Handler
	httpConfig HTTPConfig
	log        *zerolog.Logger
	engine     *gin.Engine
	server     *http.Server
}

// NewRESTAPI creates a new REST API service
func NewRESTAPI(httpConfig HTTPConfig, handler Handler) (*RESTAPI, error) {
	sameSite, err := ParseSameSite(httpConfig.Cookie.SameSite)
	if err != nil {
		return nil, fmt.Errorf("parse session cookie SameSite: %w", err)
	}

	httpConfig.Cookie.sameSite = sameSite
	if httpConfig.Cookie.Name == "" {
		return nil, fmt.Errorf("cookie name cannot be empty")
	}
	if httpConfig.Cookie.Path == "" {
		httpConfig.Cookie.Path = "/"
	}
	if httpConfig.Cookie.MaxAgeSeconds == 0 {
		httpConfig.Cookie.MaxAgeSeconds = int((8 * time.Hour).Seconds())
	}

	gin.SetMode(gin.ReleaseMode)

	a := &RESTAPI{
		Handler:    handler,
		httpConfig: httpConfig,
		log:        logger.NewLogger("api"),
		engine:     gin.New(),
	}

	a.server = &http.Server{
		Handler: a.engine,
		Addr:    fmt.Sprintf(":%d", a.httpConfig.Port),
	}

	return a, nil
}

func (a *RESTAPI) LoggingMiddleware() gin.HandlerFunc {
	if !a.httpConfig.Logging.Enabled {
		return func(c *gin.Context) {
			c.Next()
		}
	}

	return func(c *gin.Context) {
		start := time.Now()

		var reqHeaders, respHeaders map[string]string
		if a.httpConfig.Logging.RequestHeaders {
			reqHeaders = HeaderMapToLog(c.Request.Header)
		}

		c.Next()

		latency := time.Since(start)
		status := c.Writer.Status()
		ip := c.ClientIP()
		method := c.Request.Method
		path := c.Request.URL.Path

		if a.httpConfig.Logging.ResponseHeaders {
			respHeaders = HeaderMapToLog(c.Writer.Header())
		}

		ev := a.log.Info().
			Str("method", method).
			Int("status", status).
			Str("path", path).
			Str("ip", ip).
			Dur("duration", latency)

		if a.httpConfig.Logging.RequestHeaders && reqHeaders != nil {
			ev = ev.Interface("req_headers", reqHeaders)
		}
		if a.httpConfig.Logging.ResponseHeaders && respHeaders != nil {
			ev = ev.Interface("resp_headers", respHeaders)
		}

		ev.Msg("request")
	}
}

// SessionTelemetryMiddleware updates basic client info in the session.
func (a *RESTAPI) SessionTelemetryMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if sess, _ := MustGetSessionFromContext(c); sess != nil {
			sess.Set("client_ip", c.ClientIP())
			sess.Set("last_seen", time.Now().UTC().Format(time.RFC3339))
		}
		c.Next()
	}
}

// AuthMiddleware creates a middleware for token authentication and user validation
// It checks for a Bearer token in the Authorization header or a token stored in the session.
func (a *RESTAPI) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()

		var token string
		if authHeader := c.GetHeader("Authorization"); authHeader != "" {
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") && parts[1] != "" {
				token = parts[1]
				c.Set("use_cookie", false)
			}
		} else {
			c.Set("use_cookie", true)
		}

		if token == "" {
			sess, err := MustGetSessionFromContext(c)
			if err != nil {
				c.JSON(500, gin.H{"error": "failed to get session"})
				return
			}
			if v, ok := sess.Get("user_token"); ok {
				if s, ok := v.(string); ok && s != "" {
					token = s
				}
			}
		}

		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"status": http.StatusUnauthorized,
				"msg": "Unauthorized"})
			return
		}

		user, err := a.GetUser(ctx, token)
		if err != nil {
			a.log.Error().Err(err).Msg("Failed to get user from token")
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"status": http.StatusInternalServerError,
				"msg": "Internal Server Error"})
			return
		}

		if user == nil || user.Username == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"status": http.StatusUnauthorized,
				"msg": "Unauthorized"})
			return
		}

		// TODO: check if the user is authorized to access the requested resource
		// e.g., check roles/permissions/scopes
		// For now, we just check if the username in the URL matches the authenticated user
		username := c.Param("username")
		if username != "" && username != user.Username {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"status": http.StatusForbidden,
				"msg": "Forbidden"})
			return
		}

		c.Set("user", user)
		c.Next()
	}
}

// Serve starts the REST server and listens for incoming requests.
func (a *RESTAPI) Serve(ctx context.Context) error {
	a.InitializeRoutes(a.engine)
	a.log.Info().Msgf("Starting server on %s", a.server.Addr)
	if err := a.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("listen and serve: %w", err)
	}
	return nil
}

func (a *RESTAPI) Shutdown() {
	a.log.Info().Msg("Shutting down server...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := a.server.Shutdown(shutdownCtx); err != nil {
		a.log.Error().Err(err).Msg("Server shutdown failed")
	} else {
		a.log.Info().Msg("Server shutdown complete")
	}
}

// *** Helper functions ***

// GetLimitOffsetReverseFromQuery extracts pagination parameters from the query string.
func GetLimitOffsetReverseFromQuery(c *gin.Context) (limit, offset int, reverse bool) {
	limit = 50
	offset = 0
	limitStr := c.Query("limit")
	offsetStr := c.Query("offset")

	if limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
			limit = parsedLimit
		}
	}

	if offsetStr != "" {
		if parsedOffset, err := strconv.Atoi(offsetStr); err == nil && parsedOffset >= 0 {
			offset = parsedOffset
		}
	}

	reverseStr := c.Query("reverse")
	reverse = false
	if reverseStr != "" {
		if parsedReverse, err := strconv.ParseBool(reverseStr); err == nil {
			reverse = parsedReverse
		}
	}

	return limit, offset, reverse
}

// GetCurrentUserFromContext retrieves the current user from the Gin context.
func GetCurrentUserFromContext(c *gin.Context) (*models.User, bool) {
	v, ok := c.Get("user")
	if !ok || v == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"status": http.StatusUnauthorized,
			"msg":    "Unauthorized",
		})
		return nil, false
	}
	user, ok := v.(*models.User)
	if !ok {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"status": http.StatusInternalServerError,
			"msg":    "Internal Server Error",
		})
		return nil, false
	}
	return user, true
}

// Convert http.Header to a loggable map and redact sensitive values
func HeaderMapToLog(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[k] = strings.Join(v, ", ")
	}
	return out
}
