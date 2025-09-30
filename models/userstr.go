// K8shell user string parser
//
// Spec summary (v1.0):
//
//	USERSTR = user [ "~" ws-spec ]
//	ws-spec = bp-name | param-list
//	param-list = kv *( "+" kv )
//	kv = key "=" value
//
// - Percent-decode only blueprint names and values (NOT keys).
// - Keys are normalized to lowercase.
// - Slash "/" is allowed; when escaped as %2F it is decoded back to "/".
// - Reserved delimiters: @ ~ + = (use %XX inside values if literal needed).
package models

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"
)

const (
	MAX_LOCAL_LEN = 64
	MAX_TOTAL_LEN = 128
)

var (
	ErrBadParam = errors.New("userstr: bad param (expected key=value)")
	ErrTooLong  = errors.New("userstr: identifier too long")
)

// UserStr is the parsed representation of a user string.
type UserStr struct {
	Raw                string            // original input
	Username           string            // username (left of ~ or whole local if no ~)
	Blueprint          string            // blueprint name
	ParamsRaw          map[string]string // normalized keys to values (if params form)
	RepoName           string            // shortcut for Params["repo"]
	RepoOwner          string            // shortcut for Params["owner"]
	RepoRef            string            // shortcut for Params["ref"]
	HasCustomBlueprint bool              // indicates if the blueprint is custom
}

// UserStrBuilder is a builder for creating UserStr instances.
type UserStrBuilder struct {
	username  string
	blueprint string
	params    map[string]string
}

// NewUserStr parses a user string using default length constraints.
func NewUserStr(input string) (*UserStr, error) {
	if MAX_TOTAL_LEN > 0 && utf8.RuneCountInString(input) > MAX_TOTAL_LEN {
		return nil, fmt.Errorf("%w: total>%d", ErrTooLong, MAX_TOTAL_LEN)
	}

	if MAX_LOCAL_LEN > 0 && utf8.RuneCountInString(input) > MAX_LOCAL_LEN {
		return nil, fmt.Errorf("%w: local>%d", ErrTooLong, MAX_LOCAL_LEN)
	}

	input = strings.ToLower(strings.TrimSpace(input))

	username, wsSpec, _ := cutOnce(input, "~")

	if wsSpec == "" {
		return &UserStr{
			Raw:       input,
			Username:  username,
			Blueprint: "",
			ParamsRaw: nil,
		}, nil
	}

	if !strings.Contains(wsSpec, "=") {
		decoded, err := url.PathUnescape(wsSpec)
		if err != nil {
			return nil, fmt.Errorf("userstr: blueprint percent-decode: %w", err)
		}
		return &UserStr{
			Raw:       input,
			Username:  username,
			Blueprint: decoded,
			ParamsRaw: nil,
		}, nil
	}

	pairs := strings.Split(wsSpec, "+")
	params := make(map[string]string, len(pairs))
	for _, p := range pairs {
		if p == "" {
			return nil, fmt.Errorf("%w: empty pair", ErrBadParam)
		}
		k, v, ok := cutOnce(p, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("%w: %q", ErrBadParam, p)
		}

		if strings.Contains(v, "=") {
			return nil, fmt.Errorf("%w: unescaped '=' in value: %q", ErrBadParam, p)
		}

		k = strings.ToLower(k)

		val, err := url.PathUnescape(v)
		if err != nil {
			return nil, fmt.Errorf("%w: value decode failed for key %q: %v", ErrBadParam, k, err)
		}

		params[k] = val
	}

	var repoName string
	var repoOwner string = username
	if repo := params["repo"]; repo != "" {
		if owner, name, found := cutOnce(repo, "/"); found {
			repoOwner = owner
			repoName = name
		} else {
			repoName = repo
		}
	}
	if owner := params["owner"]; owner != "" {
		repoOwner = owner
	}

	var blueprintName = ""
	if repoOwner != "" && repoName != "" {
		blueprintName = fmt.Sprintf("repo-%s-%s", repoOwner, repoName)
	}

	return &UserStr{
		Raw:                input,
		Username:           username,
		Blueprint:          blueprintName,
		ParamsRaw:          params,
		RepoName:           repoName,
		RepoOwner:          repoOwner,
		RepoRef:            params["ref"],
		HasCustomBlueprint: blueprintName != "",
	}, nil
}

// cutOnce splits s at the first instance of sep. Returns before, after, and whether sep was found.
func cutOnce(s, sep string) (string, string, bool) {
	i := strings.Index(s, sep)
	if i < 0 {
		return s, "", false
	}
	return s[:i], s[i+len(sep):], true
}

// *** UserStrBuilder

// NewUserStrWith starts building a UserStr for the given username.
func NewUserStrWith(username string) *UserStrBuilder {
	return &UserStrBuilder{
		username: username,
		params:   make(map[string]string),
	}
}

func (b *UserStrBuilder) WithBlueprint(bp string) *UserStrBuilder {
	b.blueprint = bp
	return b
}

func (b *UserStrBuilder) WithRepo(repo string) *UserStrBuilder {
	b.params["repo"] = repo
	return b
}

func (b *UserStrBuilder) WithOwner(owner string) *UserStrBuilder {
	b.params["owner"] = owner
	return b
}

func (b *UserStrBuilder) WithRef(ref string) *UserStrBuilder {
	b.params["ref"] = ref
	return b
}

func (b *UserStrBuilder) WithParam(key, value string) *UserStrBuilder {
	b.params[strings.ToLower(key)] = value
	return b
}

// Build assembles the UserStr (and runs through your normal parser for consistency).
func (b *UserStrBuilder) Build() (*UserStr, error) {
	var raw string

	if b.blueprint != "" && len(b.params) == 0 {
		raw = fmt.Sprintf("%s~%s", b.username, url.PathEscape(b.blueprint))
	} else if len(b.params) > 0 {
		var parts []string
		for k, v := range b.params {
			parts = append(parts, fmt.Sprintf("%s=%s", strings.ToLower(k), url.PathEscape(v)))
		}
		raw = fmt.Sprintf("%s~%s", b.username, strings.Join(parts, "+"))
	} else {
		raw = b.username
	}

	return NewUserStr(raw)
}
