// K8shell user string parser
//
// Spec summary (v1.0):
//
//	USERSTR     = user [ "~" ws-spec ]
//	ws-spec     = bp-name [ "+" user-kv ] | param-list
//	param-list  = kv *( "+" kv )
//	kv          = key "=" value
//	key         = "repo" | "ref" | "pr" | "user" | "name"
//
//	bp-name     = <url-path-escaped string>          ; decoded with url.PathUnescape
//	value       = <url-path-escaped string>          ; decoded with url.PathUnescape
//
// Special input form (optional):
//
//	USERSTR     = ( "b64-" | "base64-" ) b64url-raw   ; decodes to USERSTR, then parsed normally
//
// Rules:
// - Allowed param keys: repo, ref, pr, user, name. Any other key is an error.
// - Keys are normalized to lowercase.
// - Values are url.PathUnescape-decoded (keys are NOT decoded).
// - Slash "/" is allowed; when escaped as %2F it is decoded back to "/".
// - Reserved delimiters in the USERSTR syntax: @ ~ + = (escape as %XX inside values if needed).
// - Mutual exclusion: "ref" and "pr" cannot both be specified.
// - ref and pr are valid only when repo is specified.
// - user is valid with explicit blueprint form, repo form, and name form.
// - name creates a standalone form (username~name=xxx or username~name=xxx+user=yyy) with implicit blueprint.
// - name cannot be used with explicit blueprint names, repo, ref, or pr parameters.
// - pr must be a base-10 integer (>0) if present.
// - If pr is specified (and ref is not), Canonicalize() may resolve pr -> ref via RefResolver.
//
// Notes (canonicalization):
//   - Parsing is pure and deterministic.
//   - Canonicalize() optionally resolves pullrequest to ref via RefResolver and computes
//     Identity + CanonicalKey + CanonicalUserStr + Aliases.
//   - Workspace identity should be based on (user, repo, resolved ref, optionally blueprint).
//     PR is treated as metadata/alias, not identity.
package models

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

const (
	MAX_TOTAL_LEN = 128
)

var (
	ErrBadParam = errors.New("bad param")
	ErrTooLong  = errors.New("identifier too long")

	// Returned when a base64-form userstr is present but cannot be decoded.
	ErrB64UserStrInvalid = errors.New("base64 userstr invalid")

	// allowed param keys in userstr
	AllowedParams = []string{"repo", "ref", "pr", "user", "name"}
)

// BlueprintKind represents the kind of blueprint used for a workspace.
type BlueprintKind int

const (
	BlueprintKindImplicit BlueprintKind = iota // no explicit blueprint, the default user blueprint will be used
	BlueprintKindExplicit                      // user-defined blueprint in userstr
	BlueprintKindCustom                        // user-defined blueprint name from repo
)

func (k BlueprintKind) String() string {
	switch k {
	case BlueprintKindImplicit:
		return "implicit"
	case BlueprintKindExplicit:
		return "explicit"
	case BlueprintKindCustom:
		return "custom"
	default:
		return "unknown"
	}
}

type WorkspaceIdentity struct {
	Username      string        // normalized username
	Blueprint     string        // computed blueprint name
	BlueprintKind BlueprintKind // kind of blueprint used
	RepoOwner     string        // repository owner
	RepoName      string        // repository name
	RepoRef       string        // repository reference (branch/tag)
}

type UserStr struct {
	Raw             string            // original raw input
	Username        string            // normalized username
	User            string            // optional user param value
	Name            string            // optional workspace name param value
	Blueprint       string            // computed blueprint name
	BlueprintKind   BlueprintKind     // kind of blueprint used
	ParamsRaw       map[string]string // raw params map
	RepoName        string            // repository name
	RepoOwner       string            // repository owner
	RepoRef         string            // repository reference (branch/tag)
	RepoPullReq     int               // repository pull request number
	ValidationError error             // validation error when parsing with allowInvalid=true; nil otherwise
}

type CanonicalUserStr struct {
	Identity            WorkspaceIdentity // canonical workspace identity
	CanonicalKey        string            // canonical workspace key
	CanonicalUserStr    string            // canonical user string
	CanonicalUserStrObj *UserStr          // parsed canonical user string
	Aliases             []string          // list of alias keys
	WorkspaceName       string            // generated workspace name
}

type UserStrBuilder struct {
	username  string
	blueprint string
	params    map[string]string
}

// RefResolver defines an interface for resolving PR numbers to refs.
type RefResolver interface {
	ResolvePullRequestRef(username string, repoOwner, repoName string, pullRequestNumber int) (ref string, err error)
}

var refResolver RefResolver
var mu = &sync.Mutex{}

func SetRefResolver(resolver RefResolver) {
	mu.Lock()
	defer mu.Unlock()
	refResolver = resolver
}

// CanonicalizeOptions defines options for the Canonicalize method.
type CanonicalizeOptions struct {
	// If true, and pullrequest is present with no ref, resolve pullrequest to ref and use that ref for identity.
	ResolvePullRequestToRef bool

	// If true, include blueprint in the identity key.
	IncludeBlueprintInKey bool
}

// Canonicalize computes Identity/CanonicalKey/CanonicalUserStr/Aliases.
// This method may call the resolver if pr to ref resolution is enabled.
func (u *UserStr) Canonicalize() (*CanonicalUserStr, error) {
	owner := u.RepoOwner
	name := u.RepoName

	opt := CanonicalizeOptions{
		ResolvePullRequestToRef: true,
		IncludeBlueprintInKey:   true,
	}

	// enforce: at most one of pr/ref
	if u.RepoRef != "" && u.RepoPullReq > 0 {
		return nil, fmt.Errorf("cannot specify more than one of ref, pullrequest")
	}

	resolvedRef := u.RepoRef
	if resolvedRef == "" && u.RepoPullReq > 0 && opt.ResolvePullRequestToRef {
		mu.Lock()
		r := refResolver
		mu.Unlock()

		if r == nil {
			return nil, fmt.Errorf("resolver required to resolve pullrequest to ref")
		}
		if owner == "" || name == "" {
			return nil, fmt.Errorf("cannot resolve pullrequest to ref without repo (owner/name)")
		}
		ref, err := r.ResolvePullRequestRef(u.Username, owner, name, u.RepoPullReq)
		if err != nil {
			return nil, fmt.Errorf("resolve pullrequest to ref failed: %w", err)
		}
		resolvedRef = ref
	}

	blueprint := u.Blueprint
	if blueprint == "" && owner != "" && name != "" {
		blueprint = fmt.Sprintf("repo-%s-%s", owner, name)
	}

	canonicalUserStr := &CanonicalUserStr{
		Identity: WorkspaceIdentity{
			Username:      u.Username,
			Blueprint:     blueprint,
			BlueprintKind: u.BlueprintKind,
			RepoOwner:     owner,
			RepoName:      name,
			RepoRef:       resolvedRef,
		},
	}

	canonicalUserStr.CanonicalKey = buildWorkspaceKey(&canonicalUserStr.Identity, opt.IncludeBlueprintInKey)
	canonicalUserStr.CanonicalUserStr = buildCanonicalUserStr(&canonicalUserStr.Identity, u.User, u.Name)
	canonicalUserStr.Aliases = buildAliases(u, resolvedRef)

	// Use the name parameter as workspace name if provided, otherwise generate one
	if u.Name != "" {
		canonicalUserStr.WorkspaceName = u.Name
	} else {
		canonicalUserStr.WorkspaceName = buildWorkspaceName(u.Username, canonicalUserStr.CanonicalKey)
	}

	var err error
	canonicalUserStr.CanonicalUserStrObj, err = NewUserStr(canonicalUserStr.CanonicalUserStr, false)
	if err != nil {
		return nil, fmt.Errorf("failed to parse canonical userstr: %w", err)
	}

	return canonicalUserStr, nil
}

func shortHash(s string, n int) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])[:n]
}

func buildWorkspaceName(username, canonicalKey string) string {
	const hashLen = 7
	return fmt.Sprintf("%s-%s", username, shortHash(canonicalKey, hashLen))
}

func buildWorkspaceKey(id *WorkspaceIdentity, includeBlueprint bool) string {
	parts := []string{"u=" + id.Username}
	if id.RepoOwner != "" && id.RepoName != "" {
		parts = append(parts, "r="+id.RepoOwner+"/"+id.RepoName)
	}
	if id.RepoRef != "" {
		parts = append(parts, "ref="+id.RepoRef)
	}
	if includeBlueprint && id.Blueprint != "" {
		parts = append(parts, "bp="+id.Blueprint)
	}
	return strings.Join(parts, "|")
}

// BuildCanonicalUserStr builds the canonical user string from the given identity.
func buildCanonicalUserStr(id *WorkspaceIdentity, user string, name string) string {
	canonicalUser := strings.ToLower(strings.TrimSpace(user))
	canonicalName := strings.ToLower(strings.TrimSpace(name))

	if canonicalName != "" {
		if canonicalUser != "" {
			return fmt.Sprintf("%s~name=%s+user=%s", id.Username,
				url.PathEscape(canonicalName), url.PathEscape(canonicalUser))
		}
		return fmt.Sprintf("%s~name=%s", id.Username, url.PathEscape(canonicalName))
	}

	if id.RepoOwner != "" && id.RepoName != "" {
		b := NewUserStrWith(id.Username).
			WithRepo(id.RepoOwner + "/" + id.RepoName)
		if id.RepoRef != "" {
			b.WithRef(id.RepoRef)
		}
		if canonicalUser != "" {
			b.WithParam("user", canonicalUser)
		}
		u, err := b.Build()
		if err == nil {
			return u.Raw
		}
		if id.RepoRef != "" {
			if canonicalUser != "" {
				return fmt.Sprintf("%s~repo=%s/%s+ref=%s+user=%s", id.Username, id.RepoOwner, id.RepoName,
					url.PathEscape(id.RepoRef), url.PathEscape(canonicalUser))
			}
			return fmt.Sprintf("%s~repo=%s/%s+ref=%s", id.Username, id.RepoOwner, id.RepoName, url.PathEscape(id.RepoRef))
		}
		if canonicalUser != "" {
			return fmt.Sprintf("%s~repo=%s/%s+user=%s", id.Username, id.RepoOwner, id.RepoName,
				url.PathEscape(canonicalUser))
		}
		return fmt.Sprintf("%s~repo=%s/%s", id.Username, id.RepoOwner, id.RepoName)
	}

	if id.Blueprint != "" {
		if canonicalUser != "" {
			return fmt.Sprintf("%s~%s+user=%s", id.Username, url.PathEscape(id.Blueprint),
				url.PathEscape(canonicalUser))
		}

		u, err := NewUserStrWith(id.Username).WithBlueprint(id.Blueprint).Build()
		if err == nil {
			return u.Raw
		}
		return fmt.Sprintf("%s~%s", id.Username, url.PathEscape(id.Blueprint))
	}

	return id.Username
}

// BuildAliases builds a list of aliases for the given UserStr and resolved ref.
func buildAliases(u *UserStr, resolvedRef string) []string {
	var aliases []string

	if u.Raw != "" {
		aliases = append(aliases, "raw:"+u.Raw)
	}

	if u.RepoOwner != "" && u.RepoName != "" && u.RepoPullReq > 0 {
		aliases = append(aliases, fmt.Sprintf("u=%s|r=%s/%s|pr=%d",
			u.Username, u.RepoOwner, u.RepoName, u.RepoPullReq))
	}

	if u.RepoOwner != "" && u.RepoName != "" && resolvedRef != "" {
		aliases = append(aliases, fmt.Sprintf("u=%s|r=%s/%s|ref=%s",
			u.Username, u.RepoOwner, u.RepoName, resolvedRef))
	}

	return aliases
}

// NewUserStr parses a user string using default length constraints.
// If input is base64-form (e.g. b64-...), it is decoded to a real userstr first.
func NewUserStr(input string, allowInvalid bool) (*UserStr, error) {
	return newUserStr(input, 0, allowInvalid)
}

// newUserStr is the internal recursive parser with depth control.
func newUserStr(input string, depth int, allowInvalid bool) (*UserStr, error) {
	if depth > 2 {
		return nil, fmt.Errorf("too many resolution steps")
	}

	var validationError error = nil
	rawTrimmed := strings.TrimSpace(input)

	if decoded, ok, err := tryDecodeB64UserStrToken(rawTrimmed); ok {
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrB64UserStrInvalid, err)
		}
		return newUserStr(decoded, depth+1, allowInvalid)
	}

	if MAX_TOTAL_LEN > 0 && utf8.RuneCountInString(rawTrimmed) > MAX_TOTAL_LEN {
		validationError = fmt.Errorf("%w: raw>%d", ErrTooLong, MAX_TOTAL_LEN)
		if !allowInvalid {
			return nil, validationError
		}
	}

	raw := rawTrimmed
	usernamePart, wsSpec, _ := cutOnce(raw, "~")
	username := strings.ToLower(strings.TrimSpace(usernamePart))

	if wsSpec == "" {
		return &UserStr{
			Raw:             raw,
			Username:        username,
			Blueprint:       "",
			BlueprintKind:   BlueprintKindImplicit,
			ParamsRaw:       nil,
			ValidationError: validationError,
		}, nil
	}

	wsSpec = strings.TrimSpace(wsSpec)

	if !strings.Contains(wsSpec, "=") {
		decoded, err := url.PathUnescape(wsSpec)
		if err != nil {
			validationError = fmt.Errorf("%w: blueprint percent-decode: %v", ErrBadParam, err)
			if !allowInvalid {
				return nil, validationError
			}
			decoded = ""
		}
		return &UserStr{
			Raw:             raw,
			Username:        username,
			Blueprint:       decoded,
			BlueprintKind:   BlueprintKindExplicit,
			ParamsRaw:       nil,
			ValidationError: validationError,
		}, nil
	}

	pairs := strings.Split(wsSpec, "+")

	if first := strings.TrimSpace(pairs[0]); first != "" && !strings.Contains(first, "=") {
		decodedBlueprint, err := url.PathUnescape(first)
		if err != nil {
			validationError = fmt.Errorf("%w: blueprint percent-decode: %v", ErrBadParam, err)
			if !allowInvalid {
				return nil, validationError
			}
			decodedBlueprint = ""
		}

		params := make(map[string]string, len(pairs)-1)
		for _, p := range pairs[1:] {
			if p == "" {
				validationError = fmt.Errorf("%w: empty pair", ErrBadParam)
				if !allowInvalid {
					return nil, validationError
				}
				continue
			}

			k, v, ok := cutOnce(p, "=")
			if !ok || strings.TrimSpace(k) == "" {
				validationError = fmt.Errorf("%w: expected key=value, %q", ErrBadParam, p)
				if !allowInvalid {
					return nil, validationError
				}
				continue
			}

			if strings.Contains(v, "=") {
				validationError = fmt.Errorf("%w: unescaped '=' in value: %q", ErrBadParam, p)
				if !allowInvalid {
					return nil, validationError
				}
				continue
			}

			k = strings.ToLower(strings.TrimSpace(k))

			val, err := url.PathUnescape(strings.TrimSpace(v))
			if err != nil {
				validationError = fmt.Errorf("%w: value decode failed for key %q: %v", ErrBadParam, k, err)
				if !allowInvalid {
					return nil, validationError
				}
				continue
			}

			if !slices.Contains(AllowedParams, k) {
				validationError = fmt.Errorf("invalid param key: %q", k)
				if !allowInvalid {
					return nil, validationError
				}
				continue
			}

			if k != "user" {
				validationError = fmt.Errorf("%w: only user param is allowed with explicit blueprint form", ErrBadParam)
				if !allowInvalid {
					return nil, validationError
				}
				continue
			}

			params[k] = strings.ToLower(val)
		}

		if len(params) == 0 {
			params = nil
		}

		return &UserStr{
			Raw:             raw,
			Username:        username,
			User:            mapValue(params, "user"),
			Name:            "", // name not allowed with explicit blueprint
			Blueprint:       decodedBlueprint,
			BlueprintKind:   BlueprintKindExplicit,
			ParamsRaw:       params,
			ValidationError: validationError,
		}, nil
	}

	params := make(map[string]string, len(pairs))
	for _, p := range pairs {
		if p == "" {
			validationError = fmt.Errorf("%w: empty pair", ErrBadParam)
			if !allowInvalid {
				return nil, validationError
			}
			continue
		}

		k, v, ok := cutOnce(p, "=")
		if !ok || strings.TrimSpace(k) == "" {
			validationError = fmt.Errorf("%w: expected key=value, %q", ErrBadParam, p)
			if !allowInvalid {
				return nil, validationError
			}
			continue
		}

		if strings.Contains(v, "=") {
			validationError = fmt.Errorf("%w: unescaped '=' in value: %q", ErrBadParam, p)
			if !allowInvalid {
				return nil, validationError
			}
			continue
		}

		k = strings.ToLower(strings.TrimSpace(k))

		val, err := url.PathUnescape(strings.TrimSpace(v))
		if err != nil {
			validationError = fmt.Errorf("%w: value decode failed for key %q: %v", ErrBadParam, k, err)
			if !allowInvalid {
				return nil, validationError
			}
			continue
		}

		if !slices.Contains(AllowedParams, k) {
			validationError = fmt.Errorf("invalid param key: %q", k)
			if !allowInvalid {
				return nil, validationError
			}
			continue
		}

		params[k] = strings.ToLower(val)
	}

	// Validate that name is not used with repo/ref/pr params
	if params["name"] != "" && (params["repo"] != "" || params["ref"] != "" || params["pr"] != "") {
		validationError = fmt.Errorf("%w: name param cannot be used with repo, ref, or pr", ErrBadParam)
		if !allowInvalid {
			return nil, validationError
		}
		delete(params, "name")
	}

	// If name is present, this is a name-based workspace (implicit blueprint)
	if params["name"] != "" {
		// Only user param is allowed with name
		for k := range params {
			if k != "name" && k != "user" {
				validationError = fmt.Errorf("%w: only user param can be used with name", ErrBadParam)
				if !allowInvalid {
					return nil, validationError
				}
				delete(params, k)
			}
		}
		return &UserStr{
			Raw:             raw,
			Username:        username,
			User:            params["user"],
			Name:            params["name"],
			Blueprint:       "", // implicit blueprint with name
			BlueprintKind:   BlueprintKindImplicit,
			ParamsRaw:       params,
			ValidationError: validationError,
		}, nil
	}

	var repoPullReq int
	if pr := params["pr"]; pr != "" {
		var err error
		repoPullReq, err = strconv.Atoi(pr)
		if err != nil {
			validationError = fmt.Errorf("%w: pr must be an integer", ErrBadParam)
			if !allowInvalid {
				return nil, validationError
			}
		}
	}

	hasRepo := params["repo"] != ""

	user := params["user"]

	repoRef := params["ref"]
	if repoRef != "" && repoPullReq > 0 {
		validationError = fmt.Errorf("%w: cannot specify more than one of ref, pr", ErrBadParam)
		if !allowInvalid {
			return nil, validationError
		}
		// In allowInvalid mode, clear conflicting values to avoid inconsistent state downstream.
		repoRef = ""
		repoPullReq = 0
		delete(params, "ref")
		delete(params, "pr")
	}

	if !hasRepo && (repoRef != "" || repoPullReq > 0) {
		validationError = fmt.Errorf("%w: ref/pr require repo", ErrBadParam)
		if !allowInvalid {
			return nil, validationError
		}
		repoRef = ""
		repoPullReq = 0
		delete(params, "ref")
		delete(params, "pr")
	}

	var repoName string
	repoOwner := username

	if repo := params["repo"]; repo != "" {
		if owner, name, found := cutOnce(repo, "/"); found {
			repoOwner = owner
			repoName = name
		} else {
			repoName = repo
		}
	}

	blueprintName := ""
	if repoOwner != "" && repoName != "" {
		blueprintName = fmt.Sprintf("repo-%s-%s", repoOwner, repoName)
	}

	if blueprintName == "" {
		validationError = fmt.Errorf("%w: blueprint could not be determined", ErrBadParam)
		if !allowInvalid {
			return nil, validationError
		}
	}

	return &UserStr{
		Raw:             raw,
		Username:        username,
		User:            user,
		Name:            "", // name not allowed in repo form
		Blueprint:       blueprintName,
		BlueprintKind:   BlueprintKindCustom,
		ParamsRaw:       params,
		RepoName:        repoName,
		RepoOwner:       repoOwner,
		RepoRef:         repoRef,
		RepoPullReq:     repoPullReq,
		ValidationError: validationError,
	}, nil
}

func mapValue(m map[string]string, key string) string {
	if m == nil {
		return ""
	}
	return m[key]
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
		username: strings.ToLower(strings.TrimSpace(username)),
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

func (b *UserStrBuilder) WithRef(ref string) *UserStrBuilder {
	b.params["ref"] = ref
	return b
}

func (b *UserStrBuilder) WithParam(key, value string) *UserStrBuilder {
	b.params[strings.ToLower(strings.TrimSpace(key))] = value
	return b
}

func (b *UserStrBuilder) WithName(name string) *UserStrBuilder {
	b.params["name"] = name
	return b
}

// Build assembles the UserStr (and runs through your normal parser for consistency).
func (b *UserStrBuilder) Build() (*UserStr, error) {
	var raw string

	if b.blueprint != "" && len(b.params) == 0 {
		raw = fmt.Sprintf("%s~%s", b.username, url.PathEscape(b.blueprint))
	} else if len(b.params) > 0 {
		keys := make([]string, 0, len(b.params))
		for k := range b.params {
			keys = append(keys, strings.ToLower(k))
		}
		sort.Strings(keys)

		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			v := b.params[k]
			parts = append(parts, fmt.Sprintf("%s=%s", strings.ToLower(k), url.PathEscape(v)))
		}
		raw = fmt.Sprintf("%s~%s", b.username, strings.Join(parts, "+"))
	} else {
		raw = b.username
	}

	return NewUserStr(raw, false)
}

// tryDecodeB64UserStrToken decodes reversible whole-userstr base64url tokens. The only supported
// encoding is raw base64url without padding, prefixed by "b64-" or "base64-" (case-insensitive).
// Supported forms:
//   - b64-<base64url payload without padding>
//   - base64-<base64url payload without padding>
func tryDecodeB64UserStrToken(s string) (string, bool, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false, nil
	}

	lower := strings.ToLower(s)
	if !strings.HasPrefix(lower, "b64-") && !strings.HasPrefix(lower, "base64-") {
		return "", false, nil
	}

	prefixLen := len("b64-")
	if strings.HasPrefix(lower, "base64-") {
		prefixLen = len("base64-")
	}

	payload := strings.TrimSpace(s[prefixLen:])
	if payload == "" {
		return "", true, fmt.Errorf("empty base64 payload")
	}

	b, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return "", true, fmt.Errorf("base64 decode failed: %w. Supported encoding is raw base64url without padding.",
			err)
	}

	return string(b), true, nil
}

// Base64 returns a reversible base64url (raw, no padding) representation of the canonical user string.
// Used where the raw canonical user string may be too long or contain unsafe characters.
func (c *CanonicalUserStr) Base64() string {
	if c == nil || c.CanonicalUserStr == "" {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString([]byte(c.CanonicalUserStr))
}

// NewCanonicalUserStrFromBase64 decodes a base64url (raw, no padding) string/token into a USERSTR,
// parses it, then canonicalizes it.
// Accepted inputs:
//   - "b64-<payload>"
//   - "base64-<payload>"
//   - "<payload>" (raw base64url without padding)
func NewCanonicalUserStrFromBase64(s string) (*CanonicalUserStr, error) {
	decoded, err := decodeBase64UserStrFlexible(s)
	if err != nil {
		return nil, err
	}

	u, err := NewUserStr(decoded, false)
	if err != nil {
		return nil, err
	}
	return u.Canonicalize()
}

// Labels returns Kubernetes/Helm-safe labels derived from the UserStr.
func (u *CanonicalUserStr) Labels() map[string]string {
	lbls := make(map[string]string)

	lbls["k8shell.io/userstr"] = u.Base64()

	if u.Identity.Username != "" {
		lbls["k8shell.io/username"] = u.Identity.Username
	}
	if u.Identity.Blueprint != "" {
		lbls["k8shell.io/blueprint"] = u.Identity.Blueprint
	}
	if u.Identity.RepoOwner != "" {
		lbls["k8shell.io/repoowner"] = u.Identity.RepoOwner
	}
	if u.Identity.RepoName != "" {
		lbls["k8shell.io/reponame"] = u.Identity.RepoName
	}
	if u.Identity.RepoRef != "" {
		lbls["k8shell.io/ref"] = u.Identity.RepoRef
	}
	return lbls
}

// decodeBase64UserStrFlexible decodes a base64url (raw, no padding) string/token into a USERSTR.
func decodeBase64UserStrFlexible(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("%w: empty base64 input", ErrB64UserStrInvalid)
	}

	// If it is already a supported token form, reuse the existing decoder.
	if decoded, ok, err := tryDecodeB64UserStrToken(s); ok {
		if err != nil {
			return "", fmt.Errorf("%w: %v", ErrB64UserStrInvalid, err)
		}
		return decoded, nil
	}

	// Otherwise treat s as the raw base64url payload (no padding).
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("%w: base64 decode failed: %v", ErrB64UserStrInvalid, err)
	}
	return string(b), nil
}

// UserStrFields is a JSON-friendly representation
type UserStrFields struct {
	Username    string `json:"username"`
	Blueprint   string `json:"blueprint,omitempty"`
	RepoOwner   string `json:"repoOwner,omitempty"`
	RepoName    string `json:"repoName,omitempty"`
	RepoRef     string `json:"repoRef,omitempty"`
	RepoPullReq int    `json:"repoPullReq,omitempty"`
}

// ToUserStr builds a userstr from the fields and parses it (single source of validation truth).
func (f UserStrFields) ToUserStr() (*UserStr, error) {
	raw, err := f.ToRawUserStr()
	if err != nil {
		return nil, err
	}
	return NewUserStr(raw, true)
}

// ToRawUserStr returns the serialized userstr that would be parsed.
func (f UserStrFields) ToRawUserStr() (string, error) {
	username := strings.ToLower(strings.TrimSpace(f.Username))
	if username == "" {
		return "", fmt.Errorf("%w: username is required", ErrBadParam)
	}

	repoOwner := strings.ToLower(strings.TrimSpace(f.RepoOwner))
	repoName := strings.ToLower(strings.TrimSpace(f.RepoName))
	repoRef := strings.TrimSpace(f.RepoRef)
	repoPullReq := f.RepoPullReq
	blueprint := strings.TrimSpace(f.Blueprint)

	if repoPullReq < 0 {
		return "", fmt.Errorf("%w: repoPullReq must be >= 0", ErrBadParam)
	}
	if repoRef != "" && repoPullReq > 0 {
		return "", fmt.Errorf("%w: cannot specify more than one of repoRef, repoPullReq", ErrBadParam)
	}

	hasAnyRepoField := repoOwner != "" || repoName != "" || repoRef != "" || repoPullReq > 0

	b := NewUserStrWith(username)

	if hasAnyRepoField {
		if blueprint != "" {
			return "", fmt.Errorf("%w: blueprint cannot be specified when repo fields are present", ErrBadParam)
		}
		if repoName == "" {
			return "", fmt.Errorf("%w: repoName is required when specifying repo fields", ErrBadParam)
		}
		if repoOwner == "" {
			repoOwner = username
		}

		b.WithRepo(repoOwner + "/" + repoName)

		if repoRef != "" && repoPullReq > 0 {
			return "", fmt.Errorf("%w: cannot specify more than one of repoRef, repoPullReq", ErrBadParam)
		}

		if repoRef != "" {
			b.WithRef(repoRef)
		}
		if repoPullReq > 0 {
			b.WithParam("pr", strconv.Itoa(repoPullReq))
		}

		u, err := b.Build()
		if err != nil {
			return "", err
		}
		return u.Raw, nil
	}

	if blueprint != "" {
		b.WithBlueprint(blueprint)
	}

	u, err := b.Build()
	if err != nil {
		return "", err
	}
	return u.Raw, nil
}

// UserStrFieldsFromUserStr creates a payload from a parsed *UserStr.
// Note: Blueprint will be populated from u.Blueprint (even for repo-derived blueprints).
func UserStrFieldsFromUserStr(u *UserStr) UserStrFields {
	if u == nil {
		return UserStrFields{}
	}
	return UserStrFields{
		Username:    u.Username,
		Blueprint:   u.Blueprint,
		RepoOwner:   u.RepoOwner,
		RepoName:    u.RepoName,
		RepoRef:     u.RepoRef,
		RepoPullReq: u.RepoPullReq,
	}
}
