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
//
// Notes (canonicalization):
//   - Parsing is pure and deterministic.
//   - Canonicalize() optionally resolves issue to ref via IssueRefResolver and computes
//     Identity + CanonicalKey + CanonicalUserStr + Aliases.
//   - Workspace identity should be based on (user, repo, resolved ref, optionally blueprint).
//     Issue is treated as metadata/alias, not identity.
package models

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
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
	ErrBadParam = errors.New("userstr: bad param (expected key=value)")
	ErrTooLong  = errors.New("userstr: identifier too long")

	// Returned when a hash-form userstr is provided but no resolver is configured.
	ErrHashResolverRequired = errors.New("userstr: hash resolver required")

	// Returned when a base64-form userstr is present but cannot be decoded.
	ErrB64UserStrInvalid = errors.New("userstr: b64 userstr invalid")
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
	Raw           string            // original raw input
	Username      string            // normalized username
	Blueprint     string            // computed blueprint name
	BlueprintKind BlueprintKind     // kind of blueprint used
	ParamsRaw     map[string]string // raw params map
	RepoName      string            // repository name
	RepoOwner     string            // repository owner
	RepoRef       string            // repository reference (branch/tag)
	RepoIssue     int               // repository issue number
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

// IssueRefResolver defines an interface for resolving issue numbers to refs.
type IssueRepoRefResolver interface {
	ResolveIssueRepoRef(username string, repoOwner, repoName string, issueNumber int) (ref string, err error)
}

var issueRefResolver IssueRepoRefResolver
var mu = &sync.Mutex{}

func SetIssueRepoRefResolver(resolver IssueRepoRefResolver) {
	mu.Lock()
	defer mu.Unlock()
	issueRefResolver = resolver
}

// CanonicalizeOptions defines options for the Canonicalize method.
type CanonicalizeOptions struct {
	// If true and ref is present, we ignore issue for identity (issue becomes metadata/alias).
	PreferExplicitRef bool

	// If true, and issue is present with no ref, resolve issue to ref and use that ref for identity.
	ResolveIssueToRef bool

	// If true, include blueprint in the identity key.
	IncludeBlueprintInKey bool
}

// Canonicalize computes Identity/CanonicalKey/CanonicalUserStr/Aliases.
// This method may call the resolver if issue to ref resolution is enabled.
func (u *UserStr) Canonicalize() (*CanonicalUserStr, error) {
	owner := u.RepoOwner
	name := u.RepoName

	opt := CanonicalizeOptions{
		PreferExplicitRef:     true,
		ResolveIssueToRef:     true,
		IncludeBlueprintInKey: true,
	}

	resolvedRef := u.RepoRef
	if resolvedRef == "" && u.RepoIssue > 0 && opt.ResolveIssueToRef {
		mu.Lock()
		r := issueRefResolver
		mu.Unlock()

		if r == nil {
			return nil, fmt.Errorf("userstr: resolver required to resolve issue to ref")
		}
		if owner == "" || name == "" {
			return nil, fmt.Errorf("userstr: cannot resolve issue to ref without repo (owner/name)")
		}
		ref, err := r.ResolveIssueRepoRef(u.Username, owner, name, u.RepoIssue)
		if err != nil {
			return nil, fmt.Errorf("userstr: resolve issue to ref failed: %w", err)
		}
		resolvedRef = ref
	}

	// PreferExplicitRef: issue never affects identity if ref is given.
	// (Issue becomes alias/metadata.) Here it’s implicit because resolvedRef is already u.RepoRef.
	if u.RepoRef != "" && opt.PreferExplicitRef {
		resolvedRef = u.RepoRef
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
	canonicalUserStr.CanonicalUserStr = buildCanonicalUserStr(&canonicalUserStr.Identity)
	canonicalUserStr.Aliases = buildAliases(u, resolvedRef)
	canonicalUserStr.WorkspaceName = buildWorkspaceName(u.Username, canonicalUserStr.CanonicalKey)

	var err error
	canonicalUserStr.CanonicalUserStrObj, err = NewUserStr(canonicalUserStr.CanonicalUserStr)
	if err != nil {
		return nil, fmt.Errorf("userstr: failed to parse canonical userstr: %w", err)
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
func buildCanonicalUserStr(id *WorkspaceIdentity) string {
	if id.RepoOwner != "" && id.RepoName != "" {
		b := NewUserStrWith(id.Username).
			WithRepo(id.RepoOwner + "/" + id.RepoName)
		if id.RepoRef != "" {
			b.WithRef(id.RepoRef)
		}
		u, err := b.Build()
		if err == nil {
			return u.Raw
		}
		if id.RepoRef != "" {
			return fmt.Sprintf("%s~repo=%s/%s+ref=%s", id.Username, id.RepoOwner, id.RepoName, url.PathEscape(id.RepoRef))
		}
		return fmt.Sprintf("%s~repo=%s/%s", id.Username, id.RepoOwner, id.RepoName)
	}

	if id.Blueprint != "" {
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

	// original raw (useful for debugging)
	if u.Raw != "" {
		aliases = append(aliases, "raw:"+u.Raw)
	}

	// issue-form alias key
	if u.RepoOwner != "" && u.RepoName != "" && u.RepoIssue > 0 {
		aliases = append(aliases, fmt.Sprintf("u=%s|r=%s/%s|issue=%d",
			u.Username, u.RepoOwner, u.RepoName, u.RepoIssue))
	}

	// ref-form alias key (canonical)
	if u.RepoOwner != "" && u.RepoName != "" && resolvedRef != "" {
		aliases = append(aliases, fmt.Sprintf("u=%s|r=%s/%s|ref=%s",
			u.Username, u.RepoOwner, u.RepoName, resolvedRef))
	}

	return aliases
}

// NewUserStr parses a user string using default length constraints.
// If input is base64-form (e.g. b64-...), it is decoded to a real userstr first.
// If input is a hash-form token (e.g. sha256-...), it is resolved to a real userstr first.
func NewUserStr(input string) (*UserStr, error) {
	return newUserStr(input, 0)
}

func newUserStr(input string, depth int) (*UserStr, error) {
	if depth > 2 {
		return nil, fmt.Errorf("userstr: too many resolution steps")
	}

	rawTrimmed := strings.TrimSpace(input)

	if decoded, ok, err := tryDecodeB64UserStrToken(rawTrimmed); ok {
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrB64UserStrInvalid, err)
		}
		return newUserStr(decoded, depth+1)
	}

	if MAX_TOTAL_LEN > 0 && utf8.RuneCountInString(rawTrimmed) > MAX_TOTAL_LEN {
		return nil, fmt.Errorf("%w: total>%d", ErrTooLong, MAX_TOTAL_LEN)
	}

	raw := rawTrimmed
	usernamePart, wsSpec, _ := cutOnce(raw, "~")
	username := strings.ToLower(strings.TrimSpace(usernamePart))

	if wsSpec == "" {
		return &UserStr{
			Raw:           raw,
			Username:      username,
			Blueprint:     "",
			BlueprintKind: BlueprintKindImplicit,
			ParamsRaw:     nil,
		}, nil
	}

	wsSpec = strings.TrimSpace(wsSpec)

	if !strings.Contains(wsSpec, "=") {
		decoded, err := url.PathUnescape(wsSpec)
		if err != nil {
			return nil, fmt.Errorf("userstr: blueprint percent-decode: %w", err)
		}
		return &UserStr{
			Raw:           raw,
			Username:      username,
			Blueprint:     decoded,
			BlueprintKind: BlueprintKindExplicit,
			ParamsRaw:     nil,
		}, nil
	}

	pairs := strings.Split(wsSpec, "+")
	params := make(map[string]string, len(pairs))
	for _, p := range pairs {
		if p == "" {
			return nil, fmt.Errorf("%w: empty pair", ErrBadParam)
		}

		k, v, ok := cutOnce(p, "=")
		if !ok || strings.TrimSpace(k) == "" {
			return nil, fmt.Errorf("%w: %q", ErrBadParam, p)
		}

		if strings.Contains(v, "=") {
			return nil, fmt.Errorf("%w: unescaped '=' in value: %q", ErrBadParam, p)
		}

		k = strings.ToLower(strings.TrimSpace(k))

		val, err := url.PathUnescape(strings.TrimSpace(v))
		if err != nil {
			return nil, fmt.Errorf("%w: value decode failed for key %q: %v", ErrBadParam, k, err)
		}

		params[k] = strings.ToLower(val)
	}

	var repoIssue int
	if issue := params["issue"]; issue != "" {
		var err error
		repoIssue, err = strconv.Atoi(issue)
		if err != nil {
			return nil, fmt.Errorf("userstr: issue must be an integer")
		}
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
	if owner := params["owner"]; owner != "" {
		repoOwner = owner
	}

	blueprintName := ""
	if repoOwner != "" && repoName != "" {
		blueprintName = fmt.Sprintf("repo-%s-%s", repoOwner, repoName)
	}

	if blueprintName == "" {
		return nil, fmt.Errorf("userstr: blueprint could not be determined")
	}

	return &UserStr{
		Raw:           raw,
		Username:      username,
		Blueprint:     blueprintName,
		BlueprintKind: BlueprintKindCustom,
		ParamsRaw:     params,
		RepoName:      repoName,
		RepoOwner:     repoOwner,
		RepoRef:       params["ref"],
		RepoIssue:     repoIssue,
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

func (b *UserStrBuilder) WithOwner(owner string) *UserStrBuilder {
	b.params["owner"] = owner
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

	return NewUserStr(raw)
}

// Labels returns Kubernetes/Helm-safe labels derived from the UserStr.
func (u *UserStr) Labels() map[string]string {
	lbls := make(map[string]string)

	if u.Username != "" {
		lbls["k8shell.io/username"] = u.Username
	}
	if u.Blueprint != "" {
		lbls["k8shell.io/blueprint"] = u.Blueprint
	}
	if u.RepoOwner != "" {
		lbls["k8shell.io/repoowner"] = u.RepoOwner
	}
	if u.RepoName != "" {
		lbls["k8shell.io/reponame"] = u.RepoName
	}
	if u.RepoRef != "" {
		lbls["k8shell.io/ref"] = u.RepoRef
	}
	if u.RepoIssue > 0 {
		lbls["k8shell.io/issue"] = strconv.Itoa(u.RepoIssue)
	}

	return lbls
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
