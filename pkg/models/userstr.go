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
//   - Canonicalize() optionally resolves issue->ref via IssueRefResolver and computes
//     Identity + CanonicalKey + CanonicalUserStr + Aliases.
//   - Workspace identity should be based on (user, repo, resolved ref, optionally blueprint).
//     Issue is treated as metadata/alias, not identity.
package models

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
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
	Identity         WorkspaceIdentity
	CanonicalKey     string
	CanonicalUserStr string
	Aliases          []string
	WorkspaceID      string
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

// CanonicalizeOptions defines options for the Canonicalize method.
type CanonicalizeOptions struct {
	// If true and ref is present, we ignore issue for identity (issue becomes metadata/alias).
	PreferExplicitRef bool

	// If true, and issue is present with no ref, resolve issue->ref and use that ref for identity.
	ResolveIssueToRef bool

	// If true, include blueprint in the identity key.
	IncludeBlueprintInKey bool
}

// Canonicalize computes Identity/CanonicalKey/CanonicalUserStr/Aliases.
// This method may call the resolver if issue->ref resolution is enabled.
func (u *UserStr) Canonicalize(r IssueRepoRefResolver) (*CanonicalUserStr, error) {
	owner := u.RepoOwner
	name := u.RepoName

	opt := CanonicalizeOptions{
		PreferExplicitRef:     true,
		ResolveIssueToRef:     true,
		IncludeBlueprintInKey: true,
	}
	if r == nil {
		opt.ResolveIssueToRef = false
	}

	resolvedRef := u.RepoRef
	if resolvedRef == "" && u.RepoIssue > 0 && opt.ResolveIssueToRef {
		if r == nil {
			return nil, fmt.Errorf("userstr: resolver required to resolve issue->ref")
		}
		if owner == "" || name == "" {
			return nil, fmt.Errorf("userstr: cannot resolve issue->ref without repo (owner/name)")
		}
		ref, err := r.ResolveIssueRepoRef(u.Username, owner, name, u.RepoIssue)
		if err != nil {
			return nil, fmt.Errorf("userstr: resolve issue->ref failed: %w", err)
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
	canonicalUserStr.WorkspaceID = buildWorkspaceID(u.Username, canonicalUserStr.CanonicalKey)

	return canonicalUserStr, nil
}

func shortHash(s string, n int) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])[:n]
}

func buildWorkspaceID(username, canonicalKey string) string {
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
func NewUserStr(input string) (*UserStr, error) {
	if MAX_TOTAL_LEN > 0 && utf8.RuneCountInString(input) > MAX_TOTAL_LEN {
		return nil, fmt.Errorf("%w: total>%d", ErrTooLong, MAX_TOTAL_LEN)
	}

	if MAX_LOCAL_LEN > 0 && utf8.RuneCountInString(input) > MAX_LOCAL_LEN {
		return nil, fmt.Errorf("%w: local>%d", ErrTooLong, MAX_LOCAL_LEN)
	}

	raw := strings.TrimSpace(input)
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
