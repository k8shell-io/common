// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package userstr

import "errors"

const MAX_TOTAL_LEN = 128 // maximum allowed length for the entire userstr

// BlueprintKind represents the kind of blueprint used for a workspace.
type BlueprintKind int

const (
	BlueprintKindImplicit BlueprintKind = iota // no explicit blueprint
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

// UserStrForm describes the semantic shape of a parsed user string.
type UserStrForm int

const (
	UserStrFormImplicit UserStrForm = iota
	UserStrFormExplicitBlueprint
	UserStrFormNamedWorkspace
	UserStrFormRepoWorkspace
)

var (
	ErrTooLong           = errors.New("identifier too long")
	ErrB64UserStrInvalid = errors.New("base64 userstr invalid")
	ErrUserStrMalformed  = errors.New("userstr malformed")
	ErrUserStrInvalid    = errors.New("userstr invalid")
)

// UserStr is the parsed user string object.
type UserStr struct {
	raw           string
	form          UserStrForm
	username      string
	user          string
	pod           string
	deploy        string
	namespace     string
	blueprint     string
	blueprintKind BlueprintKind
	paramsRaw     map[string]string
	repoOwner     string
	repoName      string
	repoRef       string
}

// Getters for UserStr
func (u *UserStr) Raw() string       { return u.raw }
func (u *UserStr) Form() UserStrForm { return u.form }
func (u *UserStr) Username() string  { return u.username }
func (u *UserStr) User() string      { return u.user }
func (u *UserStr) Pod() string       { return u.pod }
func (u *UserStr) Deploy() string    { return u.deploy }
func (u *UserStr) Namespace(defaultValue string) string {
	if u.namespace == "" {
		return defaultValue
	}
	return u.namespace
}
func (u *UserStr) Blueprint() string            { return u.blueprint }
func (u *UserStr) BlueprintKind() BlueprintKind { return u.blueprintKind }
func (u *UserStr) ParamsRaw() map[string]string { return u.paramsRaw }
func (u *UserStr) RepoOwner() string            { return u.repoOwner }
func (u *UserStr) RepoName() string             { return u.repoName }
func (u *UserStr) RepoRef() string              { return u.repoRef }

// WorkspaceIdentity is the canonical identity model.
type WorkspaceIdentity struct {
	username      string
	blueprint     string
	blueprintKind BlueprintKind
	repoOwner     string
	repoName      string
	repoRef       string
}

// Getters for WorkspaceIdentity
func (w *WorkspaceIdentity) Username() string             { return w.username }
func (w *WorkspaceIdentity) Blueprint() string            { return w.blueprint }
func (w *WorkspaceIdentity) BlueprintKind() BlueprintKind { return w.blueprintKind }
func (w *WorkspaceIdentity) RepoOwner() string            { return w.repoOwner }
func (w *WorkspaceIdentity) RepoName() string             { return w.repoName }
func (w *WorkspaceIdentity) RepoRef() string              { return w.repoRef }

type CanonicalUserStr struct {
	identity            WorkspaceIdentity
	canonicalKey        string
	canonicalUserStr    string
	canonicalUserStrObj *UserStr
	aliases             []string
	workspaceName       string
}

// Getters for CanonicalUserStr
func (c *CanonicalUserStr) Identity() WorkspaceIdentity   { return c.identity }
func (c *CanonicalUserStr) CanonicalKey() string          { return c.canonicalKey }
func (c *CanonicalUserStr) CanonicalUserStr() string      { return c.canonicalUserStr }
func (c *CanonicalUserStr) CanonicalUserStrObj() *UserStr { return c.canonicalUserStrObj }
func (c *CanonicalUserStr) Aliases() []string             { return c.aliases }
func (c *CanonicalUserStr) WorkspaceName() string         { return c.workspaceName }

// CanonicalId returns a unique identifier for the workspace based on the username and canonical key
func (c *CanonicalUserStr) CanonicalId() string {
	return buildCanonicalId(c.identity.Username(), c.canonicalKey)
}
