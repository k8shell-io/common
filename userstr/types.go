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
	Raw           string
	Form          UserStrForm
	Username      string
	User          string
	Pod           string
	Target        string
	TargetKind    string
	TargetName    string
	Namespace     string
	Blueprint     string
	BlueprintKind BlueprintKind
	ParamsRaw     map[string]string
	RepoOwner     string
	RepoName      string
	RepoRef       string
}

// WorkspaceIdentity is the canonical identity model.
type WorkspaceIdentity struct {
	Username      string
	Pod           string
	Target        string
	TargetKind    string
	TargetName    string
	Namespace     string
	Blueprint     string
	BlueprintKind BlueprintKind
	RepoOwner     string
	RepoName      string
	RepoRef       string
}

type CanonicalUserStr struct {
	Identity            WorkspaceIdentity
	CanonicalKey        string
	CanonicalUserStr    string
	CanonicalUserStrObj *UserStr
	Aliases             []string
	WorkspaceName       string
}

type CanonicalizeOptions struct {
	IncludeBlueprintInKey bool
}
