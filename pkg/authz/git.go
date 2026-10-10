// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package authz

// Contract: git:fetch | git:push
//
// Resource  type="repo"
//   id    repository id (required) — host and path of the upstream
//         repository, normalized by the enforcer: lowercase host, no scheme,
//         no leading/trailing "/" and no ".git" suffix (e.g.
//         "github.com/acme/app"). The first "/"-separated segment is the host.
//   host  repository host (resource.attributes["host"]) — derived from id by
//         Build/FromProto, carried separately so a policy can key on the host
//         without parsing id.
//
// Context
//   workspace  name of the workspace the request originates from (optional).
//              Set by the enforcer when it has bound the request to one of
//              the subject's own workspaces (api-server's git proxy binds by
//              the caller's pod IP); empty otherwise.
//
// Subject   injected by the backend from JWT claims (username, roles, email, ...)
//
// Obligations  (none) — allow/deny only
//
// git:fetch covers the read half of git's smart-HTTP protocol (clone, fetch,
// pull: info/refs?service=git-upload-pack and git-upload-pack); git:push
// covers the write half (info/refs?service=git-receive-pack and
// git-receive-pack). The enforcer must check git:push already on the
// info/refs advertisement, not only on the receive-pack POST, since that is
// where git decides between the two.
//
// Which upstream the request reaches — and with which token — is not part of
// this contract: the enforcer only ever proxies to the URL of one of the
// subject's own stored git credentials (identity's user credential store),
// so a repo the subject holds no credential for is never reachable, whatever
// the policy answers. The policy can only narrow that further (e.g. deny
// push to some hosts or repos).

import (
	"fmt"
	"strings"

	authzv1 "github.com/k8shell-io/common/pkg/api/gen/go/authz/v1"
)

const gitResourceType = "repo"

// GitAction is the action string of a git proxy policy check.
type GitAction string

const (
	// GitActionFetch reads from a repository: clone, fetch, pull.
	GitActionFetch GitAction = "git:fetch"
	// GitActionPush writes to a repository.
	GitActionPush GitAction = "git:push"
)

// GitResource holds the resource-scoped attributes for a git policy check.
type GitResource struct {
	// Repo is the normalized repository id, "host/path" (resource.id).
	Repo string

	// Host is the repository host (resource.attributes["host"]), always the
	// first "/"-separated segment of Repo.
	Host string
}

// GitContext holds the ambient context for a git policy check.
type GitContext struct {
	// Workspace is the name of the workspace the request originates from
	// (context["workspace"]); empty when the request isn't bound to one.
	Workspace string
}

// GitEvalRequest is the validated, typed model for git:fetch and git:push
// policy evaluation. Use NewGitEvalRequest to start building, then call
// Build to get a validated instance.
type GitEvalRequest struct {
	Action   GitAction
	Resource GitResource
	Context  GitContext
}

var _ EvalRequest = (*GitEvalRequest)(nil)

// NewGitEvalRequest begins building a GitEvalRequest for the given action
// and normalized repository id ("host/path"). Host is derived from repo.
// Call WithWorkspace to attach the originating workspace, then Build to
// validate and obtain the final struct.
func NewGitEvalRequest(action GitAction, repo string) *GitEvalRequest {
	return &GitEvalRequest{
		Action:   action,
		Resource: GitResource{Repo: repo, Host: gitRepoHost(repo)},
	}
}

// WithWorkspace sets the workspace the request originates from.
func (r *GitEvalRequest) WithWorkspace(workspace string) *GitEvalRequest {
	r.Context.Workspace = workspace
	return r
}

// Build validates the request and returns it if all constraints are satisfied.
// It is the required terminator for the builder chain.
func (r *GitEvalRequest) Build() (*GitEvalRequest, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Validate checks the request against the git:fetch/git:push contract.
// Implements EvalRequest.
func (r *GitEvalRequest) Validate() error {
	switch r.Action {
	case GitActionFetch, GitActionPush:
	default:
		return fmt.Errorf("git: action must be %q or %q, got %q", GitActionFetch, GitActionPush, r.Action)
	}
	if r.Resource.Repo == "" {
		return fmt.Errorf("%s: resource.id (repo) is required", r.Action)
	}
	if r.Resource.Host == "" || r.Resource.Host != gitRepoHost(r.Resource.Repo) {
		return fmt.Errorf("%s: resource host %q does not match repo %q", r.Action, r.Resource.Host, r.Resource.Repo)
	}
	return nil
}

// ToProto serializes the typed request into a gRPC EvaluateRequest, attaching
// the supplied JWT token.
// Implements EvalRequest.
func (r *GitEvalRequest) ToProto(token string) *authzv1.EvaluateRequest {
	req := &authzv1.EvaluateRequest{
		Token:  token,
		Action: string(r.Action),
		Resource: &authzv1.Resource{
			Type:       gitResourceType,
			Id:         r.Resource.Repo,
			Attributes: map[string]string{"host": r.Resource.Host},
		},
	}
	if r.Context.Workspace != "" {
		req.Context = map[string]string{"workspace": r.Context.Workspace}
	}
	return req
}

// GitEvalRequestFromProto converts a gRPC EvaluateRequest into a validated
// GitEvalRequest.
func GitEvalRequestFromProto(req *authzv1.EvaluateRequest) (*GitEvalRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("git: EvaluateRequest is nil")
	}
	if req.Resource == nil {
		return nil, fmt.Errorf("git: resource is nil")
	}
	if req.Resource.Type != gitResourceType {
		return nil, fmt.Errorf("git: resource type must be %q, got %q", gitResourceType, req.Resource.Type)
	}
	r := NewGitEvalRequest(GitAction(req.Action), req.Resource.Id)
	if h := req.Resource.Attributes["host"]; h != "" {
		r.Resource.Host = h
	}
	r.Context.Workspace = req.Context["workspace"]
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// gitRepoHost returns the host segment of a normalized "host/path" repo id.
func gitRepoHost(repo string) string {
	host, _, _ := strings.Cut(repo, "/")
	return host
}

// init registers capability probes for git:fetch and git:push. See
// CapabilityCheck and registerCapabilityCheck in capability.go.
func init() {
	for _, action := range []GitAction{GitActionFetch, GitActionPush} {
		registerCapabilityCheck(CapabilityCheck{
			Action: string(action), Package: "git", Scope: string(action),
			Build: func(ctx CapabilityContext) (EvalRequest, error) {
				return NewGitEvalRequest(action, capabilityWildcardRepo).Build()
			},
		})
	}
}
