// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package authz

// Contract: announcement:write
//
// Resource  type="announcement"
//   id     announcement id, as a decimal string — set for update/delete;
//          empty for create, where no id exists yet (allow/deny then rests
//          solely on the subject's roles, the same way org:create's
//          proposed name id is merely informational)
//   orgs   comma-separated list of organizations the announcement applies
//          (or would apply) to (resource.attributes["orgs"]); absent/empty
//          means global.
//   roles  comma-separated list of roles the announcement is further
//          scoped to (resource.attributes["roles"]); absent/empty means
//          every role. For create these are the requested scope; for
//          update/delete they are the announcement's current scope, so a
//          policy can restrict a scoped admin to only touch announcements
//          that already apply to their org/role — neither is re-evaluated
//          against the new scope an update requests.
//
// Context   (none)
//
// Subject   injected by the backend from JWT claims (username, roles, email, ...)
//
// Obligations  (none) — allow/deny only
//
// Covers create, update, and delete — one action for the whole resource,
// mirroring org:envvar:write's single write action rather than splitting
// into announcement:create/update/delete the way token:* does.
//
// Deliberately its own top-level package rather than folded under org as
// org:announcement:write: CreateAnnouncement can target zero, one, or many
// organizations in a single call — orgs empty means global — so there is no
// single org name to key a per-org resource id on the way org:envvar:write
// does. orgs/roles are carried as attribute context instead, so a policy
// that only cares about global admins can ignore them, while one that wants
// to grant org- or role-scoped announcement rights can key off either.
//
// Reading announcements (GetAnnouncement, ListAnnouncements,
// ListUnreadAnnouncements, ListUserAnnouncements) and marking one read
// (MarkAnnouncementRead) have no policy of their own — every authenticated
// user may read and acknowledge announcements; only publishing, editing, or
// removing one is gated.

import (
	"fmt"
	"strings"

	authzv1 "github.com/k8shell-io/common/pkg/api/gen/go/authz/v1"
)

const announcementResourceType = "announcement"

// AnnouncementResource holds the resource-scoped attributes for an
// announcement policy check.
type AnnouncementResource struct {
	// ID is the announcement's id, as a decimal string (resource.id in the
	// EvaluateRequest). Empty for announcement:write checks that precede a
	// create, where no id exists yet.
	ID string

	// Orgs names the organizations the announcement applies (or would
	// apply) to (resource.attributes["orgs"], comma-separated). Empty means
	// global. See the announcement:write contract doc for whether this is
	// the requested or the current scope.
	Orgs []string

	// Roles names the roles the announcement is (or would be) further
	// scoped to (resource.attributes["roles"], comma-separated). Empty
	// means every role. See the announcement:write contract doc for
	// whether this is the requested or the current scope.
	Roles []string
}

func announcementResourceToAttrs(r AnnouncementResource) map[string]string {
	attrs := map[string]string{}
	if len(r.Orgs) > 0 {
		attrs["orgs"] = strings.Join(r.Orgs, ",")
	}
	if len(r.Roles) > 0 {
		attrs["roles"] = strings.Join(r.Roles, ",")
	}
	if len(attrs) == 0 {
		return nil
	}
	return attrs
}

func announcementListFromAttrs(attrs map[string]string, key string) []string {
	v := attrs[key]
	if v == "" {
		return nil
	}
	return strings.Split(v, ",")
}

// AnnouncementWriteEvalRequest is the validated, typed model for
// announcement:write policy evaluation — creating, updating, or deleting a
// platform announcement. Use NewAnnouncementWriteEvalRequest to start
// building, then call Build to get a validated instance.
type AnnouncementWriteEvalRequest struct {
	Resource AnnouncementResource
}

var _ EvalRequest = (*AnnouncementWriteEvalRequest)(nil)

// NewAnnouncementWriteEvalRequest begins building an
// AnnouncementWriteEvalRequest for the given announcement id (empty when
// checking a create). Call WithOrgs/WithRoles to attach the announcement's
// scope, then Build to validate and obtain the final struct.
func NewAnnouncementWriteEvalRequest(id string) *AnnouncementWriteEvalRequest {
	return &AnnouncementWriteEvalRequest{Resource: AnnouncementResource{ID: id}}
}

// WithOrgs sets the organizations the announcement applies (or would apply)
// to; omit (or pass nil/empty) for a global announcement.
func (r *AnnouncementWriteEvalRequest) WithOrgs(orgs []string) *AnnouncementWriteEvalRequest {
	r.Resource.Orgs = orgs
	return r
}

// WithRoles sets the roles the announcement is (or would be) further scoped
// to; omit (or pass nil/empty) for every role.
func (r *AnnouncementWriteEvalRequest) WithRoles(roles []string) *AnnouncementWriteEvalRequest {
	r.Resource.Roles = roles
	return r
}

// Build validates the request and returns it if all constraints are satisfied.
// It is the required terminator for the builder chain.
func (r *AnnouncementWriteEvalRequest) Build() (*AnnouncementWriteEvalRequest, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// ToProto serializes the typed request into a gRPC EvaluateRequest, attaching
// the supplied JWT token.
// Implements EvalRequest.
func (r *AnnouncementWriteEvalRequest) ToProto(token string) *authzv1.EvaluateRequest {
	return &authzv1.EvaluateRequest{
		Token:  token,
		Action: "announcement:write",
		Resource: &authzv1.Resource{
			Type:       announcementResourceType,
			Id:         r.Resource.ID,
			Attributes: announcementResourceToAttrs(r.Resource),
		},
	}
}

// AnnouncementWriteEvalRequestFromProto converts a gRPC EvaluateRequest into
// a validated AnnouncementWriteEvalRequest.
func AnnouncementWriteEvalRequestFromProto(req *authzv1.EvaluateRequest) (*AnnouncementWriteEvalRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("announcement:write: EvaluateRequest is nil")
	}
	if req.Action != "announcement:write" {
		return nil, fmt.Errorf("announcement:write: action must be \"announcement:write\", got %q", req.Action)
	}
	if req.Resource == nil {
		return nil, fmt.Errorf("announcement:write: resource is nil")
	}
	if req.Resource.Type != announcementResourceType {
		return nil, fmt.Errorf("announcement:write: resource type must be %q, got %q", announcementResourceType, req.Resource.Type)
	}
	r := &AnnouncementWriteEvalRequest{
		Resource: AnnouncementResource{
			ID:    req.Resource.Id,
			Orgs:  announcementListFromAttrs(req.Resource.Attributes, "orgs"),
			Roles: announcementListFromAttrs(req.Resource.Attributes, "roles"),
		},
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Validate is a no-op for announcement:write — id, orgs, and roles are all
// optional (empty ahead of a create, or for a global/every-role
// announcement, is expected).
// Implements EvalRequest.
func (r *AnnouncementWriteEvalRequest) Validate() error { return nil }

// init registers a capability probe for announcement:write. See
// CapabilityCheck and registerCapabilityCheck in capability.go.
func init() {
	registerCapabilityCheck(CapabilityCheck{
		Action: "announcement:write", Package: "announcement", Scope: "announcement:write",
		Build: func(ctx CapabilityContext) (EvalRequest, error) {
			return NewAnnouncementWriteEvalRequest("").Build()
		},
	})
}
