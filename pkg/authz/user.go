// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package authz

// Contract: user:onboard
//
// Resource  type="user"
//   id   username               (required)
//   idp  identity provider name (required)
//   org  organization name      (optional)
//
// Context   (none)
//
// Subject   injected by the backend from JWT claims (username, roles, email, ...)
//
// Obligations
//   sudo       true | false
//   roles      JSON array of role name strings  (e.g. ["admin","dev"])
//   blueprints JSON array of blueprint name strings  (e.g. ["bp1","bp2"])
//
// ---
//
// Contract: user:create
//
// Resource  type="user"
//   id   username          (required) — the username of the new user
//   org  organization name (required) — the organization the new user will
//                                        belong to
//
// Context   (none)
//
// Subject   the ADMIN performing the creation, injected by the backend from
//           JWT claims (username, roles, email, ...) — NOT the new user being
//           created, who has no token yet. This differs from user:onboard,
//           where subject and resource are the same person (a user onboarding
//           themselves), and from user:onboard's idp attribute, which doesn't
//           apply here since the new user has no backing identity provider.
//
// Obligations
//   sudo       true | false
//   roles      JSON array of role name strings  (e.g. ["admin","dev"])
//   blueprints JSON array of blueprint name strings  (e.g. ["bp1","bp2"])
//
// ---
//
// Contract: user:auth
//
// Resource  type="user"
//   id   username               (required)
//   idp  identity provider name (required)
//   org  organization name      (optional)
//
// Context
//   surface  ssh | web (required) — the login surface being authenticated.
//            The enforcer evaluates once per surface it needs an answer for;
//            a single check answers only the surface named in the request.
//
// Subject   injected by the backend from JWT claims (username, roles, email, ...)
//
// Obligations
//   auth_methods  JSON array of allowed auth method strings — "publickey",
//                 "password", or both (e.g. ["publickey","password"]),
//                 scoped to the surface in the request context. The enforcer
//                 offers only the methods present in this list. publickey is
//                 only meaningful for the ssh surface.
//
// ---
//
// Contract: user:delete
//
// Resource  type="user"
//   id   username          (required) — the username of the user to delete
//   org  organization name (optional) — the user's organization, when known
//
// Context   (none)
//
// Subject   the ADMIN performing the deletion, injected by the backend from
//           JWT claims (username, roles, email, ...) — NOT the user being
//           deleted, mirroring user:create's admin-on-behalf-of-someone-else
//           subject model.
//
// Obligations  (none) — allow/deny only
//
// ---
//
// Contract: user:read
//
// Resource  type="user"
//   id   username (required)
//
// Context
//   data_type  profile | credentials | blueprints | roles | keys  (required)
//              profile returns the full profile view, including the sudo and
//              locked flags — those are not broken out into their own
//              data_type for reads, only for writes (see user:write below).
//              keys covers SSH public key listing, distinct from credentials.
//
// Subject   injected by the backend from JWT claims (username, roles, email, ...)
//
// Obligations  (none) — allow/deny only
//
// ---
//
// Contract: user:list
//
// Resource  type="user"
//   id   (none)
//
// Context   (none)
//
// Subject   injected by the backend from JWT claims (username, roles, email, ...)
//
// Obligations
//   roles      JSON array of role name strings — the enforcer lists only
//              users who have at least one of these roles (e.g. ["admin","dev"])
//   blueprints JSON array of blueprint name strings — the enforcer lists only
//              users granted at least one of these blueprints
//   org        organization name — the enforcer lists only users in this org
//
//              Each key is independent and optional; when absent, that
//              dimension is unrestricted. When present, dimensions combine
//              with AND (e.g. roles + org means "has one of these roles AND
//              is in this org").
//
// ---
//
// Contract: token:create
//
// Resource  type="user"
//   id   username (required) — the user who will own the new token
//
// Context
//   source  web-flow | api  (required)
//           web-flow — token issued at the end of an OAuth initiated by the CLI
//           api      — token created via a direct API request
//
// Subject   injected by the backend from JWT claims (username, roles, email, ...)
//
// Obligations
//   scopes      JSON array of scope strings  (e.g. ["token:read","workspace:create"])
//   expires_in  Go duration string (e.g. "720h") | "never" for no expiry
//
// ---
//
// Contract: user:write
//
// Resource  type="user"
//   id   username (required) — the user record being mutated
//
// Context
//   data_type  profile | credentials | blueprints | roles | keys | sudo | locked | org | posix  (required)
//              profile     — self-editable identity fields (e.g. fullname,
//                            shell, email); subject may write its own record.
//              credentials — auth credentials.
//              blueprints  — blueprint access grants.
//              roles       — role assignments.
//              keys        — SSH public keys, distinct from credentials.
//              sudo        — sudo flag; admin-managed only, never self, even
//                            for an admin editing their own record.
//              locked      — account lock/suspension flag; admin-managed
//                            only, never self.
//              org         — organization membership; admin-managed only,
//                            never self.
//              posix       — POSIX uid/gid; admin-managed only, never self.
//
//              A single mutating RPC that touches fields from more than one
//              group (e.g. UpdateUser, which carries fullname/email alongside
//              sudo, locked, org, and posix) must issue one user:write check
//              per group actually present in the request, and apply none of
//              the changes unless every required check passes.
//
// Subject   injected by the backend from JWT claims (username, roles, email, ...)
//
// Obligations  (none) — allow/deny only
//
// ---
//
// Contract: token:read
//
// Resource  type="user"
//   id   username (required) — the user whose tokens are being read
//
// Context   (none)
//
// Subject   injected by the backend from JWT claims (username, roles, email, ...)
//
// Obligations  (none) — allow/deny only

import (
	"encoding/json"
	"fmt"
	"time"

	authzv1 "github.com/k8shell-io/common/pkg/api/gen/go/authz/v1"
	"github.com/k8shell-io/common/pkg/models"
)

// UserDataType identifies which slice of user data is being accessed in
// user:read and user:write. UserDataTypeSudo, UserDataTypeLocked,
// UserDataTypeOrg, UserDataTypePosix, and UserDataTypePassword are write-only
// values: user:read never selects them individually, since UserDataTypeProfile
// already returns the full profile view including sudo, locked, org, and uid/gid,
// and a password is never readable at all.
type UserDataType string

const (
	UserDataTypeProfile     UserDataType = "profile"
	UserDataTypeCredentials UserDataType = "credentials"
	UserDataTypeBlueprints  UserDataType = "blueprints"
	UserDataTypeRoles       UserDataType = "roles"
	UserDataTypeKeys        UserDataType = "keys"
	UserDataTypeSudo        UserDataType = "sudo"
	UserDataTypeLocked      UserDataType = "locked"
	UserDataTypeOrg         UserDataType = "org"
	UserDataTypePosix       UserDataType = "posix"
	UserDataTypePassword    UserDataType = "password"
)

// validateUserDataType checks the data types valid for user:read.
func validateUserDataType(dt UserDataType) error {
	switch dt {
	case UserDataTypeProfile, UserDataTypeCredentials, UserDataTypeBlueprints, UserDataTypeRoles, UserDataTypeKeys:
		return nil
	default:
		return fmt.Errorf("context \"data_type\" must be %q, %q, %q, %q, or %q, got %q",
			UserDataTypeProfile, UserDataTypeCredentials, UserDataTypeBlueprints, UserDataTypeRoles, UserDataTypeKeys, dt)
	}
}

// validateUserWriteDataType checks the data types valid for user:write, which
// additionally includes the admin-managed sudo, locked, org, and posix groups.
func validateUserWriteDataType(dt UserDataType) error {
	switch dt {
	case UserDataTypeProfile, UserDataTypeCredentials, UserDataTypeBlueprints, UserDataTypeRoles, UserDataTypeKeys, UserDataTypeSudo, UserDataTypeLocked, UserDataTypeOrg, UserDataTypePosix, UserDataTypePassword:
		return nil
	default:
		return fmt.Errorf("context \"data_type\" must be %q, %q, %q, %q, %q, %q, %q, %q, %q, or %q, got %q",
			UserDataTypeProfile, UserDataTypeCredentials, UserDataTypeBlueprints, UserDataTypeRoles, UserDataTypeKeys,
			UserDataTypeSudo, UserDataTypeLocked, UserDataTypeOrg, UserDataTypePosix, UserDataTypePassword, dt)
	}
}

// UserAuthMethod is the typed representation of a user authentication method.
type UserAuthMethod string

const (
	UserAuthMethodPublicKey UserAuthMethod = "publickey"
	UserAuthMethodPassword  UserAuthMethod = "password"
)

// AuthSurface identifies which login surface a user:auth check is evaluating.
// publickey is only meaningful for AuthSurfaceSSH; AuthSurfaceWeb is
// password-only in practice, though the contract does not enforce that.
type AuthSurface string

const (
	AuthSurfaceSSH AuthSurface = "ssh"
	AuthSurfaceWeb AuthSurface = "web"
)

// validateAuthSurface checks the surface valid for user:auth.
func validateAuthSurface(s AuthSurface) error {
	switch s {
	case AuthSurfaceSSH, AuthSurfaceWeb:
		return nil
	default:
		return fmt.Errorf("user:auth: context \"surface\" must be %q or %q, got %q", AuthSurfaceSSH, AuthSurfaceWeb, s)
	}
}

// UserResource holds the resource-scoped attributes for a user policy check.
type UserResource struct {
	// ID is the username (resource.id in the EvaluateRequest).
	ID string

	// IDP is the identity provider through which the user was onboarded
	// (resource.attributes["idp"]).
	IDP string

	// Org is the user's organization (resource.attributes["org"]).
	Org string
}

func userResourceToAttrs(r UserResource) map[string]string {
	attrs := map[string]string{
		"idp": r.IDP,
	}
	if r.Org != "" {
		attrs["org"] = r.Org
	}
	return attrs
}

func userResourceFromAttrs(id string, attrs map[string]string) UserResource {
	return UserResource{
		ID:  id,
		IDP: attrs["idp"],
		Org: attrs["org"],
	}
}

func validateUserResource(r UserResource) error {
	if r.ID == "" {
		return fmt.Errorf("user: resource ID (username) is required")
	}
	if r.IDP == "" {
		return fmt.Errorf("user: resource attribute \"idp\" is required")
	}
	return nil
}

// UserOnboardEvalRequest is the validated, typed model for user:onboard policy
// evaluation. Use NewUserOnboardEvalRequest to start building, then chain With*
// methods and call Build to get a validated instance.
type UserOnboardEvalRequest struct {
	Resource UserResource
}

var _ EvalRequest = (*UserOnboardEvalRequest)(nil)

// NewUserOnboardEvalRequest begins building a UserOnboardEvalRequest for the
// given username. Chain With* methods to supply additional fields, then call
// Build to validate and obtain the final struct.
func NewUserOnboardEvalRequest(username string) *UserOnboardEvalRequest {
	return &UserOnboardEvalRequest{
		Resource: UserResource{ID: username},
	}
}

// WithIDP sets the identity provider name on the resource.
func (r *UserOnboardEvalRequest) WithIDP(idp string) *UserOnboardEvalRequest {
	r.Resource.IDP = idp
	return r
}

// WithOrg sets the organization on the resource.
func (r *UserOnboardEvalRequest) WithOrg(org string) *UserOnboardEvalRequest {
	r.Resource.Org = org
	return r
}

// Build validates the request and returns it if all constraints are satisfied.
// It is the required terminator for the builder chain.
func (r *UserOnboardEvalRequest) Build() (*UserOnboardEvalRequest, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// ToProto serializes the typed request into a gRPC EvaluateRequest, attaching
// the supplied JWT token.
// Implements EvalRequest.
func (r *UserOnboardEvalRequest) ToProto(token string) *authzv1.EvaluateRequest {
	return &authzv1.EvaluateRequest{
		Token:  token,
		Action: "user:onboard",
		Resource: &authzv1.Resource{
			Type:       "user",
			Id:         r.Resource.ID,
			Attributes: userResourceToAttrs(r.Resource),
		},
	}
}

// UserOnboardEvalRequestFromProto converts a gRPC EvaluateRequest into a
// validated UserOnboardEvalRequest. Returns an error if the request does not
// conform to the user:onboard contract.
func UserOnboardEvalRequestFromProto(req *authzv1.EvaluateRequest) (*UserOnboardEvalRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("user:onboard: EvaluateRequest is nil")
	}
	if req.Action != "user:onboard" {
		return nil, fmt.Errorf("user:onboard: action must be \"user:onboard\", got %q", req.Action)
	}
	if req.Resource == nil {
		return nil, fmt.Errorf("user:onboard: resource is nil")
	}
	if req.Resource.Type != "user" {
		return nil, fmt.Errorf("user:onboard: resource type must be \"user\", got %q", req.Resource.Type)
	}
	r := &UserOnboardEvalRequest{
		Resource: userResourceFromAttrs(req.Resource.Id, req.Resource.Attributes),
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Validate checks the request against the user:onboard contract.
// Implements EvalRequest.
func (r *UserOnboardEvalRequest) Validate() error {
	return validateUserResource(r.Resource)
}

// UserCreateEvalRequest is the validated, typed model for user:create policy
// evaluation. Use NewUserCreateEvalRequest to start building, then chain
// With* methods and call Build to get a validated instance.
//
// user:create authorizes an admin to create a brand-new local user record --
// one with no backing identity provider, unlike user:onboard. The acting
// principal is the admin performing the creation, not the new user, so
// callers evaluate this with the admin's own token rather than one issued
// for the user being created.
type UserCreateEvalRequest struct {
	Resource UserResource
}

var _ EvalRequest = (*UserCreateEvalRequest)(nil)

// NewUserCreateEvalRequest begins building a UserCreateEvalRequest for the
// given username. Chain With* methods to supply additional fields, then call
// Build to validate and obtain the final struct.
func NewUserCreateEvalRequest(username string) *UserCreateEvalRequest {
	return &UserCreateEvalRequest{
		Resource: UserResource{ID: username},
	}
}

// WithOrg sets the organization the new user will belong to.
func (r *UserCreateEvalRequest) WithOrg(org string) *UserCreateEvalRequest {
	r.Resource.Org = org
	return r
}

// Build validates the request and returns it if all constraints are satisfied.
// It is the required terminator for the builder chain.
func (r *UserCreateEvalRequest) Build() (*UserCreateEvalRequest, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// ToProto serializes the typed request into a gRPC EvaluateRequest, attaching
// the supplied JWT token.
// Implements EvalRequest.
func (r *UserCreateEvalRequest) ToProto(token string) *authzv1.EvaluateRequest {
	return &authzv1.EvaluateRequest{
		Token:  token,
		Action: "user:create",
		Resource: &authzv1.Resource{
			Type: "user",
			Id:   r.Resource.ID,
			Attributes: map[string]string{
				"org": r.Resource.Org,
			},
		},
	}
}

// UserCreateEvalRequestFromProto converts a gRPC EvaluateRequest into a
// validated UserCreateEvalRequest. Returns an error if the request does not
// conform to the user:create contract.
func UserCreateEvalRequestFromProto(req *authzv1.EvaluateRequest) (*UserCreateEvalRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("user:create: EvaluateRequest is nil")
	}
	if req.Action != "user:create" {
		return nil, fmt.Errorf("user:create: action must be \"user:create\", got %q", req.Action)
	}
	if req.Resource == nil {
		return nil, fmt.Errorf("user:create: resource is nil")
	}
	if req.Resource.Type != "user" {
		return nil, fmt.Errorf("user:create: resource type must be \"user\", got %q", req.Resource.Type)
	}
	r := &UserCreateEvalRequest{
		Resource: UserResource{
			ID:  req.Resource.Id,
			Org: req.Resource.Attributes["org"],
		},
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Validate checks the request against the user:create contract.
// Implements EvalRequest.
func (r *UserCreateEvalRequest) Validate() error {
	if r.Resource.ID == "" {
		return fmt.Errorf("user:create: resource ID (username) is required")
	}
	if r.Resource.Org == "" {
		return fmt.Errorf("user:create: resource attribute \"org\" is required")
	}
	return nil
}

// UserDeleteEvalRequest is the validated, typed model for user:delete policy
// evaluation. Use NewUserDeleteEvalRequest to start building, then chain
// With* methods and call Build to get a validated instance.
//
// Like user:create, the acting principal is the admin performing the
// deletion, not the user being deleted, so callers evaluate this with the
// admin's own token.
type UserDeleteEvalRequest struct {
	Resource UserResource
}

var _ EvalRequest = (*UserDeleteEvalRequest)(nil)

// NewUserDeleteEvalRequest begins building a UserDeleteEvalRequest for the
// given username. Chain With* methods to supply additional fields, then call
// Build to validate and obtain the final struct.
func NewUserDeleteEvalRequest(username string) *UserDeleteEvalRequest {
	return &UserDeleteEvalRequest{
		Resource: UserResource{ID: username},
	}
}

// WithOrg sets the user's organization on the resource.
func (r *UserDeleteEvalRequest) WithOrg(org string) *UserDeleteEvalRequest {
	r.Resource.Org = org
	return r
}

// Build validates the request and returns it if all constraints are satisfied.
// It is the required terminator for the builder chain.
func (r *UserDeleteEvalRequest) Build() (*UserDeleteEvalRequest, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// ToProto serializes the typed request into a gRPC EvaluateRequest, attaching
// the supplied JWT token.
// Implements EvalRequest.
func (r *UserDeleteEvalRequest) ToProto(token string) *authzv1.EvaluateRequest {
	attrs := map[string]string{}
	if r.Resource.Org != "" {
		attrs["org"] = r.Resource.Org
	}
	return &authzv1.EvaluateRequest{
		Token:  token,
		Action: "user:delete",
		Resource: &authzv1.Resource{
			Type:       "user",
			Id:         r.Resource.ID,
			Attributes: attrs,
		},
	}
}

// UserDeleteEvalRequestFromProto converts a gRPC EvaluateRequest into a
// validated UserDeleteEvalRequest. Returns an error if the request does not
// conform to the user:delete contract.
func UserDeleteEvalRequestFromProto(req *authzv1.EvaluateRequest) (*UserDeleteEvalRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("user:delete: EvaluateRequest is nil")
	}
	if req.Action != "user:delete" {
		return nil, fmt.Errorf("user:delete: action must be \"user:delete\", got %q", req.Action)
	}
	if req.Resource == nil {
		return nil, fmt.Errorf("user:delete: resource is nil")
	}
	if req.Resource.Type != "user" {
		return nil, fmt.Errorf("user:delete: resource type must be \"user\", got %q", req.Resource.Type)
	}
	r := &UserDeleteEvalRequest{
		Resource: UserResource{
			ID:  req.Resource.Id,
			Org: req.Resource.Attributes["org"],
		},
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Validate checks the request against the user:delete contract.
// Implements EvalRequest.
func (r *UserDeleteEvalRequest) Validate() error {
	if r.Resource.ID == "" {
		return fmt.Errorf("user:delete: resource ID (username) is required")
	}
	return nil
}

// UserAuthContext holds the context-scoped attributes for a user:auth policy check.
type UserAuthContext struct {
	// Surface is the login surface being authenticated (context["surface"]).
	Surface AuthSurface
}

// UserAuthEvalRequest is the validated, typed model for user:auth policy
// evaluation. Use NewUserAuthEvalRequest to start building, then chain With*
// methods and call Build to get a validated instance.
type UserAuthEvalRequest struct {
	Resource UserResource
	Context  UserAuthContext
}

var _ EvalRequest = (*UserAuthEvalRequest)(nil)

// NewUserAuthEvalRequest begins building a UserAuthEvalRequest for the given
// username. Chain With* methods to supply additional fields, then call Build
// to validate and obtain the final struct.
func NewUserAuthEvalRequest(username string) *UserAuthEvalRequest {
	return &UserAuthEvalRequest{
		Resource: UserResource{ID: username},
	}
}

// WithIDP sets the identity provider name on the resource.
func (r *UserAuthEvalRequest) WithIDP(idp string) *UserAuthEvalRequest {
	r.Resource.IDP = idp
	return r
}

// WithOrg sets the organization on the resource.
func (r *UserAuthEvalRequest) WithOrg(org string) *UserAuthEvalRequest {
	r.Resource.Org = org
	return r
}

// WithSurface sets the login surface being authenticated on the context.
func (r *UserAuthEvalRequest) WithSurface(surface AuthSurface) *UserAuthEvalRequest {
	r.Context.Surface = surface
	return r
}

// Build validates the request and returns it if all constraints are satisfied.
// It is the required terminator for the builder chain.
func (r *UserAuthEvalRequest) Build() (*UserAuthEvalRequest, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// ToProto serializes the typed request into a gRPC EvaluateRequest, attaching
// the supplied JWT token.
// Implements EvalRequest.
func (r *UserAuthEvalRequest) ToProto(token string) *authzv1.EvaluateRequest {
	return &authzv1.EvaluateRequest{
		Token:  token,
		Action: "user:auth",
		Resource: &authzv1.Resource{
			Type:       "user",
			Id:         r.Resource.ID,
			Attributes: userResourceToAttrs(r.Resource),
		},
		Context: map[string]string{"surface": string(r.Context.Surface)},
	}
}

// UserAuthEvalRequestFromProto converts a gRPC EvaluateRequest into a
// validated UserAuthEvalRequest. Returns an error if the request does not
// conform to the user:auth contract.
func UserAuthEvalRequestFromProto(req *authzv1.EvaluateRequest) (*UserAuthEvalRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("user:auth: EvaluateRequest is nil")
	}
	if req.Action != "user:auth" {
		return nil, fmt.Errorf("user:auth: action must be \"user:auth\", got %q", req.Action)
	}
	if req.Resource == nil {
		return nil, fmt.Errorf("user:auth: resource is nil")
	}
	if req.Resource.Type != "user" {
		return nil, fmt.Errorf("user:auth: resource type must be \"user\", got %q", req.Resource.Type)
	}
	r := &UserAuthEvalRequest{
		Resource: userResourceFromAttrs(req.Resource.Id, req.Resource.Attributes),
		Context:  UserAuthContext{Surface: AuthSurface(req.Context["surface"])},
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Validate checks the request against the user:auth contract: ID and IDP are
// required, and surface must be a recognized value.
// Implements EvalRequest.
func (r *UserAuthEvalRequest) Validate() error {
	if err := validateUserResource(r.Resource); err != nil {
		return err
	}
	return validateAuthSurface(r.Context.Surface)
}

// UserReadEvalRequest is the validated, typed model for user:read policy
// evaluation. Use NewUserReadEvalRequest to start building, then call Build
// to get a validated instance.
type UserReadEvalRequest struct {
	Resource UserResource
	DataType UserDataType
}

var _ EvalRequest = (*UserReadEvalRequest)(nil)

// NewUserReadEvalRequest begins building a UserReadEvalRequest for the given
// target username.
func NewUserReadEvalRequest(username string) *UserReadEvalRequest {
	return &UserReadEvalRequest{Resource: UserResource{ID: username}}
}

// WithDataType sets the data type being accessed.
func (r *UserReadEvalRequest) WithDataType(dt UserDataType) *UserReadEvalRequest {
	r.DataType = dt
	return r
}

// Build validates the request and returns it if all constraints are satisfied.
// It is the required terminator for the builder chain.
func (r *UserReadEvalRequest) Build() (*UserReadEvalRequest, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// ToProto serializes the typed request into a gRPC EvaluateRequest, attaching
// the supplied JWT token.
// Implements EvalRequest.
func (r *UserReadEvalRequest) ToProto(token string) *authzv1.EvaluateRequest {
	return &authzv1.EvaluateRequest{
		Token:  token,
		Action: "user:read",
		Resource: &authzv1.Resource{
			Type: "user",
			Id:   r.Resource.ID,
		},
		Context: map[string]string{"data_type": string(r.DataType)},
	}
}

// UserReadEvalRequestFromProto converts a gRPC EvaluateRequest into a
// validated UserReadEvalRequest.
func UserReadEvalRequestFromProto(req *authzv1.EvaluateRequest) (*UserReadEvalRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("user:read: EvaluateRequest is nil")
	}
	if req.Action != "user:read" {
		return nil, fmt.Errorf("user:read: action must be \"user:read\", got %q", req.Action)
	}
	if req.Resource == nil {
		return nil, fmt.Errorf("user:read: resource is nil")
	}
	if req.Resource.Type != "user" {
		return nil, fmt.Errorf("user:read: resource type must be \"user\", got %q", req.Resource.Type)
	}
	r := &UserReadEvalRequest{
		Resource: UserResource{ID: req.Resource.Id},
		DataType: UserDataType(req.Context["data_type"]),
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Validate checks the request against the user:read contract.
// Implements EvalRequest.
func (r *UserReadEvalRequest) Validate() error {
	if r.Resource.ID == "" {
		return fmt.Errorf("user:read: resource ID (username) is required")
	}
	if err := validateUserDataType(r.DataType); err != nil {
		return fmt.Errorf("user:read: %w", err)
	}
	return nil
}

// UserListEvalRequest is the validated, typed model for user:list policy
// evaluation. No resource id is required; the subject claims determine access.
type UserListEvalRequest struct{}

var _ EvalRequest = (*UserListEvalRequest)(nil)

// NewUserListEvalRequest returns a UserListEvalRequest ready to be built.
func NewUserListEvalRequest() *UserListEvalRequest {
	return &UserListEvalRequest{}
}

// Build returns the request. It is the required terminator for the builder chain.
func (r *UserListEvalRequest) Build() (*UserListEvalRequest, error) {
	return r, nil
}

// ToProto serializes the typed request into a gRPC EvaluateRequest, attaching
// the supplied JWT token.
// Implements EvalRequest.
func (r *UserListEvalRequest) ToProto(token string) *authzv1.EvaluateRequest {
	return &authzv1.EvaluateRequest{
		Token:  token,
		Action: "user:list",
		Resource: &authzv1.Resource{
			Type: "user",
		},
	}
}

// UserListEvalRequestFromProto converts a gRPC EvaluateRequest into a
// validated UserListEvalRequest.
func UserListEvalRequestFromProto(req *authzv1.EvaluateRequest) (*UserListEvalRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("user:list: EvaluateRequest is nil")
	}
	if req.Action != "user:list" {
		return nil, fmt.Errorf("user:list: action must be \"user:list\", got %q", req.Action)
	}
	if req.Resource == nil {
		return nil, fmt.Errorf("user:list: resource is nil")
	}
	if req.Resource.Type != "user" {
		return nil, fmt.Errorf("user:list: resource type must be \"user\", got %q", req.Resource.Type)
	}
	return &UserListEvalRequest{}, nil
}

// Validate is a no-op for user:list; no fields are required.
// Implements EvalRequest.
func (r *UserListEvalRequest) Validate() error { return nil }

// TokenCreateSource identifies how the token creation was initiated.
type TokenCreateSource string

const (
	// TokenCreateSourceWebFlow is set when the token is issued at the end of an
	// OAuth/device login flow initiated by the CLI.
	TokenCreateSourceWebFlow TokenCreateSource = "web-flow"

	// TokenCreateSourceAPI is set when the token is created via a direct API request.
	TokenCreateSourceAPI TokenCreateSource = "api"
)

var validTokenCreateSources = map[TokenCreateSource]struct{}{
	TokenCreateSourceWebFlow: {},
	TokenCreateSourceAPI:     {},
}

// TokenCreateContext holds the ambient attributes for a token:create request.
type TokenCreateContext struct {
	// Source is how the token creation was initiated (context["source"]).
	Source TokenCreateSource
}

// UserTokenCreateEvalRequest is the validated, typed model for token:create
// policy evaluation. The resource ID is the username of the token owner.
type UserTokenCreateEvalRequest struct {
	Resource UserResource
	Context  TokenCreateContext
}

var _ EvalRequest = (*UserTokenCreateEvalRequest)(nil)

// NewUserTokenCreateEvalRequest begins building a UserTokenCreateEvalRequest
// for the given username (the token owner). Call WithSource then Build.
func NewUserTokenCreateEvalRequest(username string) *UserTokenCreateEvalRequest {
	return &UserTokenCreateEvalRequest{Resource: UserResource{ID: username}}
}

// WithSource sets the token creation source on the context.
func (r *UserTokenCreateEvalRequest) WithSource(source TokenCreateSource) *UserTokenCreateEvalRequest {
	r.Context.Source = source
	return r
}

// Build validates the request and returns it if all constraints are satisfied.
// It is the required terminator for the builder chain.
func (r *UserTokenCreateEvalRequest) Build() (*UserTokenCreateEvalRequest, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// ToProto serializes the typed request into a gRPC EvaluateRequest, attaching
// the supplied JWT token.
// Implements EvalRequest.
func (r *UserTokenCreateEvalRequest) ToProto(token string) *authzv1.EvaluateRequest {
	return &authzv1.EvaluateRequest{
		Token:  token,
		Action: "token:create",
		Resource: &authzv1.Resource{
			Type: "user",
			Id:   r.Resource.ID,
		},
		Context: map[string]string{"source": string(r.Context.Source)},
	}
}

// UserTokenCreateEvalRequestFromProto converts a gRPC EvaluateRequest into a
// validated UserTokenCreateEvalRequest.
func UserTokenCreateEvalRequestFromProto(req *authzv1.EvaluateRequest) (*UserTokenCreateEvalRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("token:create: EvaluateRequest is nil")
	}
	if req.Action != "token:create" {
		return nil, fmt.Errorf("token:create: action must be \"token:create\", got %q", req.Action)
	}
	if req.Resource == nil {
		return nil, fmt.Errorf("token:create: resource is nil")
	}
	if req.Resource.Type != "user" {
		return nil, fmt.Errorf("token:create: resource type must be \"user\", got %q", req.Resource.Type)
	}
	r := &UserTokenCreateEvalRequest{
		Resource: UserResource{ID: req.Resource.Id},
		Context:  TokenCreateContext{Source: TokenCreateSource(req.Context["source"])},
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Validate checks the request against the token:create contract.
// Implements EvalRequest.
func (r *UserTokenCreateEvalRequest) Validate() error {
	if r.Resource.ID == "" {
		return fmt.Errorf("token:create: resource ID (username) is required")
	}
	if _, ok := validTokenCreateSources[r.Context.Source]; !ok {
		return fmt.Errorf("token:create: context \"source\" must be %q or %q, got %q",
			TokenCreateSourceWebFlow, TokenCreateSourceAPI, r.Context.Source)
	}
	return nil
}

// UserTokenReadEvalRequest is the validated, typed model for token:read policy
// evaluation. The resource ID is the username whose tokens are being read.
type UserTokenReadEvalRequest struct {
	Resource UserResource
}

var _ EvalRequest = (*UserTokenReadEvalRequest)(nil)

// NewUserTokenReadEvalRequest begins building a UserTokenReadEvalRequest for
// the given username (the token owner). Call Build to validate.
func NewUserTokenReadEvalRequest(username string) *UserTokenReadEvalRequest {
	return &UserTokenReadEvalRequest{Resource: UserResource{ID: username}}
}

// Build validates the request and returns it if all constraints are satisfied.
// It is the required terminator for the builder chain.
func (r *UserTokenReadEvalRequest) Build() (*UserTokenReadEvalRequest, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// ToProto serializes the typed request into a gRPC EvaluateRequest, attaching
// the supplied JWT token.
// Implements EvalRequest.
func (r *UserTokenReadEvalRequest) ToProto(token string) *authzv1.EvaluateRequest {
	return &authzv1.EvaluateRequest{
		Token:  token,
		Action: "token:read",
		Resource: &authzv1.Resource{
			Type: "user",
			Id:   r.Resource.ID,
		},
	}
}

// UserTokenReadEvalRequestFromProto converts a gRPC EvaluateRequest into a
// validated UserTokenReadEvalRequest.
func UserTokenReadEvalRequestFromProto(req *authzv1.EvaluateRequest) (*UserTokenReadEvalRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("token:read: EvaluateRequest is nil")
	}
	if req.Action != "token:read" {
		return nil, fmt.Errorf("token:read: action must be \"token:read\", got %q", req.Action)
	}
	if req.Resource == nil {
		return nil, fmt.Errorf("token:read: resource is nil")
	}
	if req.Resource.Type != "user" {
		return nil, fmt.Errorf("token:read: resource type must be \"user\", got %q", req.Resource.Type)
	}
	r := &UserTokenReadEvalRequest{
		Resource: UserResource{ID: req.Resource.Id},
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Validate checks the request against the token:read contract.
// Implements EvalRequest.
func (r *UserTokenReadEvalRequest) Validate() error {
	if r.Resource.ID == "" {
		return fmt.Errorf("token:read: resource ID (username) is required")
	}
	return nil
}

// UserWriteEvalRequest is the validated, typed model for user:write policy
// evaluation. It covers all mutations to a user record: profile fields, roles,
// blueprints, and auth keys. Use NewUserWriteEvalRequest to build it.
type UserWriteEvalRequest struct {
	Resource UserResource
	DataType UserDataType
}

var _ EvalRequest = (*UserWriteEvalRequest)(nil)

// NewUserWriteEvalRequest begins building a UserWriteEvalRequest for the given
// target username. Call WithDataType then Build to validate and obtain the
// final struct.
func NewUserWriteEvalRequest(username string) *UserWriteEvalRequest {
	return &UserWriteEvalRequest{Resource: UserResource{ID: username}}
}

// WithDataType sets the data type being mutated.
func (r *UserWriteEvalRequest) WithDataType(dt UserDataType) *UserWriteEvalRequest {
	r.DataType = dt
	return r
}

// Build validates the request and returns it if all constraints are satisfied.
// It is the required terminator for the builder chain.
func (r *UserWriteEvalRequest) Build() (*UserWriteEvalRequest, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// ToProto serializes the typed request into a gRPC EvaluateRequest, attaching
// the supplied JWT token.
// Implements EvalRequest.
func (r *UserWriteEvalRequest) ToProto(token string) *authzv1.EvaluateRequest {
	return &authzv1.EvaluateRequest{
		Token:  token,
		Action: "user:write",
		Resource: &authzv1.Resource{
			Type: "user",
			Id:   r.Resource.ID,
		},
		Context: map[string]string{"data_type": string(r.DataType)},
	}
}

// UserWriteEvalRequestFromProto converts a gRPC EvaluateRequest into a
// validated UserWriteEvalRequest.
func UserWriteEvalRequestFromProto(req *authzv1.EvaluateRequest) (*UserWriteEvalRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("user:write: EvaluateRequest is nil")
	}
	if req.Action != "user:write" {
		return nil, fmt.Errorf("user:write: action must be \"user:write\", got %q", req.Action)
	}
	if req.Resource == nil {
		return nil, fmt.Errorf("user:write: resource is nil")
	}
	if req.Resource.Type != "user" {
		return nil, fmt.Errorf("user:write: resource type must be \"user\", got %q", req.Resource.Type)
	}
	r := &UserWriteEvalRequest{
		Resource: UserResource{ID: req.Resource.Id},
		DataType: UserDataType(req.Context["data_type"]),
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Validate checks the request against the user:write contract.
// Implements EvalRequest.
func (r *UserWriteEvalRequest) Validate() error {
	if r.Resource.ID == "" {
		return fmt.Errorf("user:write: resource ID (username) is required")
	}
	if err := validateUserWriteDataType(r.DataType); err != nil {
		return fmt.Errorf("user:write: %w", err)
	}
	return nil
}

const (
	// ObligationKeyAuthMethods is the key the policy engine writes to indicate
	// which SSH authentication methods are available to the user. The value is
	// a JSON-encoded array of method strings (e.g. ["publickey","password"]).
	ObligationKeyAuthMethods = "auth_methods"
)

// AuthMethodsObligation is the typed representation of the "auth_methods"
// obligation key returned by the policy engine in a PolicyResult for
// user:auth.
type AuthMethodsObligation struct {
	// Methods is the list of authentication methods the policy permits for
	// the user (any of UserAuthMethodPublicKey, UserAuthMethodPassword).
	Methods []UserAuthMethod
}

// ParseAuthMethodsObligation reads the "auth_methods" key from the
// obligations map. Returns (obligation, true) when the key is present, (zero
// value, false) when the policy did not set an auth_methods obligation — in
// that case the enforcer should offer no authentication methods.
func ParseAuthMethodsObligation(obligations map[string]string) (AuthMethodsObligation, bool) {
	v, ok := obligations[ObligationKeyAuthMethods]
	if !ok {
		return AuthMethodsObligation{}, false
	}
	var raw []string
	if err := json.Unmarshal([]byte(v), &raw); err != nil {
		return AuthMethodsObligation{}, false
	}
	methods := make([]UserAuthMethod, 0, len(raw))
	for _, m := range raw {
		if m != "" {
			methods = append(methods, UserAuthMethod(m))
		}
	}
	return AuthMethodsObligation{Methods: methods}, true
}

const (
	// ObligationKeyScopes is the key the policy engine writes to restrict the
	// scopes a newly created token may carry. The value is a JSON-encoded array
	// of scope strings (e.g. ["token:read","workspace:start"]).
	ObligationKeyScopes = "scopes"

	// ObligationKeyExpiresIn is the key the policy engine writes to cap a
	// token's lifetime. The value is a Go duration string (e.g. "720h") or the
	// literal "never" to permit a non-expiring token.
	ObligationKeyExpiresIn = "expires_in"

	// ObligationExpiresInNever is the sentinel value meaning no expiry.
	ObligationExpiresInNever = "never"
)

// ScopesObligation is the typed representation of the "scopes" obligation key
// returned by the policy engine in a PolicyResult for token:create.
type ScopesObligation struct {
	// Scopes is the list of scopes the policy permits on the new token.
	Scopes []string
}

// ParseScopesObligation reads the "scopes" key from the obligations map.
// Returns (obligation, true) when the key is present, (zero value, false) when
// the policy did not set a scopes obligation.
func ParseScopesObligation(obligations map[string]string) (ScopesObligation, bool) {
	v, ok := obligations[ObligationKeyScopes]
	if !ok {
		return ScopesObligation{}, false
	}
	var raw []string
	if err := json.Unmarshal([]byte(v), &raw); err != nil {
		return ScopesObligation{}, false
	}
	scopes := make([]string, 0, len(raw))
	for _, s := range raw {
		if s != "" {
			scopes = append(scopes, s)
		}
	}
	return ScopesObligation{Scopes: scopes}, true
}

// ExpiresInObligation is the typed representation of the "expires_in"
// obligation key returned by the policy engine in a PolicyResult for
// token:create.
type ExpiresInObligation struct {
	// Duration is the maximum lifetime of the token. A nil value means the
	// policy permits a non-expiring token (ObligationExpiresInNever).
	Duration *time.Duration
}

// ParseExpiresInObligation reads the "expires_in" key from the obligations map.
// Returns (obligation, true) when the key is present, (zero value, false) when
// the policy did not set an expires_in obligation. The sentinel "never" yields
// an obligation with a nil Duration.
func ParseExpiresInObligation(obligations map[string]string) (ExpiresInObligation, bool) {
	v, ok := obligations[ObligationKeyExpiresIn]
	if !ok {
		return ExpiresInObligation{}, false
	}
	if v == ObligationExpiresInNever {
		return ExpiresInObligation{Duration: nil}, true
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return ExpiresInObligation{}, false
	}
	return ExpiresInObligation{Duration: &d}, true
}

const (
	// ObligationKeySudo is the key the policy engine writes when expressing a
	// sudo obligation. The enforcer reads this key and applies the value to the
	// user record before completing onboarding or admin-driven creation.
	ObligationKeySudo = "sudo"

	// ObligationSudoTrue is the obligation value that grants sudo access.
	ObligationSudoTrue = "true"

	// ObligationSudoFalse is the obligation value that explicitly denies sudo access.
	ObligationSudoFalse = "false"
)

// SudoObligation is the typed representation of the "sudo" obligation key
// returned by the policy engine in a PolicyResult for user:onboard or
// user:create.
type SudoObligation struct {
	// Granted is true when the policy grants sudo access, false when it denies it.
	Granted bool
}

// ParseSudoObligation reads the "sudo" key from the obligations map.
// Returns (obligation, true) when the key is present, (zero value, false) when
// the policy did not set a sudo obligation — in that case the enforcer should
// preserve its existing default rather than overwriting it.
func ParseSudoObligation(obligations map[string]string) (SudoObligation, bool) {
	v, ok := obligations[ObligationKeySudo]
	if !ok {
		return SudoObligation{}, false
	}
	return SudoObligation{Granted: v == ObligationSudoTrue}, true
}

const (
	// ObligationKeyRoles is the key the policy engine writes to assign roles
	// during onboarding or admin-driven creation. The value is a JSON-encoded
	// array of role name strings.
	ObligationKeyRoles = "roles"
)

// RolesObligation is the typed representation of the "roles" obligation key
// returned by the policy engine in a PolicyResult for user:onboard or
// user:create.
type RolesObligation struct {
	// Roles is the list of roles the policy assigns to the user.
	Roles []models.Role
}

// ParseRolesObligation reads the "roles" key from the obligations map.
// Returns (obligation, true) when the key is present, (zero value, false) when
// the policy did not set a roles obligation — in that case the enforcer should
// preserve its existing default rather than overwriting it.
func ParseRolesObligation(obligations map[string]string) (RolesObligation, bool) {
	v, ok := obligations[ObligationKeyRoles]
	if !ok {
		return RolesObligation{}, false
	}
	var raw []string
	if err := json.Unmarshal([]byte(v), &raw); err != nil {
		return RolesObligation{}, false
	}
	roles := make([]models.Role, 0, len(raw))
	for _, r := range raw {
		if r != "" {
			roles = append(roles, models.Role(r))
		}
	}
	return RolesObligation{Roles: roles}, true
}

const (
	// ObligationKeyBlueprints is the key the policy engine writes to assign
	// allowed blueprints during onboarding or admin-driven creation. The value
	// is a comma-separated list of blueprint names; "*" grants access to all
	// blueprints.
	ObligationKeyBlueprints = "blueprints"
)

// BlueprintsObligation is the typed representation of the "blueprints"
// obligation key returned by the policy engine in a PolicyResult for
// user:onboard or user:create.
type BlueprintsObligation struct {
	// Blueprints is the list of blueprint names the policy assigns to the user.
	// An entry of "*" grants access to all blueprints.
	Blueprints []string
}

// ParseBlueprintsObligation reads the "blueprints" key from the obligations map.
// The value is a JSON-encoded array of blueprint name strings (e.g. ["bp1","bp2"]).
// Returns (obligation, true) when the key is present, (zero value, false) when
// the policy did not set a blueprints obligation — in that case the enforcer
// should preserve its existing default rather than overwriting it.
func ParseBlueprintsObligation(obligations map[string]string) (BlueprintsObligation, bool) {
	v, ok := obligations[ObligationKeyBlueprints]
	if !ok {
		return BlueprintsObligation{}, false
	}
	var raw []string
	if err := json.Unmarshal([]byte(v), &raw); err != nil {
		return BlueprintsObligation{}, false
	}
	blueprints := make([]string, 0, len(raw))
	for _, b := range raw {
		if b != "" {
			blueprints = append(blueprints, b)
		}
	}
	return BlueprintsObligation{Blueprints: blueprints}, true
}

const (
	// ObligationKeyOrg is the key the policy engine writes to scope a user:list
	// result to a single organization. The value is an organization name.
	ObligationKeyOrg = "org"
)

// OrgObligation is the typed representation of the "org" obligation key
// returned by the policy engine in a PolicyResult for user:list.
type OrgObligation struct {
	// Org is the organization the enforcer should restrict the listing to.
	Org string
}

// ParseOrgObligation reads the "org" key from the obligations map.
// Returns (obligation, true) when the key is present, (zero value, false) when
// the policy did not set an org obligation — in that case the enforcer should
// not scope the listing by organization.
func ParseOrgObligation(obligations map[string]string) (OrgObligation, bool) {
	v, ok := obligations[ObligationKeyOrg]
	if !ok || v == "" {
		return OrgObligation{}, false
	}
	return OrgObligation{Org: v}, true
}

// init registers a capability probe for every user/token domain action. See
// CapabilityCheck and registerCapabilityCheck in capability.go.
func init() {
	registerCapabilityCheck(CapabilityCheck{
		Action: "user:list", Package: "user", Scope: "user:list",
		Build: func(ctx CapabilityContext) (EvalRequest, error) {
			return NewUserListEvalRequest().Build()
		},
		SelfOnly: true,
	})
	registerCapabilityCheck(CapabilityCheck{
		Action: "user:onboard", Package: "user", Scope: "user:onboard",
		Build: func(ctx CapabilityContext) (EvalRequest, error) {
			return NewUserOnboardEvalRequest(ctx.ResourceOwner).WithIDP(ctx.IDP).WithOrg(ctx.Org).Build()
		},
		SelfOnly: true,
	})
	registerCapabilityCheck(CapabilityCheck{
		Action: "user:create", Package: "user", Scope: "user:create",
		Build: func(ctx CapabilityContext) (EvalRequest, error) {
			return NewUserCreateEvalRequest(ctx.ResourceOwner).WithOrg(ctx.Org).Build()
		},
	})
	registerCapabilityCheck(CapabilityCheck{
		Action: "user:delete", Package: "user", Scope: "user:delete",
		Build: func(ctx CapabilityContext) (EvalRequest, error) {
			return NewUserDeleteEvalRequest(ctx.ResourceOwner).WithOrg(ctx.Org).Build()
		},
	})
	registerCapabilityCheck(CapabilityCheck{
		// "user:auth" itself has no dedicated const (unlike WorkspaceAction/
		// SessionAction/SSHAction) — only the surface qualifier does.
		Action: "user:auth:" + string(AuthSurfaceWeb), Package: "user", Scope: "user:auth:" + string(AuthSurfaceWeb),
		Build: func(ctx CapabilityContext) (EvalRequest, error) {
			return NewUserAuthEvalRequest(ctx.ResourceOwner).WithIDP(ctx.IDP).WithOrg(ctx.Org).
				WithSurface(AuthSurfaceWeb).Build()
		},
		SelfOnly: true,
	})
	registerCapabilityCheck(CapabilityCheck{
		Action: "user:auth:" + string(AuthSurfaceSSH), Package: "user", Scope: "user:auth:" + string(AuthSurfaceSSH),
		Build: func(ctx CapabilityContext) (EvalRequest, error) {
			return NewUserAuthEvalRequest(ctx.ResourceOwner).WithIDP(ctx.IDP).WithOrg(ctx.Org).
				WithSurface(AuthSurfaceSSH).Build()
		},
		SelfOnly: true,
	})
	registerCapabilityCheck(CapabilityCheck{
		Action: "token:create", Package: "user", Scope: "token:create",
		Build: func(ctx CapabilityContext) (EvalRequest, error) {
			return NewUserTokenCreateEvalRequest(ctx.ResourceOwner).WithSource(TokenCreateSourceAPI).Build()
		},
	})
	registerCapabilityCheck(CapabilityCheck{
		Action: "token:read", Package: "user", Scope: "token:read",
		Build: func(ctx CapabilityContext) (EvalRequest, error) {
			return NewUserTokenReadEvalRequest(ctx.ResourceOwner).Build()
		},
	})

	for _, dt := range []UserDataType{
		UserDataTypeProfile, UserDataTypeCredentials, UserDataTypeBlueprints, UserDataTypeRoles, UserDataTypeKeys,
	} {
		action := "user:read:" + string(dt)
		registerCapabilityCheck(CapabilityCheck{
			Action: action, Package: "user", Scope: action,
			Build: func(ctx CapabilityContext) (EvalRequest, error) {
				return NewUserReadEvalRequest(ctx.ResourceOwner).WithDataType(dt).Build()
			},
		})
	}

	for _, dt := range []UserDataType{
		UserDataTypeProfile, UserDataTypeCredentials, UserDataTypeBlueprints, UserDataTypeRoles, UserDataTypeKeys,
		UserDataTypeSudo, UserDataTypeLocked, UserDataTypeOrg, UserDataTypePosix, UserDataTypePassword,
	} {
		action := "user:write:" + string(dt)
		registerCapabilityCheck(CapabilityCheck{
			Action: action, Package: "user", Scope: action,
			Build: func(ctx CapabilityContext) (EvalRequest, error) {
				return NewUserWriteEvalRequest(ctx.ResourceOwner).WithDataType(dt).Build()
			},
		})
	}
}
