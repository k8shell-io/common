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
// Contract: user:auth
//
// Resource  type="user"
//   id   username               (required)
//   idp  identity provider name (required)
//   org  organization name      (optional)
//
// Context
//   method       publickey | password          (required)
//   fingerprint  SHA256 public key fingerprint (required for publickey)
//
// Subject   injected by the backend from JWT claims (username, roles, email, ...)
//
// Obligations  (none)
//
// ---
//
// Contract: user:read
//
// Resource  type="user"
//   id         username               (required) — the user whose data is being read
//   idp        identity provider name (required)
//   org        organization name      (optional)
//   email      user's email address   (required)
//   fullname   user's full name       (required)
//   uid        POSIX uid              (required)
//   gid        POSIX gid              (required)
//   roles      JSON array of role name strings currently assigned  (required, non-empty)
//   sudo       true | false — whether the user currently has sudo (required)
//   blueprints JSON array of blueprint names currently granted     (required, non-empty)
//
// Context
//   data_type  profile | credentials | blueprints | roles  (required)
//              profile returns the full profile view, including the sudo and
//              locked flags — those are not broken out into their own
//              data_type for reads, only for writes (see user:write below).
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
// Obligations  (none) — allow/deny only
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
//   id         username               (required) — the user record being mutated
//   idp        identity provider name (required)
//   org        organization name      (optional)
//   email      user's email address   (required)
//   fullname   user's full name       (required)
//   uid        POSIX uid              (required)
//   gid        POSIX gid              (required)
//   roles      JSON array of role name strings currently assigned  (required, non-empty)
//   sudo       true | false — whether the user currently has sudo (required)
//   blueprints JSON array of blueprint names currently granted     (required, non-empty)
//
// Context
//   data_type  profile | credentials | blueprints | roles | sudo | locked | org | posix  (required)
//              profile     — self-editable identity fields (e.g. fullname,
//                            shell, email); subject may write its own record.
//              credentials — auth credentials.
//              blueprints  — blueprint access grants.
//              roles       — role assignments.
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
	"strconv"
	"time"

	authzv1 "github.com/k8shell-io/common/pkg/api/gen/go/authz/v1"
	"github.com/k8shell-io/common/pkg/models"
)

// UserDataType identifies which slice of user data is being accessed in
// user:read and user:write. UserDataTypeSudo, UserDataTypeLocked,
// UserDataTypeOrg, and UserDataTypePosix are write-only values: user:read
// never selects them individually, since UserDataTypeProfile already returns
// the full profile view including sudo, locked, org, and uid/gid.
type UserDataType string

const (
	UserDataTypeProfile     UserDataType = "profile"
	UserDataTypeCredentials UserDataType = "credentials"
	UserDataTypeBlueprints  UserDataType = "blueprints"
	UserDataTypeRoles       UserDataType = "roles"
	UserDataTypeSudo        UserDataType = "sudo"
	UserDataTypeLocked      UserDataType = "locked"
	UserDataTypeOrg         UserDataType = "org"
	UserDataTypePosix       UserDataType = "posix"
)

// validateUserDataType checks the data types valid for user:read.
func validateUserDataType(dt UserDataType) error {
	switch dt {
	case UserDataTypeProfile, UserDataTypeCredentials, UserDataTypeBlueprints, UserDataTypeRoles:
		return nil
	default:
		return fmt.Errorf("context \"data_type\" must be %q, %q, %q, or %q, got %q",
			UserDataTypeProfile, UserDataTypeCredentials, UserDataTypeBlueprints, UserDataTypeRoles, dt)
	}
}

// validateUserWriteDataType checks the data types valid for user:write, which
// additionally includes the admin-managed sudo, locked, org, and posix groups.
func validateUserWriteDataType(dt UserDataType) error {
	switch dt {
	case UserDataTypeProfile, UserDataTypeCredentials, UserDataTypeBlueprints, UserDataTypeRoles, UserDataTypeSudo, UserDataTypeLocked, UserDataTypeOrg, UserDataTypePosix:
		return nil
	default:
		return fmt.Errorf("context \"data_type\" must be %q, %q, %q, %q, %q, %q, %q, or %q, got %q",
			UserDataTypeProfile, UserDataTypeCredentials, UserDataTypeBlueprints, UserDataTypeRoles,
			UserDataTypeSudo, UserDataTypeLocked, UserDataTypeOrg, UserDataTypePosix, dt)
	}
}

// UserAuthMethod is the typed representation of an SSH authentication method.
type UserAuthMethod string

const (
	UserAuthMethodPublicKey UserAuthMethod = "publickey"
	UserAuthMethodPassword  UserAuthMethod = "password"
)

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

// UserIdentityResource extends UserResource with the rest of the target
// user's identity snapshot — the fields a policy needs to condition on who
// the target user is (email, fullname, uid/gid) and their current standing
// (roles, sudo, blueprints), not just their username/idp/org. Used by
// user:read and user:write, where the acting subject and the user record
// being read or mutated are two different people.
type UserIdentityResource struct {
	UserResource

	// Email is the user's email address (resource.attributes["email"]).
	Email string

	// Fullname is the user's full name (resource.attributes["fullname"]).
	Fullname string

	// UID is the POSIX user-id (resource.attributes["uid"]).
	UID uint32

	// GID is the POSIX primary group-id (resource.attributes["gid"]).
	GID uint32

	// Roles lists the roles currently assigned to the user
	// (resource.attributes["roles"], JSON-encoded array).
	Roles []models.Role

	// Sudo indicates whether the user currently has sudo privileges
	// (resource.attributes["sudo"]).
	Sudo bool

	// Blueprints lists the blueprint names the user currently has access to
	// (resource.attributes["blueprints"], JSON-encoded array).
	Blueprints []string
}

func userIdentityResourceToAttrs(r UserIdentityResource) map[string]string {
	attrs := userResourceToAttrs(r.UserResource)
	attrs["email"] = r.Email
	attrs["fullname"] = r.Fullname
	attrs["uid"] = strconv.FormatUint(uint64(r.UID), 10)
	attrs["gid"] = strconv.FormatUint(uint64(r.GID), 10)
	if b, err := json.Marshal(r.Roles); err == nil {
		attrs["roles"] = string(b)
	}
	attrs["sudo"] = strconv.FormatBool(r.Sudo)
	if b, err := json.Marshal(r.Blueprints); err == nil {
		attrs["blueprints"] = string(b)
	}
	return attrs
}

func userIdentityResourceFromAttrs(id string, attrs map[string]string) UserIdentityResource {
	r := UserIdentityResource{
		UserResource: userResourceFromAttrs(id, attrs),
		Email:        attrs["email"],
		Fullname:     attrs["fullname"],
		Sudo:         attrs["sudo"] == "true",
	}
	if v, err := strconv.ParseUint(attrs["uid"], 10, 32); err == nil {
		r.UID = uint32(v)
	}
	if v, err := strconv.ParseUint(attrs["gid"], 10, 32); err == nil {
		r.GID = uint32(v)
	}
	if v, ok := attrs["roles"]; ok {
		var roles []models.Role
		if err := json.Unmarshal([]byte(v), &roles); err == nil {
			r.Roles = roles
		}
	}
	if v, ok := attrs["blueprints"]; ok {
		var bps []string
		if err := json.Unmarshal([]byte(v), &bps); err == nil {
			r.Blueprints = bps
		}
	}
	return r
}

// validateUserIdentityResource checks the request against the user:read and
// user:write contracts: id and idp (via validateUserResource) plus the full
// identity snapshot — email, fullname, uid, gid, roles, and blueprints — are
// all required. Sudo has no missing-value check since both true and false
// are valid, meaningful states.
func validateUserIdentityResource(r UserIdentityResource) error {
	if err := validateUserResource(r.UserResource); err != nil {
		return err
	}
	if r.Email == "" {
		return fmt.Errorf("user: resource attribute \"email\" is required")
	}
	if r.Fullname == "" {
		return fmt.Errorf("user: resource attribute \"fullname\" is required")
	}
	if r.UID == 0 {
		return fmt.Errorf("user: resource attribute \"uid\" is required")
	}
	if r.GID == 0 {
		return fmt.Errorf("user: resource attribute \"gid\" is required")
	}
	if len(r.Roles) == 0 {
		return fmt.Errorf("user: resource attribute \"roles\" is required")
	}
	if len(r.Blueprints) == 0 {
		return fmt.Errorf("user: resource attribute \"blueprints\" is required")
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

// UserAuthEvalRequest is the validated, typed model for user:auth policy
// evaluation. Use NewUserAuthEvalRequest to start building, then chain With*
// methods and call Build to get a validated instance.
type UserAuthEvalRequest struct {
	Resource UserResource
	Context  UserAuthContext
}

// UserAuthContext holds the ambient authentication attributes for user:auth.
type UserAuthContext struct {
	// Method is the SSH authentication method ("publickey" or "password").
	Method UserAuthMethod

	// Fingerprint is the SHA256 public key fingerprint; set only when
	// Method is UserAuthMethodPublicKey (context["fingerprint"]).
	Fingerprint string
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

// WithAuthMethod sets the authentication method.
func (r *UserAuthEvalRequest) WithAuthMethod(method UserAuthMethod) *UserAuthEvalRequest {
	r.Context.Method = method
	return r
}

// WithFingerprint sets the public key fingerprint; required for publickey auth.
func (r *UserAuthEvalRequest) WithFingerprint(fp string) *UserAuthEvalRequest {
	r.Context.Fingerprint = fp
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
	ctx := map[string]string{
		"method": string(r.Context.Method),
	}
	if r.Context.Fingerprint != "" {
		ctx["fingerprint"] = r.Context.Fingerprint
	}
	return &authzv1.EvaluateRequest{
		Token:  token,
		Action: "user:auth",
		Resource: &authzv1.Resource{
			Type:       "user",
			Id:         r.Resource.ID,
			Attributes: userResourceToAttrs(r.Resource),
		},
		Context: ctx,
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
	ctx := req.Context
	r := &UserAuthEvalRequest{
		Resource: userResourceFromAttrs(req.Resource.Id, req.Resource.Attributes),
		Context: UserAuthContext{
			Method:      UserAuthMethod(ctx["method"]),
			Fingerprint: ctx["fingerprint"],
		},
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Validate checks the request against the user:auth contract: ID and IDP are
// required, method must be set, and publickey auth requires a fingerprint.
// Implements EvalRequest.
func (r *UserAuthEvalRequest) Validate() error {
	if err := validateUserResource(r.Resource); err != nil {
		return err
	}
	switch r.Context.Method {
	case UserAuthMethodPublicKey:
		if r.Context.Fingerprint == "" {
			return fmt.Errorf("user:auth: context \"fingerprint\" is required for publickey auth")
		}
	case UserAuthMethodPassword:
		// no additional fields required
	default:
		return fmt.Errorf("user:auth: context \"method\" must be %q or %q, got %q",
			UserAuthMethodPublicKey, UserAuthMethodPassword, r.Context.Method)
	}
	return nil
}

// UserReadEvalRequest is the validated, typed model for user:read policy
// evaluation. Use NewUserReadEvalRequest to start building, then call Build
// to get a validated instance.
type UserReadEvalRequest struct {
	Resource UserIdentityResource
	DataType UserDataType
}

var _ EvalRequest = (*UserReadEvalRequest)(nil)

// NewUserReadEvalRequest begins building a UserReadEvalRequest for the given
// target username.
func NewUserReadEvalRequest(username string) *UserReadEvalRequest {
	return &UserReadEvalRequest{Resource: UserIdentityResource{UserResource: UserResource{ID: username}}}
}

// WithDataType sets the data type being accessed.
func (r *UserReadEvalRequest) WithDataType(dt UserDataType) *UserReadEvalRequest {
	r.DataType = dt
	return r
}

// WithIDP sets the identity provider name on the resource.
func (r *UserReadEvalRequest) WithIDP(idp string) *UserReadEvalRequest {
	r.Resource.IDP = idp
	return r
}

// WithOrg sets the organization on the resource.
func (r *UserReadEvalRequest) WithOrg(org string) *UserReadEvalRequest {
	r.Resource.Org = org
	return r
}

// WithEmail sets the target user's email address on the resource.
func (r *UserReadEvalRequest) WithEmail(email string) *UserReadEvalRequest {
	r.Resource.Email = email
	return r
}

// WithFullname sets the target user's full name on the resource.
func (r *UserReadEvalRequest) WithFullname(fullname string) *UserReadEvalRequest {
	r.Resource.Fullname = fullname
	return r
}

// WithUID sets the target user's POSIX uid on the resource.
func (r *UserReadEvalRequest) WithUID(uid uint32) *UserReadEvalRequest {
	r.Resource.UID = uid
	return r
}

// WithGID sets the target user's POSIX gid on the resource.
func (r *UserReadEvalRequest) WithGID(gid uint32) *UserReadEvalRequest {
	r.Resource.GID = gid
	return r
}

// WithRoles sets the target user's currently assigned roles on the resource.
func (r *UserReadEvalRequest) WithRoles(roles []models.Role) *UserReadEvalRequest {
	r.Resource.Roles = roles
	return r
}

// WithSudo sets whether the target user currently has sudo privileges.
func (r *UserReadEvalRequest) WithSudo(sudo bool) *UserReadEvalRequest {
	r.Resource.Sudo = sudo
	return r
}

// WithBlueprints sets the target user's currently granted blueprints on the resource.
func (r *UserReadEvalRequest) WithBlueprints(blueprints []string) *UserReadEvalRequest {
	r.Resource.Blueprints = blueprints
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
			Type:       "user",
			Id:         r.Resource.ID,
			Attributes: userIdentityResourceToAttrs(r.Resource),
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
		Resource: userIdentityResourceFromAttrs(req.Resource.Id, req.Resource.Attributes),
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
	if err := validateUserIdentityResource(r.Resource); err != nil {
		return err
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
	Resource UserIdentityResource
	DataType UserDataType
}

var _ EvalRequest = (*UserWriteEvalRequest)(nil)

// NewUserWriteEvalRequest begins building a UserWriteEvalRequest for the given
// target username. Call WithDataType then Build to validate and obtain the
// final struct.
func NewUserWriteEvalRequest(username string) *UserWriteEvalRequest {
	return &UserWriteEvalRequest{Resource: UserIdentityResource{UserResource: UserResource{ID: username}}}
}

// WithDataType sets the data type being mutated.
func (r *UserWriteEvalRequest) WithDataType(dt UserDataType) *UserWriteEvalRequest {
	r.DataType = dt
	return r
}

// WithIDP sets the identity provider name on the resource.
func (r *UserWriteEvalRequest) WithIDP(idp string) *UserWriteEvalRequest {
	r.Resource.IDP = idp
	return r
}

// WithOrg sets the organization on the resource.
func (r *UserWriteEvalRequest) WithOrg(org string) *UserWriteEvalRequest {
	r.Resource.Org = org
	return r
}

// WithEmail sets the target user's email address on the resource.
func (r *UserWriteEvalRequest) WithEmail(email string) *UserWriteEvalRequest {
	r.Resource.Email = email
	return r
}

// WithFullname sets the target user's full name on the resource.
func (r *UserWriteEvalRequest) WithFullname(fullname string) *UserWriteEvalRequest {
	r.Resource.Fullname = fullname
	return r
}

// WithUID sets the target user's POSIX uid on the resource.
func (r *UserWriteEvalRequest) WithUID(uid uint32) *UserWriteEvalRequest {
	r.Resource.UID = uid
	return r
}

// WithGID sets the target user's POSIX gid on the resource.
func (r *UserWriteEvalRequest) WithGID(gid uint32) *UserWriteEvalRequest {
	r.Resource.GID = gid
	return r
}

// WithRoles sets the target user's currently assigned roles on the resource.
func (r *UserWriteEvalRequest) WithRoles(roles []models.Role) *UserWriteEvalRequest {
	r.Resource.Roles = roles
	return r
}

// WithSudo sets whether the target user currently has sudo privileges.
func (r *UserWriteEvalRequest) WithSudo(sudo bool) *UserWriteEvalRequest {
	r.Resource.Sudo = sudo
	return r
}

// WithBlueprints sets the target user's currently granted blueprints on the resource.
func (r *UserWriteEvalRequest) WithBlueprints(blueprints []string) *UserWriteEvalRequest {
	r.Resource.Blueprints = blueprints
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
			Type:       "user",
			Id:         r.Resource.ID,
			Attributes: userIdentityResourceToAttrs(r.Resource),
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
		Resource: userIdentityResourceFromAttrs(req.Resource.Id, req.Resource.Attributes),
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
	if err := validateUserIdentityResource(r.Resource); err != nil {
		return err
	}
	if err := validateUserWriteDataType(r.DataType); err != nil {
		return fmt.Errorf("user:write: %w", err)
	}
	return nil
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
	// user record before completing onboarding.
	ObligationKeySudo = "sudo"

	// ObligationSudoTrue is the obligation value that grants sudo access.
	ObligationSudoTrue = "true"

	// ObligationSudoFalse is the obligation value that explicitly denies sudo access.
	ObligationSudoFalse = "false"
)

// SudoObligation is the typed representation of the "sudo" obligation key
// returned by the policy engine in a PolicyResult for user:onboard.
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
	// during onboarding. The value is a JSON-encoded array of role name strings.
	ObligationKeyRoles = "roles"
)

// RolesObligation is the typed representation of the "roles" obligation key
// returned by the policy engine in a PolicyResult for user:onboard.
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
	// allowed blueprints during onboarding. The value is a comma-separated
	// list of blueprint names; "*" grants access to all blueprints.
	ObligationKeyBlueprints = "blueprints"
)

// BlueprintsObligation is the typed representation of the "blueprints"
// obligation key returned by the policy engine in a PolicyResult for
// user:onboard.
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
