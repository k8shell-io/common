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
//   blueprints comma-separated blueprint names or "*" for all
//
// Subject   injected by the backend from JWT claims (username, roles, email, ...)
//
// ---
//
// Contract: user:preonboard
//
// Resource  type="user"
//   id   username               (required)
//   idp  identity provider name (required)
//
// Context
//   flow  device | web           (required)
//
// Subject   injected by the backend from ephemeral JWT (only username, source (idp))
//
// Obligations  (none) — allow/deny only
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

import (
	"encoding/json"
	"fmt"
	"strings"

	authzv1 "github.com/k8shell-io/common/pkg/api/gen/go/authz/v1"
	"github.com/k8shell-io/common/pkg/models"
)

// UserPreonboardFlow is the typed representation of the onboarding flow kind.
type UserPreonboardFlow string

const (
	UserPreonboardFlowDevice UserPreonboardFlow = "device"
	UserPreonboardFlowWeb    UserPreonboardFlow = "web"
)

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

// UserPreonboardContext holds the ambient context attributes for user:preonboard.
type UserPreonboardContext struct {
	// Flow is the onboarding flow kind ("device" or "web").
	Flow UserPreonboardFlow
}

// UserPreonboardEvalRequest is the validated, typed model for user:preonboard
// policy evaluation. Use NewUserPreonboardEvalRequest to start building, then
// chain WithIDP / WithFlow and call Build to get a validated instance.
type UserPreonboardEvalRequest struct {
	Resource UserResource
	Context  UserPreonboardContext
}

var _ EvalRequest = (*UserPreonboardEvalRequest)(nil)

// NewUserPreonboardEvalRequest begins building a UserPreonboardEvalRequest for
// the given username.
func NewUserPreonboardEvalRequest(username string) *UserPreonboardEvalRequest {
	return &UserPreonboardEvalRequest{
		Resource: UserResource{ID: username},
	}
}

// WithIDP sets the identity provider name on the resource.
func (r *UserPreonboardEvalRequest) WithIDP(idp string) *UserPreonboardEvalRequest {
	r.Resource.IDP = idp
	return r
}

// WithFlow sets the onboarding flow kind on the context.
func (r *UserPreonboardEvalRequest) WithFlow(flow UserPreonboardFlow) *UserPreonboardEvalRequest {
	r.Context.Flow = flow
	return r
}

// Build validates the request and returns it if all constraints are satisfied.
// It is the required terminator for the builder chain.
func (r *UserPreonboardEvalRequest) Build() (*UserPreonboardEvalRequest, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// ToProto serializes the typed request into a gRPC EvaluateRequest. The token
// is empty because the subject does not yet exist in the system.
// Implements EvalRequest.
func (r *UserPreonboardEvalRequest) ToProto(token string) *authzv1.EvaluateRequest {
	return &authzv1.EvaluateRequest{
		Token:  token,
		Action: "user:preonboard",
		Resource: &authzv1.Resource{
			Type:       "user",
			Id:         r.Resource.ID,
			Attributes: userResourceToAttrs(r.Resource),
		},
		Context: map[string]string{
			"flow": string(r.Context.Flow),
		},
	}
}

// UserPreonboardEvalRequestFromProto converts a gRPC EvaluateRequest into a
// validated UserPreonboardEvalRequest. Returns an error if the request does not
// conform to the user:preonboard contract.
func UserPreonboardEvalRequestFromProto(req *authzv1.EvaluateRequest) (*UserPreonboardEvalRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("user:preonboard: EvaluateRequest is nil")
	}
	if req.Action != "user:preonboard" {
		return nil, fmt.Errorf("user:preonboard: action must be \"user:preonboard\", got %q", req.Action)
	}
	if req.Resource == nil {
		return nil, fmt.Errorf("user:preonboard: resource is nil")
	}
	if req.Resource.Type != "user" {
		return nil, fmt.Errorf("user:preonboard: resource type must be \"user\", got %q", req.Resource.Type)
	}
	r := &UserPreonboardEvalRequest{
		Resource: userResourceFromAttrs(req.Resource.Id, req.Resource.Attributes),
		Context:  UserPreonboardContext{Flow: UserPreonboardFlow(req.Context["flow"])},
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Validate checks the request against the user:preonboard contract.
// Implements EvalRequest.
func (r *UserPreonboardEvalRequest) Validate() error {
	if err := validateUserResource(r.Resource); err != nil {
		return err
	}
	switch r.Context.Flow {
	case UserPreonboardFlowDevice, UserPreonboardFlowWeb:
	default:
		return fmt.Errorf("user:preonboard: context \"flow\" must be %q or %q, got %q",
			UserPreonboardFlowDevice, UserPreonboardFlowWeb, r.Context.Flow)
	}
	return nil
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
// Returns (obligation, true) when the key is present, (zero value, false) when
// the policy did not set a blueprints obligation — in that case the enforcer
// should preserve its existing default rather than overwriting it.
func ParseBlueprintsObligation(obligations map[string]string) (BlueprintsObligation, bool) {
	v, ok := obligations[ObligationKeyBlueprints]
	if !ok {
		return BlueprintsObligation{}, false
	}
	var blueprints []string
	for b := range strings.SplitSeq(v, ",") {
		if b = strings.TrimSpace(b); b != "" {
			blueprints = append(blueprints, b)
		}
	}
	return BlueprintsObligation{Blueprints: blueprints}, true
}
