// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package authz

// Contract: workspace:provision
//
// Resource  type="workspace"
//   id         workspace name            (required)
//   owner      provisioning username     (required)
//   blueprint  blueprint name            (optional)
//
// Context
//   blueprint          YAML-encoded blueprint struct       (required)
//   mode               standalone | inject                 (required)
//   workload_name      target workload name                (required for inject)
//   workload_namespace target workload namespace           (required for inject)
//   workload_kind      target workload kind                (required for inject)
//
// Subject   injected by the backend from JWT claims (username, roles, email, ...)
//
// Obligations
//   patch:<json-pointer>  string value to write at that path in the blueprint
//
// ---
//
// Contract: workspace:list
//
// Resource  type="workspace"
//   id     (empty — no specific workspace)
//   owner  owner username  (required)
//
// Context   (none)
//
// Subject   injected by the backend from JWT claims (username, roles, email, ...)
//
// Obligations  (none) — allow/deny only
//
// ---
//
// Contract: workspace:create
//
// Resource  type="workspace"
//   id     (empty — no specific workspace yet)
//   owner  owner username  (required)
//
// Context   (none)
//
// Subject   injected by the backend from JWT claims (username, roles, email, ...)
//
// Obligations  (none) — allow/deny only
//
// ---
//
// Contract: workspace:read
//
// Resource  type="workspace"
//   id     workspace name (required)
//   owner  owner username (required)
//
// Context   (none)
//
// Subject   injected by the backend from JWT claims (username, roles, email, ...)
//
// Obligations  (none) — allow/deny only
//
// ---
//
// Contract: workspace:delete
//
// Resource  type="workspace"
//   id     workspace name (required)
//   owner  owner username (required)
//
// Context   (none)
//
// Subject   injected by the backend from JWT claims (username, roles, email, ...)
//
// Obligations  (none) — allow/deny only
//
// ---
//
// Contract: workspace:connect
//
// Resource  type="workspace"
//   id     workspace name (required)
//   owner  owner username (required)
//
// Context
//   type  webshell | webfiles | portforward  (required)
//   port  port number as string              (required for portforward)
//
// Subject   injected by the backend from JWT claims (username, roles, email, ...)
//
// Obligations  (none) — allow/deny only
//
// ---
//
// Contract: workspace:files
//
// Resource  type="workspace"
//   id     workspace name (required)
//   owner  owner username (required)
//
// Context
//   op  download | upload  (required)
//
// Subject   injected by the backend from JWT claims (username, roles, email, ...)
//
// Obligations  (none) — allow/deny only
//
// ---
//
// Contract: workspace:app
//
// Resource  type="workspace"
//   id     workspace name (required)
//   owner  owner username (required)
//   app    app name       (required)
//
// Context
//   op  install | start | stop  (required)
//
// Subject   injected by the backend from JWT claims (username, roles, email, ...)
//
// Obligations  (none) — allow/deny only

import (
	"fmt"
	"strings"

	authzv1 "github.com/k8shell-io/common/pkg/api/gen/go/authz/v1"
	"github.com/k8shell-io/common/pkg/models"
	"gopkg.in/yaml.v3"
)

// WorkspaceAction is the typed representation of a workspace policy action.
type WorkspaceAction string

const (
	// WorkspaceActionProvision is the action evaluated before a workspace is
	// provisioned. The full blueprint is carried in context["blueprint"] as a
	// YAML string. The policy result may carry patch obligations (keys prefixed
	// with ObligationKeyPatchPrefix) that the enforcer must apply to the
	// blueprint before provisioning proceeds.
	WorkspaceActionProvision WorkspaceAction = "workspace:provision"

	WorkspaceActionList    WorkspaceAction = "workspace:list"
	WorkspaceActionCreate  WorkspaceAction = "workspace:create"
	WorkspaceActionRead    WorkspaceAction = "workspace:read"
	WorkspaceActionDelete  WorkspaceAction = "workspace:delete"
	WorkspaceActionConnect WorkspaceAction = "workspace:connect"
	WorkspaceActionFiles   WorkspaceAction = "workspace:files"
	WorkspaceActionApp     WorkspaceAction = "workspace:app"
)

// validWorkspaceProvisionActions is the set of recognized workspace:provision actions.
var validWorkspaceProvisionActions = map[WorkspaceAction]struct{}{
	WorkspaceActionProvision: {},
}

// WorkspaceProvisionMode controls how the workspace is attached to its runtime.
type WorkspaceProvisionMode string

const (
	// WorkspaceProvisionModeStandalone creates a new independent workspace pod.
	WorkspaceProvisionModeStandalone WorkspaceProvisionMode = "standalone"

	// WorkspaceProvisionModeInject injects the workspace into an existing
	// workload. WorkloadName, WorkloadNamespace, and WorkloadKind are required.
	WorkspaceProvisionModeInject WorkspaceProvisionMode = "inject"
)

// validWorkspaceProvisionModes is the set of recognized provision modes.
var validWorkspaceProvisionModes = map[WorkspaceProvisionMode]struct{}{
	WorkspaceProvisionModeStandalone: {},
	WorkspaceProvisionModeInject:     {},
}

// WorkspaceResource holds the resource-scoped attributes for a workspace policy check.
type WorkspaceResource struct {
	// ID is the workspace name (resource.id in the EvaluateRequest).
	ID string

	// Owner is the username of the user provisioning the workspace
	// (resource.attributes["owner"]).
	Owner string

	// Blueprint is the blueprint name (resource.attributes["blueprint"]).
	Blueprint string
}

// WorkspaceProvisionContext holds the full blueprint being provisioned and the
// provisioning mode. The enforcer must apply any ProvisionPatch obligations to
// Blueprint before provisioning proceeds.
type WorkspaceProvisionContext struct {
	Blueprint         *models.Blueprint
	Mode              WorkspaceProvisionMode
	WorkloadName      string
	WorkloadNamespace string
	WorkloadKind      string
}

// WorkspaceEvalRequest is the validated, typed model for workspace policy
// evaluation. Use NewWorkspaceEvalRequest to start building, then chain With*
// methods and call Build to get a validated instance. Use
// WorkspaceEvalRequestFromProto to convert directly from a gRPC EvaluateRequest.
type WorkspaceEvalRequest struct {
	Action   WorkspaceAction
	Resource WorkspaceResource
	Context  WorkspaceProvisionContext
}

var _ EvalRequest = (*WorkspaceEvalRequest)(nil)

// NewWorkspaceEvalRequest begins building a WorkspaceEvalRequest for the given
// action and workspace ID. Chain With* methods to supply additional fields,
// then call Build to validate and obtain the final struct.
func NewWorkspaceEvalRequest(action WorkspaceAction, workspaceID string) *WorkspaceEvalRequest {
	return &WorkspaceEvalRequest{
		Action:   action,
		Resource: WorkspaceResource{ID: workspaceID},
	}
}

// WithOwner sets the username of the user provisioning the workspace.
func (r *WorkspaceEvalRequest) WithOwner(owner string) *WorkspaceEvalRequest {
	r.Resource.Owner = owner
	return r
}

// WithBlueprintName sets the blueprint name on the resource attributes.
func (r *WorkspaceEvalRequest) WithBlueprintName(name string) *WorkspaceEvalRequest {
	r.Resource.Blueprint = name
	return r
}

// WithBlueprint sets the full blueprint struct in the provision context;
// required for WorkspaceActionProvision.
func (r *WorkspaceEvalRequest) WithBlueprint(bp *models.Blueprint) *WorkspaceEvalRequest {
	r.Context.Blueprint = bp
	return r
}

// WithMode sets the provisioning mode; required for WorkspaceActionProvision.
func (r *WorkspaceEvalRequest) WithMode(mode WorkspaceProvisionMode) *WorkspaceEvalRequest {
	r.Context.Mode = mode
	return r
}

// WithWorkload sets the target workload fields; required when mode is
// WorkspaceProvisionModeInject.
func (r *WorkspaceEvalRequest) WithWorkload(name, namespace, kind string) *WorkspaceEvalRequest {
	r.Context.WorkloadName = name
	r.Context.WorkloadNamespace = namespace
	r.Context.WorkloadKind = kind
	return r
}

// Build validates the request and returns it if all constraints are satisfied.
// It is the required terminator for the builder chain.
func (r *WorkspaceEvalRequest) Build() (*WorkspaceEvalRequest, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// ToProto serializes the typed request into a gRPC EvaluateRequest, attaching
// the supplied JWT token. The blueprint is marshaled to YAML and carried in
// context["blueprint"].
// Implements EvalRequest.
func (r *WorkspaceEvalRequest) ToProto(token string) *authzv1.EvaluateRequest {
	attrs := map[string]string{
		"owner": r.Resource.Owner,
	}
	if r.Resource.Blueprint != "" {
		attrs["blueprint"] = r.Resource.Blueprint
	}

	ctx := map[string]string{}
	if r.Context.Blueprint != nil {
		if data, err := yaml.Marshal(r.Context.Blueprint); err == nil {
			ctx["blueprint"] = string(data)
		}
	}
	if r.Context.Mode != "" {
		ctx["mode"] = string(r.Context.Mode)
	}
	if r.Context.WorkloadName != "" {
		ctx["workload_name"] = r.Context.WorkloadName
	}
	if r.Context.WorkloadNamespace != "" {
		ctx["workload_namespace"] = r.Context.WorkloadNamespace
	}
	if r.Context.WorkloadKind != "" {
		ctx["workload_kind"] = r.Context.WorkloadKind
	}

	return &authzv1.EvaluateRequest{
		Token:  token,
		Action: string(r.Action),
		Resource: &authzv1.Resource{
			Type:       "workspace",
			Id:         r.Resource.ID,
			Attributes: attrs,
		},
		Context: ctx,
	}
}

// WorkspaceEvalRequestFromProto converts a gRPC EvaluateRequest into a
// validated WorkspaceEvalRequest. Returns an error if the request does not
// conform to the workspace policy contract.
func WorkspaceEvalRequestFromProto(req *authzv1.EvaluateRequest) (*WorkspaceEvalRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("workspace: EvaluateRequest is nil")
	}
	if req.Resource == nil {
		return nil, fmt.Errorf("workspace: resource is nil")
	}
	if req.Resource.Type != "workspace" {
		return nil, fmt.Errorf("workspace: resource type must be \"workspace\", got %q", req.Resource.Type)
	}

	attrs := req.Resource.Attributes
	ctx := req.Context

	r := &WorkspaceEvalRequest{
		Action: WorkspaceAction(req.Action),
		Resource: WorkspaceResource{
			ID:        req.Resource.Id,
			Owner:     attrs["owner"],
			Blueprint: attrs["blueprint"],
		},
	}

	if raw, ok := ctx["blueprint"]; ok {
		var bp models.Blueprint
		if err := yaml.Unmarshal([]byte(raw), &bp); err != nil {
			return nil, fmt.Errorf("workspace: failed to decode blueprint context: %w", err)
		}
		r.Context.Blueprint = &bp
	}
	r.Context.Mode = WorkspaceProvisionMode(ctx["mode"])
	r.Context.WorkloadName = ctx["workload_name"]
	r.Context.WorkloadNamespace = ctx["workload_namespace"]
	r.Context.WorkloadKind = ctx["workload_kind"]

	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Validate checks the request against the workspace policy contract: the
// action must be recognized, and resource ID, owner, and blueprint context are
// all required for workspace:provision.
// Implements EvalRequest.
func (r *WorkspaceEvalRequest) Validate() error {
	if _, ok := validWorkspaceProvisionActions[r.Action]; !ok {
		return fmt.Errorf("workspace: unknown action %q", r.Action)
	}
	if r.Resource.ID == "" {
		return fmt.Errorf("workspace: resource ID (workspace name) is required")
	}
	if r.Resource.Owner == "" {
		return fmt.Errorf("workspace: resource attribute \"owner\" is required")
	}
	if r.Context.Blueprint == nil {
		return fmt.Errorf("workspace: provision context blueprint is required")
	}
	if _, ok := validWorkspaceProvisionModes[r.Context.Mode]; !ok {
		return fmt.Errorf("workspace: context \"mode\" must be %q or %q, got %q",
			WorkspaceProvisionModeStandalone, WorkspaceProvisionModeInject, r.Context.Mode)
	}
	if r.Context.Mode == WorkspaceProvisionModeInject {
		if r.Context.WorkloadName == "" {
			return fmt.Errorf("workspace: context \"workload_name\" is required for inject mode")
		}
		if r.Context.WorkloadNamespace == "" {
			return fmt.Errorf("workspace: context \"workload_namespace\" is required for inject mode")
		}
		if r.Context.WorkloadKind == "" {
			return fmt.Errorf("workspace: context \"workload_kind\" is required for inject mode")
		}
	}
	return nil
}

// WorkspaceConnectType is the kind of interactive session for workspace:connect.
type WorkspaceConnectType string

const (
	WorkspaceConnectTypeWebshell    WorkspaceConnectType = "webshell"
	WorkspaceConnectTypeWebfiles    WorkspaceConnectType = "webfiles"
	WorkspaceConnectTypePortForward WorkspaceConnectType = "portforward"
)

// WorkspaceFilesOp is the direction of file transfer for workspace:files.
type WorkspaceFilesOp string

const (
	WorkspaceFilesOpDownload WorkspaceFilesOp = "download"
	WorkspaceFilesOpUpload   WorkspaceFilesOp = "upload"
)

// WorkspaceAppOp is the operation applied to an app for workspace:app.
type WorkspaceAppOp string

const (
	WorkspaceAppOpInstall WorkspaceAppOp = "install"
	WorkspaceAppOpStart   WorkspaceAppOp = "start"
	WorkspaceAppOpStop    WorkspaceAppOp = "stop"
)

// --- workspace:list and workspace:create ---

// WorkspaceOwnerEvalRequest is the validated, typed model for workspace:list
// and workspace:create. Resource.ID is empty — there is no specific workspace;
// Resource.Owner identifies whose workspace collection is being accessed or extended.
type WorkspaceOwnerEvalRequest struct {
	Action   WorkspaceAction
	Resource WorkspaceResource
}

var validWorkspaceOwnerActions = map[WorkspaceAction]struct{}{
	WorkspaceActionList:   {},
	WorkspaceActionCreate: {},
}

var _ EvalRequest = (*WorkspaceOwnerEvalRequest)(nil)

// NewWorkspaceOwnerEvalRequest begins building a WorkspaceOwnerEvalRequest for
// the given action and owner username.
func NewWorkspaceOwnerEvalRequest(action WorkspaceAction, owner string) *WorkspaceOwnerEvalRequest {
	return &WorkspaceOwnerEvalRequest{Action: action, Resource: WorkspaceResource{Owner: owner}}
}

// Build validates the request and returns it if all constraints are satisfied.
func (r *WorkspaceOwnerEvalRequest) Build() (*WorkspaceOwnerEvalRequest, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// ToProto serializes the typed request into a gRPC EvaluateRequest.
// Implements EvalRequest.
func (r *WorkspaceOwnerEvalRequest) ToProto(token string) *authzv1.EvaluateRequest {
	return &authzv1.EvaluateRequest{
		Token:  token,
		Action: string(r.Action),
		Resource: &authzv1.Resource{
			Type:       "workspace",
			Id:         r.Resource.ID,
			Attributes: map[string]string{"owner": r.Resource.Owner},
		},
	}
}

// WorkspaceOwnerEvalRequestFromProto converts a gRPC EvaluateRequest into a
// validated WorkspaceOwnerEvalRequest.
func WorkspaceOwnerEvalRequestFromProto(req *authzv1.EvaluateRequest) (*WorkspaceOwnerEvalRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("workspace: EvaluateRequest is nil")
	}
	if req.Resource == nil {
		return nil, fmt.Errorf("workspace: resource is nil")
	}
	if req.Resource.Type != "workspace" {
		return nil, fmt.Errorf("workspace: resource type must be \"workspace\", got %q", req.Resource.Type)
	}
	r := &WorkspaceOwnerEvalRequest{
		Action: WorkspaceAction(req.Action),
		Resource: WorkspaceResource{
			ID:    req.Resource.Id,
			Owner: req.Resource.Attributes["owner"],
		},
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Validate checks the request against the workspace:list / workspace:create contract.
// Implements EvalRequest.
func (r *WorkspaceOwnerEvalRequest) Validate() error {
	if _, ok := validWorkspaceOwnerActions[r.Action]; !ok {
		return fmt.Errorf("workspace: unknown owner action %q", r.Action)
	}
	if r.Resource.Owner == "" {
		return fmt.Errorf("workspace: resource attribute \"owner\" is required")
	}
	return nil
}

// --- workspace:read and workspace:delete ---

// WorkspaceAccessEvalRequest is the validated, typed model for workspace:read
// and workspace:delete. The resource id is the workspace name; the owner
// attribute identifies who owns it.
type WorkspaceAccessEvalRequest struct {
	Action   WorkspaceAction
	Resource WorkspaceResource
}

var validWorkspaceAccessActions = map[WorkspaceAction]struct{}{
	WorkspaceActionRead:   {},
	WorkspaceActionDelete: {},
}

var _ EvalRequest = (*WorkspaceAccessEvalRequest)(nil)

// NewWorkspaceAccessEvalRequest begins building a WorkspaceAccessEvalRequest.
func NewWorkspaceAccessEvalRequest(action WorkspaceAction, workspaceName string) *WorkspaceAccessEvalRequest {
	return &WorkspaceAccessEvalRequest{
		Action:   action,
		Resource: WorkspaceResource{ID: workspaceName},
	}
}

// WithOwner sets the owner username on the resource.
func (r *WorkspaceAccessEvalRequest) WithOwner(owner string) *WorkspaceAccessEvalRequest {
	r.Resource.Owner = owner
	return r
}

// Build validates the request and returns it if all constraints are satisfied.
func (r *WorkspaceAccessEvalRequest) Build() (*WorkspaceAccessEvalRequest, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// ToProto serializes the typed request into a gRPC EvaluateRequest.
// Implements EvalRequest.
func (r *WorkspaceAccessEvalRequest) ToProto(token string) *authzv1.EvaluateRequest {
	return &authzv1.EvaluateRequest{
		Token:  token,
		Action: string(r.Action),
		Resource: &authzv1.Resource{
			Type:       "workspace",
			Id:         r.Resource.ID,
			Attributes: map[string]string{"owner": r.Resource.Owner},
		},
	}
}

// WorkspaceAccessEvalRequestFromProto converts a gRPC EvaluateRequest into a
// validated WorkspaceAccessEvalRequest.
func WorkspaceAccessEvalRequestFromProto(req *authzv1.EvaluateRequest) (*WorkspaceAccessEvalRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("workspace: EvaluateRequest is nil")
	}
	if req.Resource == nil {
		return nil, fmt.Errorf("workspace: resource is nil")
	}
	if req.Resource.Type != "workspace" {
		return nil, fmt.Errorf("workspace: resource type must be \"workspace\", got %q", req.Resource.Type)
	}
	r := &WorkspaceAccessEvalRequest{
		Action: WorkspaceAction(req.Action),
		Resource: WorkspaceResource{
			ID:    req.Resource.Id,
			Owner: req.Resource.Attributes["owner"],
		},
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Validate checks the request against the workspace:read / workspace:delete contract.
// Implements EvalRequest.
func (r *WorkspaceAccessEvalRequest) Validate() error {
	if _, ok := validWorkspaceAccessActions[r.Action]; !ok {
		return fmt.Errorf("workspace: unknown access action %q", r.Action)
	}
	if r.Resource.ID == "" {
		return fmt.Errorf("workspace: resource ID (workspace name) is required")
	}
	if r.Resource.Owner == "" {
		return fmt.Errorf("workspace: resource attribute \"owner\" is required")
	}
	return nil
}

// --- workspace:connect ---

// WorkspaceConnectContext holds the session type and optional port for
// workspace:connect.
type WorkspaceConnectContext struct {
	Type WorkspaceConnectType
	Port string // non-empty only when Type is WorkspaceConnectTypePortForward
}

// WorkspaceConnectEvalRequest is the validated, typed model for workspace:connect.
type WorkspaceConnectEvalRequest struct {
	Resource WorkspaceResource
	Context  WorkspaceConnectContext
}

var _ EvalRequest = (*WorkspaceConnectEvalRequest)(nil)

// NewWorkspaceConnectEvalRequest begins building a WorkspaceConnectEvalRequest
// for the given workspace name.
func NewWorkspaceConnectEvalRequest(workspaceName string) *WorkspaceConnectEvalRequest {
	return &WorkspaceConnectEvalRequest{
		Resource: WorkspaceResource{ID: workspaceName},
	}
}

// WithOwner sets the owner username on the resource.
func (r *WorkspaceConnectEvalRequest) WithOwner(owner string) *WorkspaceConnectEvalRequest {
	r.Resource.Owner = owner
	return r
}

// WithType sets the connection type.
func (r *WorkspaceConnectEvalRequest) WithType(t WorkspaceConnectType) *WorkspaceConnectEvalRequest {
	r.Context.Type = t
	return r
}

// WithPort sets the port; required when type is WorkspaceConnectTypePortForward.
func (r *WorkspaceConnectEvalRequest) WithPort(port string) *WorkspaceConnectEvalRequest {
	r.Context.Port = port
	return r
}

// Build validates the request and returns it if all constraints are satisfied.
func (r *WorkspaceConnectEvalRequest) Build() (*WorkspaceConnectEvalRequest, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// ToProto serializes the typed request into a gRPC EvaluateRequest.
// Implements EvalRequest.
func (r *WorkspaceConnectEvalRequest) ToProto(token string) *authzv1.EvaluateRequest {
	ctx := map[string]string{"type": string(r.Context.Type)}
	if r.Context.Port != "" {
		ctx["port"] = r.Context.Port
	}
	return &authzv1.EvaluateRequest{
		Token:  token,
		Action: "workspace:connect",
		Resource: &authzv1.Resource{
			Type:       "workspace",
			Id:         r.Resource.ID,
			Attributes: map[string]string{"owner": r.Resource.Owner},
		},
		Context: ctx,
	}
}

// WorkspaceConnectEvalRequestFromProto converts a gRPC EvaluateRequest into a
// validated WorkspaceConnectEvalRequest.
func WorkspaceConnectEvalRequestFromProto(req *authzv1.EvaluateRequest) (*WorkspaceConnectEvalRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("workspace:connect: EvaluateRequest is nil")
	}
	if req.Action != "workspace:connect" {
		return nil, fmt.Errorf("workspace:connect: action must be \"workspace:connect\", got %q", req.Action)
	}
	if req.Resource == nil {
		return nil, fmt.Errorf("workspace:connect: resource is nil")
	}
	if req.Resource.Type != "workspace" {
		return nil, fmt.Errorf("workspace:connect: resource type must be \"workspace\", got %q", req.Resource.Type)
	}
	r := &WorkspaceConnectEvalRequest{
		Resource: WorkspaceResource{
			ID:    req.Resource.Id,
			Owner: req.Resource.Attributes["owner"],
		},
		Context: WorkspaceConnectContext{
			Type: WorkspaceConnectType(req.Context["type"]),
			Port: req.Context["port"],
		},
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Validate checks the request against the workspace:connect contract.
// Implements EvalRequest.
func (r *WorkspaceConnectEvalRequest) Validate() error {
	if r.Resource.ID == "" {
		return fmt.Errorf("workspace:connect: resource ID (workspace name) is required")
	}
	if r.Resource.Owner == "" {
		return fmt.Errorf("workspace:connect: resource attribute \"owner\" is required")
	}
	switch r.Context.Type {
	case WorkspaceConnectTypeWebshell, WorkspaceConnectTypeWebfiles:
	case WorkspaceConnectTypePortForward:
		if r.Context.Port == "" {
			return fmt.Errorf("workspace:connect: context \"port\" is required for portforward")
		}
	default:
		return fmt.Errorf("workspace:connect: context \"type\" must be %q, %q, or %q, got %q",
			WorkspaceConnectTypeWebshell, WorkspaceConnectTypeWebfiles, WorkspaceConnectTypePortForward, r.Context.Type)
	}
	return nil
}

// --- workspace:files ---

// WorkspaceFilesEvalRequest is the validated, typed model for workspace:files.
type WorkspaceFilesEvalRequest struct {
	Resource WorkspaceResource
	Op       WorkspaceFilesOp
}

var _ EvalRequest = (*WorkspaceFilesEvalRequest)(nil)

// NewWorkspaceFilesEvalRequest begins building a WorkspaceFilesEvalRequest for
// the given workspace name.
func NewWorkspaceFilesEvalRequest(workspaceName string) *WorkspaceFilesEvalRequest {
	return &WorkspaceFilesEvalRequest{
		Resource: WorkspaceResource{ID: workspaceName},
	}
}

// WithOwner sets the owner username on the resource.
func (r *WorkspaceFilesEvalRequest) WithOwner(owner string) *WorkspaceFilesEvalRequest {
	r.Resource.Owner = owner
	return r
}

// WithOp sets the file transfer direction.
func (r *WorkspaceFilesEvalRequest) WithOp(op WorkspaceFilesOp) *WorkspaceFilesEvalRequest {
	r.Op = op
	return r
}

// Build validates the request and returns it if all constraints are satisfied.
func (r *WorkspaceFilesEvalRequest) Build() (*WorkspaceFilesEvalRequest, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// ToProto serializes the typed request into a gRPC EvaluateRequest.
// Implements EvalRequest.
func (r *WorkspaceFilesEvalRequest) ToProto(token string) *authzv1.EvaluateRequest {
	return &authzv1.EvaluateRequest{
		Token:  token,
		Action: "workspace:files",
		Resource: &authzv1.Resource{
			Type:       "workspace",
			Id:         r.Resource.ID,
			Attributes: map[string]string{"owner": r.Resource.Owner},
		},
		Context: map[string]string{"op": string(r.Op)},
	}
}

// WorkspaceFilesEvalRequestFromProto converts a gRPC EvaluateRequest into a
// validated WorkspaceFilesEvalRequest.
func WorkspaceFilesEvalRequestFromProto(req *authzv1.EvaluateRequest) (*WorkspaceFilesEvalRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("workspace:files: EvaluateRequest is nil")
	}
	if req.Action != "workspace:files" {
		return nil, fmt.Errorf("workspace:files: action must be \"workspace:files\", got %q", req.Action)
	}
	if req.Resource == nil {
		return nil, fmt.Errorf("workspace:files: resource is nil")
	}
	if req.Resource.Type != "workspace" {
		return nil, fmt.Errorf("workspace:files: resource type must be \"workspace\", got %q", req.Resource.Type)
	}
	r := &WorkspaceFilesEvalRequest{
		Resource: WorkspaceResource{
			ID:    req.Resource.Id,
			Owner: req.Resource.Attributes["owner"],
		},
		Op: WorkspaceFilesOp(req.Context["op"]),
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Validate checks the request against the workspace:files contract.
// Implements EvalRequest.
func (r *WorkspaceFilesEvalRequest) Validate() error {
	if r.Resource.ID == "" {
		return fmt.Errorf("workspace:files: resource ID (workspace name) is required")
	}
	if r.Resource.Owner == "" {
		return fmt.Errorf("workspace:files: resource attribute \"owner\" is required")
	}
	switch r.Op {
	case WorkspaceFilesOpDownload, WorkspaceFilesOpUpload:
	default:
		return fmt.Errorf("workspace:files: context \"op\" must be %q or %q, got %q",
			WorkspaceFilesOpDownload, WorkspaceFilesOpUpload, r.Op)
	}
	return nil
}

// --- workspace:app ---

// WorkspaceAppEvalRequest is the validated, typed model for workspace:app.
type WorkspaceAppEvalRequest struct {
	Resource WorkspaceResource
	App      string
	Op       WorkspaceAppOp
}

var _ EvalRequest = (*WorkspaceAppEvalRequest)(nil)

// NewWorkspaceAppEvalRequest begins building a WorkspaceAppEvalRequest for the
// given workspace name and app name.
func NewWorkspaceAppEvalRequest(workspaceName, appName string) *WorkspaceAppEvalRequest {
	return &WorkspaceAppEvalRequest{
		Resource: WorkspaceResource{ID: workspaceName},
		App:      appName,
	}
}

// WithOwner sets the owner username on the resource.
func (r *WorkspaceAppEvalRequest) WithOwner(owner string) *WorkspaceAppEvalRequest {
	r.Resource.Owner = owner
	return r
}

// WithOp sets the app operation.
func (r *WorkspaceAppEvalRequest) WithOp(op WorkspaceAppOp) *WorkspaceAppEvalRequest {
	r.Op = op
	return r
}

// Build validates the request and returns it if all constraints are satisfied.
func (r *WorkspaceAppEvalRequest) Build() (*WorkspaceAppEvalRequest, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// ToProto serializes the typed request into a gRPC EvaluateRequest.
// Implements EvalRequest.
func (r *WorkspaceAppEvalRequest) ToProto(token string) *authzv1.EvaluateRequest {
	return &authzv1.EvaluateRequest{
		Token:  token,
		Action: "workspace:app",
		Resource: &authzv1.Resource{
			Type: "workspace",
			Id:   r.Resource.ID,
			Attributes: map[string]string{
				"owner": r.Resource.Owner,
				"app":   r.App,
			},
		},
		Context: map[string]string{"op": string(r.Op)},
	}
}

// WorkspaceAppEvalRequestFromProto converts a gRPC EvaluateRequest into a
// validated WorkspaceAppEvalRequest.
func WorkspaceAppEvalRequestFromProto(req *authzv1.EvaluateRequest) (*WorkspaceAppEvalRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("workspace:app: EvaluateRequest is nil")
	}
	if req.Action != "workspace:app" {
		return nil, fmt.Errorf("workspace:app: action must be \"workspace:app\", got %q", req.Action)
	}
	if req.Resource == nil {
		return nil, fmt.Errorf("workspace:app: resource is nil")
	}
	if req.Resource.Type != "workspace" {
		return nil, fmt.Errorf("workspace:app: resource type must be \"workspace\", got %q", req.Resource.Type)
	}
	r := &WorkspaceAppEvalRequest{
		Resource: WorkspaceResource{
			ID:    req.Resource.Id,
			Owner: req.Resource.Attributes["owner"],
		},
		App: req.Resource.Attributes["app"],
		Op:  WorkspaceAppOp(req.Context["op"]),
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Validate checks the request against the workspace:app contract.
// Implements EvalRequest.
func (r *WorkspaceAppEvalRequest) Validate() error {
	if r.Resource.ID == "" {
		return fmt.Errorf("workspace:app: resource ID (workspace name) is required")
	}
	if r.Resource.Owner == "" {
		return fmt.Errorf("workspace:app: resource attribute \"owner\" is required")
	}
	if r.App == "" {
		return fmt.Errorf("workspace:app: resource attribute \"app\" is required")
	}
	switch r.Op {
	case WorkspaceAppOpInstall, WorkspaceAppOpStart, WorkspaceAppOpStop:
	default:
		return fmt.Errorf("workspace:app: context \"op\" must be %q, %q, or %q, got %q",
			WorkspaceAppOpInstall, WorkspaceAppOpStart, WorkspaceAppOpStop, r.Op)
	}
	return nil
}

const (
	// ObligationKeyPatchPrefix is the prefix the policy engine uses to express
	// blueprint patch obligations for workspace:provision. Each key of the form
	// "patch:<json-pointer>" (RFC 6901) names a location in the blueprint YAML
	// document; the corresponding value is the string to set at that path.
	// Example: "patch:/resources/cpu" → "2000m".
	ObligationKeyPatchPrefix = "patch:"
)

// ProvisionPatch is a single blueprint mutation expressed by the policy engine
// as part of a workspace:provision obligation. Path is a JSON Pointer (RFC 6901)
// addressing a field in the blueprint YAML document.
type ProvisionPatch struct {
	Path  string // e.g. "/resources/cpu"
	Value string
}

// ParseProvisionPatchObligations extracts all patch obligations from the
// obligations map. Every key with the ObligationKeyPatchPrefix prefix is
// interpreted as a JSON Pointer path; the map value is the string to write
// there. Returns nil when no patch obligations are present.
func ParseProvisionPatchObligations(obligations map[string]string) []ProvisionPatch {
	var patches []ProvisionPatch
	for k, v := range obligations {
		if p, ok := strings.CutPrefix(k, ObligationKeyPatchPrefix); ok {
			patches = append(patches, ProvisionPatch{Path: p, Value: v})
		}
	}
	return patches
}

// ApplyProvisionPatches applies a slice of ProvisionPatch obligations to a
// Blueprint and returns the modified copy. The blueprint is round-tripped
// through YAML so that path tokens match yaml struct tag names. Each patch
// value is YAML-decoded before being written, so "false" becomes bool(false),
// "2000m" stays as a string, etc. Returns the original pointer unchanged when
// patches is empty.
func ApplyProvisionPatches(bp *models.Blueprint, patches []ProvisionPatch) (*models.Blueprint, error) {
	if len(patches) == 0 {
		return bp, nil
	}

	// Marshal to YAML then to a generic map so JSON Pointer tokens can navigate it.
	data, err := yaml.Marshal(bp)
	if err != nil {
		return nil, fmt.Errorf("workspace: marshal blueprint: %w", err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("workspace: unmarshal blueprint to map: %w", err)
	}

	for _, p := range patches {
		if err := applyPatch(doc, p); err != nil {
			return nil, fmt.Errorf("workspace: patch %q: %w", p.Path, err)
		}
	}

	// Round-trip back to a typed Blueprint.
	patched, err := yaml.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("workspace: marshal patched blueprint: %w", err)
	}
	var result models.Blueprint
	if err := yaml.Unmarshal(patched, &result); err != nil {
		return nil, fmt.Errorf("workspace: unmarshal patched blueprint: %w", err)
	}
	return &result, nil
}

// applyPatch navigates doc using the JSON Pointer in p.Path and sets the leaf
// to p.Value. The value is YAML-decoded first so typed scalars (bool, int, ...)
// round-trip correctly; if that decode fails the raw string is used instead.
func applyPatch(doc map[string]any, p ProvisionPatch) error {
	tokens, err := parseJSONPointer(p.Path)
	if err != nil {
		return err
	}

	// Decode the string value via YAML so "false"→bool, "42"→int, etc.
	var value any
	if err := yaml.Unmarshal([]byte(p.Value), &value); err != nil {
		value = p.Value
	}

	// Walk to the parent node, auto-vivifying intermediate maps.
	current := any(doc)
	for _, token := range tokens[:len(tokens)-1] {
		m, ok := current.(map[string]any)
		if !ok {
			return fmt.Errorf("segment %q: parent is not a map", token)
		}
		next, exists := m[token]
		if !exists {
			child := map[string]any{}
			m[token] = child
			current = child
		} else {
			current = next
		}
	}

	leaf := tokens[len(tokens)-1]
	m, ok := current.(map[string]any)
	if !ok {
		return fmt.Errorf("parent of %q is not a map", leaf)
	}
	m[leaf] = value
	return nil
}

// parseJSONPointer splits a JSON Pointer (RFC 6901) into its reference tokens.
// The pointer must begin with '/'. Escape sequences are decoded in the order
// required by the spec: '~1' → '/' first, then '~0' → '~'.
func parseJSONPointer(ptr string) ([]string, error) {
	if len(ptr) == 0 || ptr[0] != '/' {
		return nil, fmt.Errorf("JSON Pointer must start with '/', got %q", ptr)
	}
	tokens := strings.Split(ptr[1:], "/")
	for i, t := range tokens {
		if t == "" {
			return nil, fmt.Errorf("JSON Pointer contains empty token in %q", ptr)
		}
		tokens[i] = strings.ReplaceAll(strings.ReplaceAll(t, "~1", "/"), "~0", "~")
	}
	return tokens, nil
}
