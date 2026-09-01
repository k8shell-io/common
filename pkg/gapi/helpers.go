package gapi

import (
	"time"

	commonv1 "github.com/k8shell-io/common/pkg/api/gen/go/common/v1"
	identityv1 "github.com/k8shell-io/common/pkg/api/gen/go/identity/v1"
	provisionerv1 "github.com/k8shell-io/common/pkg/api/gen/go/provisioner/v1"
	"github.com/k8shell-io/common/pkg/models"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gopkg.in/yaml.v3"
)

// *** User and related models

func UserToProto(u *models.User) *commonv1.User {
	if u == nil {
		return nil
	}
	var expires *timestamppb.Timestamp
	if !u.ExpiresAt.IsZero() {
		expires = timestamppb.New(u.ExpiresAt)
	}

	roles := make([]string, len(u.Roles))
	for i, r := range u.Roles {
		roles[i] = string(r)
	}

	return &commonv1.User{
		Username:     u.Username,
		Organization: u.Organization,
		IsValid:      u.IsValid,
		ExpiresAt:    expires,
		Uid:          u.UID,
		Gid:          u.GID,
		Fullname:     u.Fullname,
		Email:        u.Email,
		// Password is intentionally omitted: it is never populated in read responses.
		Locked:      u.Locked,
		Roles:       roles,
		Blueprints:  u.Blueprints,
		Source:      u.Source,
		Shell:       u.Shell,
		Sudo:        u.Sudo,
		ManageRepos: u.ManageRepos,
		GitAddress:  u.GitAddress,
	}
}

func ProtoToUser(pb *commonv1.User) *models.User {
	if pb == nil {
		return nil
	}
	var expires time.Time
	if ts := pb.GetExpiresAt(); ts != nil {
		expires = ts.AsTime()
	}

	roles := make([]models.Role, len(pb.GetRoles()))
	for i, r := range pb.GetRoles() {
		roles[i] = models.Role(r)
	}

	return &models.User{
		Username:     pb.GetUsername(),
		Organization: pb.GetOrganization(),
		IsValid:      pb.GetIsValid(),
		ExpiresAt:    expires,
		UID:          pb.GetUid(), // already uint32
		GID:          pb.GetGid(),
		Fullname:     pb.GetFullname(),

		Email:    pb.GetEmail(),
		Password: pb.GetPassword(),

		Locked:     pb.GetLocked(),
		Roles:      roles,
		Blueprints: pb.GetBlueprints(),
		Source:     pb.GetSource(),
		Shell:      pb.GetShell(),
		Sudo:       pb.GetSudo(),

		ManageRepos: pb.GetManageRepos(),
		GitAddress:  pb.GetGitAddress(),
	}
}

// UserCredentialToProto converts a Go model to a protobuf message.
func UserCredentialToProto(c *models.UserCredential) *commonv1.UserCredential {
	if c == nil {
		return nil
	}
	var expiresAt *timestamppb.Timestamp
	if c.ExpiresAt != nil {
		expiresAt = timestamppb.New(*c.ExpiresAt)
	}
	var lastUsedAt *timestamppb.Timestamp
	if c.LastUsedAt != nil {
		lastUsedAt = timestamppb.New(*c.LastUsedAt)
	}
	return &commonv1.UserCredential{
		Id:               c.ID,
		Username:         c.Username,
		ServiceName:      c.ServiceName,
		ServiceScope:     c.ServiceScope,
		CredentialSource: c.CredentialSource,
		Subject:          c.Subject,
		Secret:           c.Secret,
		IsActive:         c.IsActive,
		CreatedAt:        timestamppb.New(c.CreatedAt),
		UpdatedAt:        timestamppb.New(c.UpdatedAt),
		ExpiresAt:        expiresAt,
		LastUsedAt:       lastUsedAt,
	}
}

// ProtoToUserCredential converts a protobuf message to a Go model.
func ProtoToUserCredential(pb *commonv1.UserCredential) *models.UserCredential {
	if pb == nil {
		return nil
	}
	var expiresAt *time.Time
	if ts := pb.GetExpiresAt(); ts != nil {
		t := ts.AsTime()
		expiresAt = &t
	}
	var lastUsedAt *time.Time
	if ts := pb.GetLastUsedAt(); ts != nil {
		t := ts.AsTime()
		lastUsedAt = &t
	}
	return &models.UserCredential{
		ID:               pb.GetId(),
		Username:         pb.GetUsername(),
		ServiceName:      pb.GetServiceName(),
		ServiceScope:     pb.GetServiceScope(),
		CredentialSource: pb.GetCredentialSource(),
		Subject:          pb.GetSubject(),
		Secret:           pb.GetSecret(),
		IsActive:         pb.GetIsActive(),
		CreatedAt:        pb.GetCreatedAt().AsTime(),
		UpdatedAt:        pb.GetUpdatedAt().AsTime(),
		ExpiresAt:        expiresAt,
		LastUsedAt:       lastUsedAt,
	}
}

// OnboardUserDeviceFlowToProto converts a Go model to a protobuf message.
func OnboardUserDeviceFlowToProto(m *models.OnboardUserDeviceFlow) *commonv1.OnboardUserDeviceFlow {
	if m == nil {
		return nil
	}
	return &commonv1.OnboardUserDeviceFlow{
		Provider:        m.Provider,
		Username:        m.Username,
		UserCode:        m.UserCode,
		VerificationUrl: m.VerificationUrl,
		ExpiresIn:       int32(m.ExpiresIn),
	}
}

// ProtoToOnboardUserDeviceFlow converts a protobuf message to a Go model.
func ProtoToOnboardUserDeviceFlow(pb *commonv1.OnboardUserDeviceFlow) *models.OnboardUserDeviceFlow {
	if pb == nil {
		return nil
	}
	return &models.OnboardUserDeviceFlow{
		Provider:        pb.GetProvider(),
		Username:        pb.GetUsername(),
		UserCode:        pb.GetUserCode(),
		VerificationUrl: pb.GetVerificationUrl(),
		ExpiresIn:       int(pb.GetExpiresIn()),
	}
}

// OnboardUserWebFlowToProto converts a Go model to a protobuf message.
func OnboardUserWebFlowToProto(m *models.OnboardUserWebFlow) *commonv1.OnboardUserWebFlow {
	if m == nil {
		return nil
	}
	return &commonv1.OnboardUserWebFlow{
		Provider:  m.Provider,
		AuthUrl:   m.AuthorizationURL,
		State:     m.State,
		ExpiresIn: int32(m.ExpiresIn),
	}
}

// ProtoToOnboardUserWebFlow converts a protobuf message to a Go model.
func ProtoToOnboardUserWebFlow(pb *commonv1.OnboardUserWebFlow) *models.OnboardUserWebFlow {
	if pb == nil {
		return nil
	}
	return &models.OnboardUserWebFlow{
		Provider:         pb.GetProvider(),
		AuthorizationURL: pb.GetAuthUrl(),
		State:            pb.GetState(),
		ExpiresIn:        int(pb.GetExpiresIn()),
	}
}

// CompleteUserWebFlowToProto converts a Go model to a protobuf message.
func CompleteUserWebFlowToProto(m *models.CompleteUserWebFlow) *commonv1.CompleteUserWebFlow {
	if m == nil {
		return nil
	}
	return &commonv1.CompleteUserWebFlow{
		Code:  m.Code,
		State: m.State,
	}
}

// ProtoToCompleteUserWebFlow converts a protobuf message to a Go model.
func ProtoToCompleteUserWebFlow(pb *commonv1.CompleteUserWebFlow) *models.CompleteUserWebFlow {
	if pb == nil {
		return nil
	}
	return &models.CompleteUserWebFlow{
		Code:  pb.GetCode(),
		State: pb.GetState(),
	}
}

// UserOnboardCapabilityToProto converts a Go model to a protobuf message.
func UserOnboardCapabilityToProto(m *models.OnboardCapability) *commonv1.UserOnboardCapability {
	if m == nil {
		return nil
	}
	return &commonv1.UserOnboardCapability{
		Provider:   m.Provider,
		Username:   m.Username,
		CanOnboard: m.CanOnboard,
	}
}

// ProtoToUserOnboardCapability converts a protobuf message to a Go model.
func ProtoToUserOnboardCapability(pb *commonv1.UserOnboardCapability) *models.OnboardCapability {
	if pb == nil {
		return nil
	}
	return &models.OnboardCapability{
		Provider:   pb.GetProvider(),
		Username:   pb.GetUsername(),
		CanOnboard: pb.GetCanOnboard(),
	}
}

// OnboardUserRuleToProto converts a Go model to a protobuf message.
func OnboardUserRuleToProto(m *models.OnboardUserRule) *commonv1.OnboardUserRule {
	if m == nil {
		return nil
	}
	return &commonv1.OnboardUserRule{
		Username:     m.Username,
		Fullname:     m.Fullname,
		Email:        m.Email,
		Organization: m.Organization,
		Sudo:         copyBool(m.Sudo),
		Action:       string(m.Action),
		Roles:        m.Roles,
		Uid:          m.UID,
		Gid:          m.GID,
	}
}

// ProtoToOnboardUserRule converts a protobuf message to a Go model.
func ProtoToOnboardUserRule(pb *commonv1.OnboardUserRule) *models.OnboardUserRule {
	if pb == nil {
		return nil
	}
	return &models.OnboardUserRule{
		Username:     pb.GetUsername(),
		Fullname:     pb.GetFullname(),
		Email:        pb.GetEmail(),
		Organization: pb.GetOrganization(),
		Sudo:         copyBool(pb.Sudo),
		Action:       models.OnboardAction(pb.GetAction()),
		Roles:        pb.GetRoles(),
		UID:          pb.GetUid(),
		GID:          pb.GetGid(),
	}
}

// copyBool duplicates an optional bool so that the model and the protobuf
// message never share the same pointer.
func copyBool(v *bool) *bool {
	if v == nil {
		return nil
	}
	c := *v
	return &c
}

// UserResultToProto converts a Go model to a protobuf message.
func UserResultToProto(m *models.UserResult) *commonv1.UserResult {
	if m == nil {
		return nil
	}
	return &commonv1.UserResult{
		OnboardRule: OnboardUserRuleToProto(&m.OnboardRule),
		ManageRepos: m.ManageRepos,
		GitAddress:  m.GitAddress,
	}
}

// ProtoToUserResult converts a protobuf message to a Go model.
func ProtoToUserResult(pb *commonv1.UserResult) *models.UserResult {
	if pb == nil {
		return nil
	}
	return &models.UserResult{
		OnboardRule: *ProtoToOnboardUserRule(pb.GetOnboardRule()),
		ManageRepos: pb.GetManageRepos(),
		GitAddress:  pb.GetGitAddress(),
	}
}

// *** Workspace and related models

// WorkspaceStatusToProto converts a Go WorkspaceStatus model to its protobuf message.
func WorkspaceStatusToProto(m *models.WorkspaceStatus) *commonv1.WorkspaceStatus {
	if m == nil {
		return nil
	}

	var created *timestamppb.Timestamp
	if !m.Created.IsZero() {
		created = timestamppb.New(m.Created)
	}

	return &commonv1.WorkspaceStatus{
		Created:         created,
		Status:          string(m.Status),
		Message:         m.Message,
		Restarts:        m.Restarts,
		LastFailMessage: m.LastFailMessage,
	}
}

// ProtoToWorkspaceStatus converts a protobuf WorkspaceStatus message to its Go model.
func ProtoToWorkspaceStatus(pb *commonv1.WorkspaceStatus) *models.WorkspaceStatus {
	if pb == nil {
		return nil
	}

	var created time.Time
	if ts := pb.GetCreated(); ts != nil {
		created = ts.AsTime()
	}

	return &models.WorkspaceStatus{
		Created:         created,
		Status:          models.WorkspaceStatusMessage(pb.GetStatus()),
		Message:         pb.GetMessage(),
		Restarts:        pb.GetRestarts(),
		LastFailMessage: pb.GetLastFailMessage(),
	}
}

// WorkspaceDetailsToProto converts a Go WorkspaceDetails model to its protobuf message.
func WorkspaceDetailsToProto(m *models.WorkspaceDetails) *commonv1.WorkspaceDetails {
	if m == nil {
		return nil
	}

	return &commonv1.WorkspaceDetails{
		WorkspaceStatus:    WorkspaceStatusToProto(&m.WorkspaceStatus),
		Name:               m.Name,
		Username:           m.Username,
		Blueprint:          m.Blueprint,
		Origin:             m.Origin,
		Organization:       m.Organization,
		RepoOwner:          m.RepoOwner,
		RepoName:           m.RepoName,
		RepoRef:            m.RepoRef,
		ServerName:         m.ServerName,
		PodIp:              m.PodIP,
		Port:               int32(m.Port),
		TlsEnabled:         m.TLSEnabled,
		AppVersion:         m.AppVersion,
		Cpu:                m.CPU,
		Memory:             m.Memory,
		Hostname:           m.Hostname,
		JobId:              m.JobId,
		Namespace:          m.Namespace,
		NetworkPolicyClass: m.NetworkPolicyClass,
		AllowEgressToCidrs: append([]string(nil), m.AllowEgressToCIDRs...),
		AllowEgressToPods:  podSelectorsToProto(m.AllowEgressToPods),
		WorkspaceType:      string(m.WorkspaceType),
		WorkloadKind:       m.WorkloadKind,
		WorkloadName:       m.WorkloadName,
		ReplicaIndex:       copyInt32(m.ReplicaIndex),
		ReplicaCount:       copyInt32(m.ReplicaCount),
	}
}

// copyInt32 duplicates an optional int32 so that the model and the protobuf
// message never share the same pointer.
func copyInt32(v *int32) *int32 {
	if v == nil {
		return nil
	}
	c := *v
	return &c
}

// podSelectorsToProto converts the []map[string]string egress-to-pods shorthand
// into its repeated-message protobuf form, copying every map.
func podSelectorsToProto(sels []map[string]string) []*commonv1.PodLabelSelector {
	if sels == nil {
		return nil
	}
	out := make([]*commonv1.PodLabelSelector, 0, len(sels))
	for _, s := range sels {
		labels := make(map[string]string, len(s))
		for k, v := range s {
			labels[k] = v
		}
		out = append(out, &commonv1.PodLabelSelector{MatchLabels: labels})
	}
	return out
}

// protoToPodSelectors is the inverse of podSelectorsToProto.
func protoToPodSelectors(sels []*commonv1.PodLabelSelector) []map[string]string {
	if sels == nil {
		return nil
	}
	out := make([]map[string]string, 0, len(sels))
	for _, s := range sels {
		labels := make(map[string]string, len(s.GetMatchLabels()))
		for k, v := range s.GetMatchLabels() {
			labels[k] = v
		}
		out = append(out, labels)
	}
	return out
}

// ProtoToWorkspaceDetails converts a protobuf WorkspaceDetails message to its Go model.
func ProtoToWorkspaceDetails(pb *commonv1.WorkspaceDetails) *models.WorkspaceDetails {
	if pb == nil {
		return nil
	}

	return &models.WorkspaceDetails{
		WorkspaceStatus:    *ProtoToWorkspaceStatus(pb.GetWorkspaceStatus()),
		Name:               pb.GetName(),
		Username:           pb.GetUsername(),
		Organization:       pb.GetOrganization(),
		RepoOwner:          pb.GetRepoOwner(),
		RepoName:           pb.GetRepoName(),
		RepoRef:            pb.GetRepoRef(),
		Blueprint:          pb.GetBlueprint(),
		Origin:             pb.GetOrigin(),
		ServerName:         pb.GetServerName(),
		PodIP:              pb.GetPodIp(),
		Port:               int(pb.GetPort()),
		TLSEnabled:         pb.GetTlsEnabled(),
		AppVersion:         pb.GetAppVersion(),
		CPU:                pb.GetCpu(),
		Memory:             pb.GetMemory(),
		Hostname:           pb.GetHostname(),
		JobId:              pb.GetJobId(),
		Namespace:          pb.GetNamespace(),
		NetworkPolicyClass: pb.GetNetworkPolicyClass(),
		AllowEgressToCIDRs: append([]string(nil), pb.GetAllowEgressToCidrs()...),
		AllowEgressToPods:  protoToPodSelectors(pb.GetAllowEgressToPods()),
		WorkspaceType:      models.WorkspaceType(pb.GetWorkspaceType()),
		WorkloadKind:       pb.GetWorkloadKind(),
		WorkloadName:       pb.GetWorkloadName(),
		ReplicaIndex:       copyInt32(pb.ReplicaIndex),
		ReplicaCount:       copyInt32(pb.ReplicaCount),
	}
}

// BlueprintSummaryToProto converts a Go BlueprintSummary model to its protobuf message.
func BlueprintSummaryToProto(m *models.BlueprintSummary) *commonv1.BlueprintSummary {
	if m == nil {
		return nil
	}
	return &commonv1.BlueprintSummary{
		Name:        m.Name,
		Description: m.Description,
		IsTemplate:  m.IsTemplate,
		Org:         m.Org,
		IsGlobal:    m.IsGlobal,
		Template:    m.Template,
		CreatedAt:   timestamppb.New(m.CreatedAt),
		UpdatedAt:   timestamppb.New(m.UpdatedAt),
	}
}

// ProtoToBlueprintSummary converts a protobuf BlueprintSummary message to its Go model.
func ProtoToBlueprintSummary(pb *commonv1.BlueprintSummary) *models.BlueprintSummary {
	if pb == nil {
		return nil
	}
	return &models.BlueprintSummary{
		Name:        pb.GetName(),
		Description: pb.GetDescription(),
		IsTemplate:  pb.GetIsTemplate(),
		Org:         pb.GetOrg(),
		IsGlobal:    pb.GetIsGlobal(),
		Template:    pb.GetTemplate(),
		CreatedAt:   pb.GetCreatedAt().AsTime(),
		UpdatedAt:   pb.GetUpdatedAt().AsTime(),
	}
}

// ProtoToBlueprintValidation converts a protobuf ValidateBlueprintResponse
// message to its Go model, decoding ResolvedBlueprint generically into
// Blueprint (see BlueprintValidation). ResolvedBlueprint is only set by the
// server when Valid is true, so Blueprint is left nil for any invalid
// submission; returns an error only if a present ResolvedBlueprint fails to
// parse as YAML.
func ProtoToBlueprintValidation(pb *provisionerv1.ValidateBlueprintResponse) (*models.BlueprintValidation, error) {
	if pb == nil {
		return nil, nil
	}
	errs := make([]*models.BlueprintValidationError, 0, len(pb.GetErrors()))
	for _, e := range pb.GetErrors() {
		errs = append(errs, &models.BlueprintValidationError{
			Line:    e.GetLine(),
			Column:  e.GetColumn(),
			Field:   e.GetField(),
			Message: e.GetMessage(),
		})
	}
	v := &models.BlueprintValidation{
		Valid:  pb.GetValid(),
		Errors: errs,
	}
	if raw := pb.GetResolvedBlueprint(); len(raw) > 0 {
		if err := yaml.Unmarshal(raw, &v.Blueprint); err != nil {
			return nil, err
		}
	}
	return v, nil
}

// OrgBlueprintToProto converts a Go OrgBlueprint model to its protobuf message.
func OrgBlueprintToProto(m *models.OrgBlueprint) *provisionerv1.OrgBlueprint {
	if m == nil {
		return nil
	}
	var createdAt, updatedAt *timestamppb.Timestamp
	if !m.CreatedAt.IsZero() {
		createdAt = timestamppb.New(m.CreatedAt)
	}
	if !m.UpdatedAt.IsZero() {
		updatedAt = timestamppb.New(m.UpdatedAt)
	}
	return &provisionerv1.OrgBlueprint{
		Name:        m.Name,
		Org:         m.Org,
		Description: m.Description,
		Yaml:        m.YAML,
		IsTemplate:  m.IsTemplate,
		CreatedAt:   createdAt,
		UpdatedAt:   updatedAt,
	}
}

// ProtoToOrgBlueprint converts a protobuf OrgBlueprint message to its Go model.
func ProtoToOrgBlueprint(pb *provisionerv1.OrgBlueprint) *models.OrgBlueprint {
	if pb == nil {
		return nil
	}
	m := &models.OrgBlueprint{
		Name:        pb.GetName(),
		Org:         pb.GetOrg(),
		Description: pb.GetDescription(),
		YAML:        pb.GetYaml(),
		IsTemplate:  pb.GetIsTemplate(),
	}
	if pb.GetCreatedAt() != nil {
		m.CreatedAt = pb.GetCreatedAt().AsTime()
	}
	if pb.GetUpdatedAt() != nil {
		m.UpdatedAt = pb.GetUpdatedAt().AsTime()
	}
	return m
}

// ProtoToInjectNamespaces converts a protobuf ListInjectNamespacesResponse
// message to its Go model.
func ProtoToInjectNamespaces(pb *provisionerv1.ListInjectNamespacesResponse) *models.InjectNamespaces {
	if pb == nil {
		return nil
	}
	return &models.InjectNamespaces{
		Namespaces:  pb.GetNamespaces(),
		ClusterWide: pb.GetClusterWide(),
	}
}

// ProtoToInjectWorkload converts a protobuf InjectWorkload message to its Go model.
func ProtoToInjectWorkload(pb *provisionerv1.InjectWorkload) *models.InjectWorkload {
	if pb == nil {
		return nil
	}
	return &models.InjectWorkload{
		Namespace:    pb.GetNamespace(),
		Kind:         pb.GetKind(),
		Name:         pb.GetName(),
		Replicas:     pb.GetReplicas(),
		Injected:     pb.GetInjected(),
		Workspace:    pb.GetWorkspace(),
		Username:     pb.GetUsername(),
		Organization: pb.GetOrganization(),
		Blueprint:    pb.GetBlueprint(),
	}
}

// ProtoToRepoOwner converts a protobuf RepoOwner message to its Go model.
func ProtoToRepoOwner(pb *identityv1.RepoOwner) *models.RepoOwner {
	if pb == nil {
		return nil
	}
	return &models.RepoOwner{
		Login:       pb.GetLogin(),
		Kind:        pb.GetKind(),
		Description: pb.GetDescription(),
		AvatarURL:   pb.GetAvatarUrl(),
	}
}

// ProtoToRepo converts a protobuf Repo message to its Go model.
func ProtoToRepo(pb *identityv1.Repo) *models.Repo {
	if pb == nil {
		return nil
	}
	return &models.Repo{
		Name:          pb.GetName(),
		FullName:      pb.GetFullName(),
		Description:   pb.GetDescription(),
		Private:       pb.GetPrivate(),
		DefaultBranch: pb.GetDefaultBranch(),
		HTMLURL:       pb.GetHtmlUrl(),
	}
}

// ProtoToServiceVersionInfo converts a protobuf GetVersionInfoResponse
// message to its Go model. It maps only the fields the RPC carries; the
// model's Error and any Version fallback are set by the caller.
func ProtoToServiceVersionInfo(pb *commonv1.GetVersionInfoResponse) *models.ServiceVersionInfo {
	if pb == nil {
		return nil
	}
	return &models.ServiceVersionInfo{
		Version:     pb.GetVersion(),
		CommitID:    pb.GetCommitId(),
		Description: pb.GetDescription(),
	}
}
