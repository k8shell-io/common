package gapi

import (
	"time"

	commonv1 "github.com/k8shell-io/common/pkg/api/gen/go/common/v1"
	"github.com/k8shell-io/common/pkg/models"
	"google.golang.org/protobuf/types/known/timestamppb"
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
		Password:     u.Password,
		Auths:        u.Auths,
		AuthKeys:     u.AuthKeys,
		Locked:       u.Locked,
		Roles:        roles,
		Blueprints:   u.Blueprints,
		Source:       u.Source,
		Shell:        u.Shell,
		Sudo:         u.Sudo,
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

		Auths:      pb.GetAuths(),
		AuthKeys:   pb.GetAuthKeys(),
		Locked:     pb.GetLocked(),
		Roles:      roles,
		Blueprints: pb.GetBlueprints(),
		Source:     pb.GetSource(),
		Shell:      pb.GetShell(),
		Sudo:       pb.GetSudo(),
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
		WorkspaceStatus: WorkspaceStatusToProto(&m.WorkspaceStatus),
		Name:            m.Name,
		Username:        m.Username,
		Blueprint:       m.Blueprint,
		Organization:    m.Organization,
		RepoOwner:       m.RepoOwner,
		RepoName:        m.RepoName,
		RepoRef:         m.RepoRef,
		ServerName:      m.ServerName,
		PodIp:           m.PodIP,
		Port:            int32(m.Port),
		TlsEnabled:      m.TLSEnabled,
		AppVersion:      m.AppVersion,
		Cpu:             m.CPU,
		Memory:          m.Memory,
		Hostname:        m.Hostname,
		JobId:           m.JobId,
		Namespace:       m.Namespace,
	}
}

// ProtoToWorkspaceDetails converts a protobuf WorkspaceDetails message to its Go model.
func ProtoToWorkspaceDetails(pb *commonv1.WorkspaceDetails) *models.WorkspaceDetails {
	if pb == nil {
		return nil
	}

	return &models.WorkspaceDetails{
		WorkspaceStatus: *ProtoToWorkspaceStatus(pb.GetWorkspaceStatus()),
		Name:            pb.GetName(),
		Username:        pb.GetUsername(),
		Organization:    pb.GetOrganization(),
		RepoOwner:       pb.GetRepoOwner(),
		RepoName:        pb.GetRepoName(),
		RepoRef:         pb.GetRepoRef(),
		Blueprint:       pb.GetBlueprint(),
		ServerName:      pb.GetServerName(),
		PodIP:           pb.GetPodIp(),
		Port:            int(pb.GetPort()),
		TLSEnabled:      pb.GetTlsEnabled(),
		AppVersion:      pb.GetAppVersion(),
		CPU:             pb.GetCpu(),
		Memory:          pb.GetMemory(),
		Hostname:        pb.GetHostname(),
		JobId:           pb.GetJobId(),
		Namespace:       pb.GetNamespace(),
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
	}
}
