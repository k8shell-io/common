package gapi

import (
	"time"

	commonpb "github.com/k8shell-io/common/pkg/gapi/commonpb"
	"github.com/k8shell-io/common/pkg/models"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// *** User and related models

func UserToProto(u *models.User) *commonpb.User {
	if u == nil {
		return nil
	}
	var expires *timestamppb.Timestamp
	if !u.ExpiresAt.IsZero() {
		expires = timestamppb.New(u.ExpiresAt)
	}
	return &commonpb.User{
		Username:     u.Username,
		Organization: u.Organization,
		IsValid:      u.IsValid,
		ExpiresAt:    expires,
		Uid:          u.UID,
		Gid:          u.GID,
		Fullname:     u.Fullname,
		AccessToken:  u.AccessToken,
		Email:        u.Email,
		Password:     u.Password,
		Auths:        u.Auths,
		AuthKeys:     u.AuthKeys,
		Locked:       u.Locked,
		FailedLogins: u.FailedLogins,
		Channels:     u.Channels,
		Envs:         u.Envs,
		Roles:        u.Roles,
		Blueprints:   u.Blueprints,
		Source:       u.Source,
	}
}

func ProtoToUser(pb *commonpb.User) *models.User {
	if pb == nil {
		return nil
	}
	var expires time.Time
	if ts := pb.GetExpiresAt(); ts != nil {
		expires = ts.AsTime()
	}
	return &models.User{
		Username:     pb.GetUsername(),
		Organization: pb.GetOrganization(),
		IsValid:      pb.GetIsValid(),
		ExpiresAt:    expires,
		UID:          pb.GetUid(), // already uint32
		GID:          pb.GetGid(),
		Fullname:     pb.GetFullname(),

		AccessToken: pb.GetAccessToken(),
		Email:       pb.GetEmail(),
		Password:    pb.GetPassword(),

		Auths:        pb.GetAuths(),
		AuthKeys:     pb.GetAuthKeys(),
		Locked:       pb.GetLocked(),
		FailedLogins: pb.GetFailedLogins(),
		Channels:     pb.GetChannels(),
		Envs:         pb.GetEnvs(),
		Roles:        pb.GetRoles(),
		Blueprints:   pb.GetBlueprints(),
		Source:       pb.GetSource(),
	}
}

// ExternalCredentialToProto converts a Go model to a protobuf message.
func ExternalCredentialToProto(c *models.ExternalCredential) *commonpb.ExternalCredential {
	if c == nil {
		return nil
	}
	return &commonpb.ExternalCredential{
		Id:            uint32(c.ID),
		Username:      c.Username,
		ServiceName:   c.ServiceName,
		ServiceUrl:    c.ServiceURL,
		ExternalId:    c.ExternalID,
		ExternalToken: c.ExternalToken,
	}
}

// ProtoToExternalCredential converts a protobuf message to a Go model.
func ProtoToExternalCredential(pb *commonpb.ExternalCredential) *models.ExternalCredential {
	if pb == nil {
		return nil
	}
	return &models.ExternalCredential{
		ID:            uint64(pb.GetId()),
		Username:      pb.GetUsername(),
		ServiceName:   pb.GetServiceName(),
		ServiceURL:    pb.GetServiceUrl(),
		ExternalID:    pb.GetExternalId(),
		ExternalToken: pb.GetExternalToken(),
	}
}

// OnboardUserDeviceFlowToProto converts a Go model to a protobuf message.
func OnboardUserDeviceFlowToProto(m *models.OnboardUserDeviceFlow) *commonpb.OnboardUserDeviceFlow {
	if m == nil {
		return nil
	}
	return &commonpb.OnboardUserDeviceFlow{
		Provider:        m.Provider,
		Username:        m.Username,
		UserCode:        m.UserCode,
		VerificationUrl: m.VerificationUrl,
		ExpiresIn:       int32(m.ExpiresIn),
	}
}

// ProtoToOnboardUserDeviceFlow converts a protobuf message to a Go model.
func ProtoToOnboardUserDeviceFlow(pb *commonpb.OnboardUserDeviceFlow) *models.OnboardUserDeviceFlow {
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
func OnboardUserWebFlowToProto(m *models.OnboardUserWebFlow) *commonpb.OnboardUserWebFlow {
	if m == nil {
		return nil
	}
	return &commonpb.OnboardUserWebFlow{
		Provider:  m.Provider,
		AuthUrl:   m.AuthorizationURL,
		State:     m.State,
		ExpiresIn: int32(m.ExpiresIn),
	}
}

// ProtoToOnboardUserWebFlow converts a protobuf message to a Go model.
func ProtoToOnboardUserWebFlow(pb *commonpb.OnboardUserWebFlow) *models.OnboardUserWebFlow {
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
func CompleteUserWebFlowToProto(m *models.CompleteUserWebFlow) *commonpb.CompleteUserWebFlow {
	if m == nil {
		return nil
	}
	return &commonpb.CompleteUserWebFlow{
		Code:  m.Code,
		State: m.State,
	}
}

// ProtoToCompleteUserWebFlow converts a protobuf message to a Go model.
func ProtoToCompleteUserWebFlow(pb *commonpb.CompleteUserWebFlow) *models.CompleteUserWebFlow {
	if pb == nil {
		return nil
	}
	return &models.CompleteUserWebFlow{
		Code:  pb.GetCode(),
		State: pb.GetState(),
	}
}

// UserOnboardCapabilityToProto converts a Go model to a protobuf message.
func UserOnboardCapabilityToProto(m *models.OnboardCapability) *commonpb.UserOnboardCapability {
	if m == nil {
		return nil
	}
	return &commonpb.UserOnboardCapability{
		Provider:   m.Provider,
		Username:   m.Username,
		CanOnboard: m.CanOnboard,
	}
}

// ProtoToUserOnboardCapability converts a protobuf message to a Go model.
func ProtoToUserOnboardCapability(pb *commonpb.UserOnboardCapability) *models.OnboardCapability {
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

// PodStatusToProto converts a Go PodStatus model to its protobuf message.
func PodStatusToProto(m *models.PodStatus) *commonpb.PodStatus {
	if m == nil {
		return nil
	}

	var created *timestamppb.Timestamp
	if !m.Created.IsZero() {
		created = timestamppb.New(m.Created)
	}

	return &commonpb.PodStatus{
		Created:         created,
		Status:          string(m.Status),
		Message:         m.Message,
		Restarts:        m.Restarts,
		LastFailMessage: m.LastFailMessage,
	}
}

// ProtoToPodStatus converts a protobuf PodStatus message to its Go model.
func ProtoToPodStatus(pb *commonpb.PodStatus) *models.PodStatus {
	if pb == nil {
		return nil
	}

	var created time.Time
	if ts := pb.GetCreated(); ts != nil {
		created = ts.AsTime()
	}

	return &models.PodStatus{
		Created:         created,
		Status:          models.WorkspacePodStatus(pb.GetStatus()),
		Message:         pb.GetMessage(),
		Restarts:        pb.GetRestarts(),
		LastFailMessage: pb.GetLastFailMessage(),
	}
}

// WorkspaceDetailsToProto converts a Go WorkspaceDetails model to its protobuf message.
func WorkspaceDetailsToProto(m *models.WorkspaceDetails) *commonpb.WorkspaceDetails {
	if m == nil {
		return nil
	}

	return &commonpb.WorkspaceDetails{
		PodStatus:    PodStatusToProto(&m.PodStatus),
		Name:         m.Name,
		Username:     m.Username,
		Blueprint:    m.Blueprint,
		Organization: m.Organization,
		RepoOwner:    m.RepoOwner,
		RepoName:     m.RepoName,
		RepoRef:      m.RepoRef,
		ServerName:   m.ServerName,
		PodIp:        m.PodIP,
		Port:         int32(m.Port),
		TlsEnabled:   m.TLSEnabled,
		Splash:       m.Splash,
		AppVersion:   m.AppVersion,
		Cpu:          m.CPU,
		Memory:       m.Memory,
		Hostname:     m.Hostname,
		JobId:        m.JobId,
	}
}

// ProtoToWorkspaceDetails converts a protobuf WorkspaceDetails message to its Go model.
func ProtoToWorkspaceDetails(pb *commonpb.WorkspaceDetails) *models.WorkspaceDetails {
	if pb == nil {
		return nil
	}

	return &models.WorkspaceDetails{
		PodStatus:    *ProtoToPodStatus(pb.GetPodStatus()),
		Name:         pb.GetName(),
		Username:     pb.GetUsername(),
		Organization: pb.GetOrganization(),
		RepoOwner:    pb.GetRepoOwner(),
		RepoName:     pb.GetRepoName(),
		RepoRef:      pb.GetRepoRef(),
		Blueprint:    pb.GetBlueprint(),
		ServerName:   pb.GetServerName(),
		PodIP:        pb.GetPodIp(),
		Port:         int(pb.GetPort()),
		TLSEnabled:   pb.GetTlsEnabled(),
		Splash:       pb.GetSplash(),
		AppVersion:   pb.GetAppVersion(),
		CPU:          pb.GetCpu(),
		Memory:       pb.GetMemory(),
		Hostname:     pb.GetHostname(),
		JobId:        pb.GetJobId(),
	}
}

// BlueprintSummaryToProto converts a Go BlueprintSummary model to its protobuf message.
func BlueprintSummaryToProto(m *models.BlueprintSummary) *commonpb.BlueprintSummary {
	if m == nil {
		return nil
	}
	return &commonpb.BlueprintSummary{
		Name:        m.Name,
		Description: m.Description,
		IsTemplate:  m.IsTemplate,
	}
}

// ProtoToBlueprintSummary converts a protobuf BlueprintSummary message to its Go model.
func ProtoToBlueprintSummary(pb *commonpb.BlueprintSummary) *models.BlueprintSummary {
	if pb == nil {
		return nil
	}
	return &models.BlueprintSummary{
		Name:        pb.GetName(),
		Description: pb.GetDescription(),
		IsTemplate:  pb.GetIsTemplate(),
	}
}
