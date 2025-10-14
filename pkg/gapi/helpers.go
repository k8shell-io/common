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
		Created: created,
		Status:  m.Status,
		Message: m.Message,
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
		Created: created,
		Status:  pb.GetStatus(),
		Message: pb.GetMessage(),
	}
}

// WorkspaceStatusToProto converts a Go WorkspaceStatus model to its protobuf message.
func WorkspaceStatusToProto(m *models.WorkspaceStatus) *commonpb.WorkspaceStatus {
	if m == nil {
		return nil
	}

	return &commonpb.WorkspaceStatus{
		PodStatus: PodStatusToProto(&m.PodStatus),
		Name:      m.Name,
		Host:      m.Host,
		PodIp:     m.PodIP,
		Port:      int32(m.Port),
		AccessKey: m.AccessKey,
		TlsCert:   m.TLSCert,
		Splash:    m.Splash,
	}
}

// ProtoToWorkspaceStatus converts a protobuf WorkspaceStatus message to its Go model.
func ProtoToWorkspaceStatus(pb *commonpb.WorkspaceStatus) *models.WorkspaceStatus {
	if pb == nil {
		return nil
	}

	return &models.WorkspaceStatus{
		PodStatus: *ProtoToPodStatus(pb.GetPodStatus()),
		Name:      pb.GetName(),
		Host:      pb.GetHost(),
		PodIP:     pb.GetPodIp(),
		Port:      int(pb.GetPort()),
		AccessKey: pb.GetAccessKey(),
		TLSCert:   pb.GetTlsCert(),
		Splash:    pb.GetSplash(),
	}
}

// WorkspaceInfoToProto converts a Go WorkspaceInfo model to its protobuf message.
func WorkspaceInfoToProto(m *models.WorkspaceInfo) *commonpb.WorkspaceInfo {
	if m == nil {
		return nil
	}

	var deployed *timestamppb.Timestamp
	if !m.Deployed.IsZero() {
		deployed = timestamppb.New(m.Deployed)
	}

	return &commonpb.WorkspaceInfo{
		Name:      m.Name,
		Username:  m.Username,
		Blueprint: m.Blueprint,
		Deployed:  deployed,
	}
}

// ProtoToWorkspaceInfo converts a protobuf WorkspaceInfo message to its Go model.
func ProtoToWorkspaceInfo(pb *commonpb.WorkspaceInfo) *models.WorkspaceInfo {
	if pb == nil {
		return nil
	}

	var deployed time.Time
	if ts := pb.GetDeployed(); ts != nil {
		deployed = ts.AsTime()
	}

	return &models.WorkspaceInfo{
		Name:      pb.GetName(),
		Username:  pb.GetUsername(),
		Blueprint: pb.GetBlueprint(),
		Deployed:  deployed,
	}
}
