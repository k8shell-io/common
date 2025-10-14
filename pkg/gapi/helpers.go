package gapi

import (
	commonpb "github.com/k8shell-io/common/pkg/gapi/commonpb"
	"github.com/k8shell-io/common/pkg/models"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func UserToProto(user *models.User) *commonpb.User {
	return &commonpb.User{
		Username:     user.Username,
		Organization: user.Organization,
		IsValid:      user.IsValid,
		ExpiresAt:    timestamppb.New(user.ExpiresAt),
		Uid:          int32(user.UID),
		Gid:          int32(user.GID),
		Fullname:     user.Fullname,
		AccessToken:  user.AccessToken,
		Email:        user.Email,
		Password:     user.Password,
		Auths:        user.Auths,
		AuthKeys:     user.AuthKeys,
		Locked:       user.Locked,
		FailedLogins: int32(user.FailedLogins),
		Channels:     user.Channels,
		Envs:         user.Envs,
		Roles:        user.Roles,
		Blueprints:   user.Blueprints,
		Source:       user.Source,
	}
}

func ProtoToUser(pb *commonpb.User) *models.User {
	return &models.User{
		Username:     pb.GetUsername(),
		Organization: pb.GetOrganization(),
		IsValid:      pb.GetIsValid(),
		ExpiresAt:    pb.GetExpiresAt().AsTime(),
		UID:          uint32(pb.GetUid()),
		GID:          uint32(pb.GetGid()),
		Fullname:     pb.GetFullname(),
		AccessToken:  pb.GetAccessToken(),
		Email:        pb.GetEmail(),
		Password:     pb.GetPassword(),
		Auths:        pb.GetAuths(),
		AuthKeys:     pb.GetAuthKeys(),
		Locked:       pb.GetLocked(),
		FailedLogins: int(pb.GetFailedLogins()),
		Channels:     pb.GetChannels(),
		Envs:         pb.GetEnvs(),
		Roles:        pb.GetRoles(),
		Blueprints:   pb.GetBlueprints(),
		Source:       pb.GetSource(),
	}
}
