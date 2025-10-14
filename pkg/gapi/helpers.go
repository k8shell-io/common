package gapi

import (
	"time"

	commonpb "github.com/k8shell-io/common/pkg/gapi/commonpb"
	"github.com/k8shell-io/common/pkg/models"
	"google.golang.org/protobuf/types/known/timestamppb"
)

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
