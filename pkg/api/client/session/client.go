package session

import (
	"math"
	"time"

	sessionv1 "github.com/k8shell-io/common/pkg/api/gen/go/session/v1"
	"github.com/k8shell-io/common/pkg/gapi"
	"github.com/k8shell-io/common/pkg/models"
)

type Client struct {
	sessionv1.SessionServiceClient
	sessionv1.RecordingServiceClient
}

func NewClient(cfg gapi.ClientConfig) (*Client, error) {
	gapiClient, err := gapi.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return &Client{
		SessionServiceClient:   sessionv1.NewSessionServiceClient(gapiClient.Conn),
		RecordingServiceClient: sessionv1.NewRecordingServiceClient(gapiClient.Conn),
	}, nil
}

// ToProtobufSession converts a models.SSHSession to a sessionv1.Session
func ToProtobufSession(session *models.SSHSession) *sessionv1.Session {
	var startTime, endTime, updatedAt int64

	if session.StartTime != nil {
		startTime = session.StartTime.Unix()
	}
	if session.EndTime != nil {
		endTime = session.EndTime.Unix()
	}
	if session.UpdatedAt != nil {
		updatedAt = session.UpdatedAt.Unix()
	}

	return &sessionv1.Session{
		SessionId:      session.SessionID,
		Username:       session.Username,
		K8ShelldVer:    session.K8shelldVer,
		Client:         session.Client,
		ClientIp:       session.ClientIP,
		StartTime:      startTime,
		EndTime:        endTime,
		Workspace:      session.Workspace,
		BytesIn:        session.BytesIn,
		BytesOut:       session.BytesOut,
		Operations:     session.Operations,
		Blueprint:      session.Blueprint,
		Recordings:     toProtobufRecordingRefs(session.Recordings),
		ExecRecordings: int32(min(session.ExecRecordings, math.MaxInt32)), // #nosec G115 -- clamped
		UpdatedAt:      updatedAt,
	}
}

// FromProtobufSession converts a sessionv1.Session to a models.SSHSession
func FromProtobufSession(pbSession *sessionv1.Session) *models.SSHSession {
	session := &models.SSHSession{
		SessionID:      pbSession.SessionId,
		Username:       pbSession.Username,
		K8shelldVer:    pbSession.K8ShelldVer,
		Client:         pbSession.Client,
		ClientIP:       pbSession.ClientIp,
		Workspace:      pbSession.Workspace,
		BytesIn:        pbSession.BytesIn,
		BytesOut:       pbSession.BytesOut,
		Operations:     pbSession.Operations,
		Blueprint:      pbSession.Blueprint,
		Recordings:     FromProtobufRecordingRefs(pbSession.Recordings),
		ExecRecordings: int(pbSession.ExecRecordings),
	}

	// Convert Unix timestamps back to time.Time pointers
	if pbSession.StartTime > 0 {
		startTime := time.Unix(pbSession.StartTime, 0)
		session.StartTime = &startTime
	}
	if pbSession.EndTime > 0 {
		endTime := time.Unix(pbSession.EndTime, 0)
		session.EndTime = &endTime
	}
	if pbSession.UpdatedAt > 0 {
		updatedAt := time.Unix(pbSession.UpdatedAt, 0)
		session.UpdatedAt = &updatedAt
	}

	return session
}

// recordingTypes maps model recording types to their protobuf enum.
var recordingTypes = map[string]sessionv1.RecordingType{
	"shell":           sessionv1.RecordingType_RECORDING_TYPE_SHELL,
	"exec":            sessionv1.RecordingType_RECORDING_TYPE_EXEC,
	"tcpip":           sessionv1.RecordingType_RECORDING_TYPE_TCPIP,
	"sftp":            sessionv1.RecordingType_RECORDING_TYPE_SFTP,
	"vscode_terminal": sessionv1.RecordingType_RECORDING_TYPE_VSCODE_TERMINAL,
}

// RecordingTypeToProto converts a recording type name ("shell", "exec",
// "tcpip", "sftp") to its protobuf enum; unknown names map to UNSPECIFIED.
func RecordingTypeToProto(t string) sessionv1.RecordingType {
	return recordingTypes[t]
}

// RecordingTypeFromProto converts a protobuf recording type to its name, or
// "" for UNSPECIFIED and unknown values.
func RecordingTypeFromProto(t sessionv1.RecordingType) string {
	for name, v := range recordingTypes {
		if v == t {
			return name
		}
	}
	return ""
}

func toProtobufRecordingRefs(refs []models.SessionRecordingRef) []*sessionv1.RecordingRef {
	if len(refs) == 0 {
		return nil
	}
	out := make([]*sessionv1.RecordingRef, len(refs))
	for i, r := range refs {
		out[i] = &sessionv1.RecordingRef{
			RecordingId:       r.ID,
			Type:              RecordingTypeToProto(r.Type),
			ParentRecordingId: r.ParentRecordingID,
		}
	}
	return out
}

// FromProtobufRecordingRefs converts protobuf recording references to models.
func FromProtobufRecordingRefs(refs []*sessionv1.RecordingRef) []models.SessionRecordingRef {
	if len(refs) == 0 {
		return nil
	}
	out := make([]models.SessionRecordingRef, len(refs))
	for i, r := range refs {
		out[i] = models.SessionRecordingRef{
			ID:                r.GetRecordingId(),
			Type:              RecordingTypeFromProto(r.GetType()),
			ParentRecordingID: r.GetParentRecordingId(),
		}
	}
	return out
}
