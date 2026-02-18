package models

import (
	"errors"
	"fmt"
	"time"
)

const WORKSPACE_PORT = 2822 // port that workspace containers listen on for grpc connections

// WorkspacePodStatus is the user-friendly status reported for a workspace pod.
type WorkspacePodStatus string

const (
	WorkspaceStatusProvisioning WorkspacePodStatus = "Starting"
	WorkspaceStatusRunning      WorkspacePodStatus = "Running"
	WorkspaceStatusFailing      WorkspacePodStatus = "Failing"
	WorkspaceStatusTerminating  WorkspacePodStatus = "Terminating"
	WorkspaceStatusStopped      WorkspacePodStatus = "Stopped"
	WorkspaceStatusError        WorkspacePodStatus = "Error"
	WorkspaceStatusUnknown      WorkspacePodStatus = "Unknown"
)

// PodStatus represents the status of a workspace pod
type PodStatus struct {
	Created         time.Time          `json:"created" example:"2025-08-05T10:30:00Z"`
	Status          WorkspacePodStatus `json:"status" example:"Running"`
	Message         string             `json:"message" example:"Workspace is running"`
	Restarts        int32              `json:"restarts" example:"0"`
	LastFailMessage string             `json:"lastFailMessage,omitempty" example:""`
}

// WorkspaceDetails represents the details of a workspace
// It contains information about the workspace pod status and in addition
type WorkspaceDetails struct {
	PodStatus
	AppVersion   string `json:"appVersion" example:"1.0.0"`
	Name         string `json:"name"`
	Username     string `json:"username"`
	RepoOwner    string `json:"repoOwner,omitempty"`
	RepoName     string `json:"repoName,omitempty"`
	RepoRef      string `json:"repoRef,omitempty"`
	Blueprint    string `json:"blueprint"`
	Organization string `json:"organization"`
	CPU          string `json:"cpu" example:"500m"`
	Memory       string `json:"memory" example:"256Mi"`
	ServerName   string `json:"serverName"`
	PodIP        string `json:"podIP"`
	Port         int    `json:"port"`
	TLSEnabled   bool   `json:"tlsEnabled"`
	Splash       string `json:"splash,omitempty"`
	Hostname     string `json:"hostname,omitempty"`
	JobId        string `json:"jobId,omitempty"`
}

// WorkspaceCreateRequest represents workspace resources (CPU and memory)
// It is used when updating the workspace resources via the API
type WorkspaceResources struct {
	CPU    string `json:"cpu" example:"500m"`
	Memory string `json:"memory" example:"256Mi"`
}

type WorkspaceStreamEventType string

const (
	WorkspaceStreamEventTypeEvent    WorkspaceStreamEventType = "event"
	WorkspaceStreamEventTypeStatus   WorkspaceStreamEventType = "status"
	WorkspaceStreamEventTypeProgress WorkspaceStreamEventType = "progress"
)

// StreamEvent represents a streaming event response
type WorkspaceStreamEvent struct {
	Id         int64                    `json:"id" example:"123456789"`
	Type       WorkspaceStreamEventType `json:"type" example:"event"`
	Timestamp  string                   `json:"timestamp,omitempty" example:"2025-08-05T10:30:00Z"`
	ObjectName string                   `json:"objectName,omitempty" example:"dev-user123"`
	Message    string                   `json:"message,omitempty" example:"Pod is starting"`
	Status     WorkspacePodStatus       `json:"status,omitempty" example:"Running"`
}

type ProvisionJobStatus string

const (
	ProvisionJobAccepted  ProvisionJobStatus = "accepted"
	ProvisionJobRunning   ProvisionJobStatus = "running"
	ProvisionJobSucceeded ProvisionJobStatus = "succeeded"
	ProvisionJobFailed    ProvisionJobStatus = "failed"
)

// ProvisionJob represents the state of a workspace provisioning job,
// The provisioning job is stored in a JetStream KV store, and updated as new events are received
// from the provisioner service.
type ProvisionJob struct {
	ID            string                 `json:"id"`
	WorkspaceName string                 `json:"workspaceName,omitempty"`
	Status        ProvisionJobStatus     `json:"status"`
	CreatedAt     time.Time              `json:"createdAt"`
	UpdatedAt     time.Time              `json:"updatedAt"`
	FinishedAt    *time.Time             `json:"finishedAt,omitempty"`
	Error         string                 `json:"error,omitempty"`
	Events        []WorkspaceStreamEvent `json:"events,omitempty"`
}

// ErrWorkspaceNotFound is returned when a workspace is not found
var ErrWorkspaceNotFound = errors.New("workspace not found")

// ErrInvalidParameters is returned when the provided parameters are invalid
var ErrInvalidParameters = errors.New("invalid parameters")

func (e WorkspaceStreamEvent) String() string {
	if e.Type == "event" {
		return fmt.Sprintf("[%s] [%-12s] %s",
			e.Timestamp, e.ObjectName, e.Message)
	}
	if e.Type == "status" {
		return fmt.Sprintf("[%s] [%-12s] %s: %s",
			e.Timestamp, e.ObjectName, e.Status, e.Message)
	}
	return ""
}
