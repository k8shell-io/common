package models

import (
	"errors"
	"slices"
	"time"
)

// OperationCode is a short code identifying the kind of SSH session activity
// (shell, pty, port-forward, sftp, scp, exec, agent-forward, system-exec).
type OperationCode string

const (
	OpShell        OperationCode = "sh"
	OpPty          OperationCode = "pt"
	OpPortForward  OperationCode = "pf"
	OpSFTP         OperationCode = "sf"
	OpSCP          OperationCode = "sc"
	OpExec         OperationCode = "ex"
	OpForwardAgent OperationCode = "af"
	OpSystemExec   OperationCode = "se"
)

// User roles
type Role string

const (
	RoleAdmin          Role = "admin"
	RoleOrgAdmin       Role = "org-admin"
	RoleWorkspaceAdmin Role = "workspace-admin"
	RoleWorkspaceUser  Role = "workspace-user"
)

var ErrMethodNotSupported = errors.New("method not supported")
var ErrUserNotFound = errors.New("user not found")
var ErrActiveSessionNotFound = errors.New("active session not found")
var ErrSessionNotFound = errors.New("session not found")
var ErrUserNotOnboarded = errors.New("user not onboarded")
var ErrUserIsNotValid = errors.New("user is not valid")
var ErrOnboardingPending = errors.New("onboarding pending")
var ErrAlreadyOnboarded = errors.New("user already onboarded")
var ErrUserNotAllowedOnboard = errors.New("user not allowed to onboard")
var ErrUserTokenNotSupported = errors.New("user token not supported by provider")

// User represents a user in the system
type User struct {
	Username     string    `yaml:"username" json:"username"`
	Organization string    `yaml:"organization" json:"organization"`
	IsValid      bool      `yaml:"isValid" json:"isValid"`
	ExpiresAt    time.Time `yaml:"expiresAt" json:"expiresAt"`
	UID          uint32    `yaml:"uid" json:"uid"`
	GID          uint32    `yaml:"gid" json:"gid"`
	Fullname     string    `yaml:"fullname" json:"fullname"`
	Email        string    `yaml:"email" json:"email"`
	Password     string    `yaml:"password,omitempty" json:"password,omitempty"`
	AuthKeys     []string  `yaml:"authKeys" json:"authKeys"`
	Locked       bool      `yaml:"locked" json:"locked"`
	Roles        []Role    `yaml:"roles" json:"roles"`
	Blueprints   []string  `yaml:"blueprints" json:"blueprints"`
	Source       string    `yaml:"source" json:"source"`
	Shell        string    `yaml:"shell" json:"shell"`
	Sudo         bool      `yaml:"sudo" json:"sudo"`
}

func (u *User) HasBlueprint(blueprintName string) bool {
	if len(u.Blueprints) == 0 || !slices.Contains(u.Blueprints, "*") && !slices.Contains(u.Blueprints, blueprintName) {
		return false
	}
	return true
}

// SSHSession represents an SSH session for a user
type SSHSession struct {
	SessionID   string     `yaml:"sessionID" json:"sessionID"`
	Username    string     `yaml:"username" json:"username"`
	K8shelldVer string     `yaml:"k8shelldVer" json:"k8shelldVer"`
	Client      string     `yaml:"client" json:"client"`
	ClientIP    string     `yaml:"clientIP" json:"clientIP"`
	StartTime   *time.Time `yaml:"startTime" json:"startTime"`
	EndTime     *time.Time `yaml:"endTime" json:"endTime"`
	Workspace   string     `yaml:"workspace" json:"workspace"`
	BytesIn     int64      `yaml:"bytesIn" json:"bytesIn"`
	BytesOut    int64      `yaml:"bytesOut" json:"bytesOut"`
	Operations  []string   `yaml:"operations" json:"operations"`
	Blueprint   string     `yaml:"blueprint" json:"blueprint"`
	UpdatedAt   *time.Time `yaml:"updatedAt" json:"updatedAt"`
	PtyName     string     `yaml:"ptyName" json:"ptyName"`
}

// Organization represents an organization in the system
type Organization struct {
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description" json:"description"`
}

// ProviderInfo holds information about a identity provider
type ProviderInfo struct {
	Status          string     `yaml:"status" json:"status"`
	CreatedAt       time.Time  `yaml:"createdAt" json:"createdAt"`
	UpdatedAt       time.Time  `yaml:"updatedAt" json:"updatedAt"`
	Username        string     `yaml:"username" json:"username"`
	Provider        string     `yaml:"provider" json:"provider"`
	UserCode        string     `yaml:"userCode" json:"userCode"`
	DeviceCode      string     `yaml:"deviceCode" json:"deviceCode"`
	ExpiresAt       *time.Time `yaml:"expiresAt" json:"expiresAt"`
	VerificationURI string     `yaml:"verificationURI" json:"verificationURI"`
	AccessToken     string     `yaml:"accessToken" json:"accessToken"`
	RefreshToken    string     `yaml:"refreshToken" json:"refreshToken"`
}

// OnboardUserDeviceFlow represents a user being onboarded via OAuth device flow
type OnboardUserDeviceFlow struct {
	Provider        string `json:"provider"`
	Username        string `json:"username"`
	UserCode        string `json:"userCode"`
	VerificationUrl string `json:"verificationUrl"`
	ExpiresIn       int    `json:"expiresIn"`
}

// OnboardUserWebFlow represents a user being onboarded via OAuth web flow
type OnboardUserWebFlow struct {
	Provider         string `json:"provider"`
	AuthorizationURL string `json:"authorizationUrl"`
	State            string `json:"state"`
	ExpiresIn        int    `json:"expiresIn"`
}

// CompleteUserWebFlow represents the data needed to complete a web onboarding flow
type CompleteUserWebFlow struct {
	Code  string `json:"code"`
	State string `json:"state"`
}

// OnboardCapability represents the capability of a user to onboard
type OnboardCapability struct {
	Provider   string `json:"provider"`
	Username   string `json:"username"`
	CanOnboard bool   `json:"canOnboard"`
}

// UserToken represents a token for a user
type UserToken struct {
	Provider string `json:"provider"`
	Address  string `json:"address"`
	Username string `json:"username"`
	Token    string `json:"token"`
}

// UserCredential represents external service credentials for a user
type UserCredential struct {
	ID               uint32     `json:"id"`
	Username         string     `json:"username"`
	ServiceName      string     `json:"serviceName"`
	ServiceScope     string     `json:"serviceScope"`
	CredentialSource string     `json:"credentialSource"`
	Subject          string     `json:"subject"`
	Secret           string     `json:"secret,omitempty"`
	IsActive         bool       `json:"isActive"`
	CreatedAt        time.Time  `json:"createdAt"`
	UpdatedAt        time.Time  `json:"updatedAt"`
	ExpiresAt        *time.Time `json:"expiresAt,omitempty"`
}
