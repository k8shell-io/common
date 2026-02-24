package models

import (
	"errors"
	"slices"
	"time"
)

const (
	ChannelSession      string = "session"
	ChannelShell        string = "shell"
	ChannelPty          string = "pty"
	ChannelPortForward  string = "port-forward"
	ChannelSFTP         string = "sftp"
	ChannelSCP          string = "scp"
	ChannelExec         string = "exec"
	ChannelForwardAgent string = "forward-agent"
	ChannelSystemExec   string = "system-exec"
)

const (
	ChannelShortSh string = "sh"
	ChannelShortPt string = "pt"
	ChannelShortPf string = "pf"
	ChannelShortSf string = "sf"
	ChannelShortSc string = "sc"
	ChannelShortEx string = "ex"
	ChannelShortAf string = "af"
	ChannelShortSe string = "se"
)

const (
	RoleAdmin          string = "admin"
	RoleOrgAdmin       string = "org-admin"
	RoleWorkspaceAdmin string = "workspace-admin"
	RoleWorkspaceUser  string = "workspace-user"
)

const (
	AuthMethodPublicKey string = "publickey"
	AuthMethodPassword  string = "password"
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
	Username     string    `yaml:"username"`
	Organization string    `yaml:"organization"`
	IsValid      bool      `yaml:"isValid"`
	ExpiresAt    time.Time `yaml:"expiresAt"`
	UID          uint32    `yaml:"uid"`
	GID          uint32    `yaml:"gid"`
	Fullname     string    `yaml:"fullname"`
	AccessToken  string    `yaml:"accessToken"`
	Email        string    `yaml:"email"`
	Password     string    `yaml:"password,omitempty"`
	Auths        []string  `yaml:"auths"`
	AuthKeys     []string  `yaml:"authKeys"`
	Locked       bool      `yaml:"locked"`
	FailedLogins uint32    `yaml:"failedLogins"`
	Channels     []string  `yaml:"channels"`
	Envs         []string  `yaml:"envs"`
	Roles        []string  `yaml:"roles"`
	Blueprints   []string  `yaml:"blueprints"`
	Source       string    `yaml:"source"`
}

func (u *User) HasBlueprint(blueprintName string) bool {
	if len(u.Blueprints) == 0 || !slices.Contains(u.Blueprints, "*") && !slices.Contains(u.Blueprints, blueprintName) {
		return false
	}
	return true
}

// SSHSession represents an SSH session for a user
type SSHSession struct {
	SessionID   string     `yaml:"sessionID"`
	Username    string     `yaml:"username"`
	K8shelldVer string     `yaml:"k8shelldVer"`
	Client      string     `yaml:"client"`
	ClientIP    string     `yaml:"clientIP"`
	StartTime   *time.Time `yaml:"startTime"`
	EndTime     *time.Time `yaml:"endTime"`
	Workspace   string     `yaml:"workspace"`
	BytesIn     int64      `yaml:"bytesIn"`
	BytesOut    int64      `yaml:"bytesOut"`
	Channels    []string   `yaml:"channels"`
	Blueprint   string     `yaml:"blueprint"`
	UpdatedAt   *time.Time `yaml:"updatedAt"`
}

// Organization represents an organization in the system
type Organization struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
}

// ProviderInfo holds information about a identity provider
type ProviderInfo struct {
	Status          string     `yaml:"status"`
	CreatedAt       time.Time  `yaml:"createdAt"`
	UpdatedAt       time.Time  `yaml:"updatedAt"`
	Username        string     `yaml:"username"`
	Provider        string     `yaml:"provider"`
	UserCode        string     `yaml:"userCode"`
	DeviceCode      string     `yaml:"deviceCode"`
	ExpiresAt       *time.Time `yaml:"expiresAt"`
	VerificationURI string     `yaml:"verificationURI"`
	AccessToken     string     `yaml:"accessToken"`
	RefreshToken    string     `yaml:"refreshToken"`
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

// ExternalCredential represents external service credentials for a user
type ExternalCredential struct {
	ID            uint64 `json:"id"`
	Username      string `json:"username"`
	ServiceName   string `json:"serviceName"`
	ServiceURL    string `json:"serviceUrl"`
	ExternalID    string `json:"externalId"`
	ExternalToken string `json:"externalToken"`
}
