package k8shelld

import (
	"time"

	"github.com/k8shell-io/common/pkg/gapi"
)

// Identity holds the configuration required to load and verify the workspace
// identity JWT at startup and during periodic renewal checks.
type Identity struct {
	TokenPath     string `yaml:"tokenPath"`
	PublicKeyPath string `yaml:"publicKeyPath"`
	SigningMethod string `yaml:"signingMethod"`
}

// Config is the root structure of k8shelld's config.yaml.
type Config struct {
	System           System           `yaml:"system"`
	Identity         Identity         `yaml:"identity"`
	Splash           string           `yaml:"splash,omitempty"`
	TerminateOrphans TerminateOrphans `yaml:"terminateOrphans"`
	ReapZombies      ReapZombies      `yaml:"reapZombies"`
	Podman           PodmanConfig     `yaml:"podman"`
	InitScriptsDir   string           `yaml:"initScriptsDir,omitempty"`
	EnableApps       bool             `yaml:"enableApps"`
	Apps             Apps             `yaml:"apps,omitempty"`
}

// System represents the general system configuration.
type System struct {
	PProf      bool              `yaml:"pprof"`
	LogLevel   string            `yaml:"logLevel,omitempty"`
	ApiServer  ApiServer         `yaml:"apiServer"`
	GrpcConfig gapi.ServerConfig `yaml:"grpc"`
}

// ApiServer holds the API server address and enable flag.
type ApiServer struct {
	Enabled bool   `yaml:"enabled"`
	Address string `yaml:"address"`
}

// TerminateOrphans represents the configuration for the terminate-orphans feature.
type TerminateOrphans struct {
	Enabled       bool     `yaml:"enabled"`
	CheckInterval int      `yaml:"checkInterval"`
	Exclude       []string `yaml:"exclude,omitempty"`
}

// ReapZombies represents the configuration for the reap-zombies feature.
type ReapZombies struct {
	Enabled bool `yaml:"enabled"`
}

// PodmanConfig holds Podman runtime settings written into config.yaml.
// This is distinct from the blueprint's Podman spec (models.Podman).
type PodmanConfig struct {
	Enabled                 bool `yaml:"enabled"`
	CreateDockerSockSymlink bool `yaml:"createDockerSockSymlink"`
}

// Apps is a map of app name to AppSpec, matching k8shelld's Apps type.
type Apps map[string]*AppSpec

// AppSpec represents the specification for a single app in k8shelld.
// Note: the Enabled field is part of the blueprint's AppSpec, not the config file spec.
type AppSpec struct {
	Name              string        `yaml:"name,omitempty"`
	Binary            string        `yaml:"binary"`
	VersionCmd        []string      `yaml:"versionCmd,omitempty"`
	VersionRegex      string        `yaml:"versionRegex,omitempty"`
	Install           string        `yaml:"install,omitempty"`
	Start             []string      `yaml:"start,omitempty"`
	Listen            int           `yaml:"listen,omitempty"`
	RestartPolicy     string        `yaml:"restartPolicy,omitempty"`
	MaxRestartBackoff time.Duration `yaml:"maxRestartBackoff,omitempty"`
	InstallAsRoot     bool          `yaml:"installAsRoot"`
	AutoStart         bool          `yaml:"autoStart"`
	Protocol          string        `yaml:"protocol,omitempty"`
}
