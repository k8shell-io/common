package k8shelld

import (
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
	TerminateOrphans TerminateOrphans `yaml:"terminateOrphans"`
	ReapZombies      ReapZombies      `yaml:"reapZombies"`
	Shells           Shells           `yaml:"shells,omitempty"`
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

// Shells holds shell session configuration.
type Shells struct {
	// DetachedTTL controls how long a PTY shell session with no attached
	// client is kept alive before the GC terminates it.
	// Accepts Go duration strings (e.g. "30m", "1h").
	// When empty the server falls back to its built-in default (30m).
	// Set to "0s" to disable automatic termination entirely.
	DetachedTTL string `yaml:"detachedTTL,omitempty"`

	// AllowUnlimittedTTL controls whether clients are allowed to set an unlimitted TTL for detached sessions.
	AllowUnlimittedTTL bool `yaml:"allowUnlimittedTTL"`

	// AllowSessionDetach controls whether clients are allowed to detach from PTY shell sessions.
	AllowSessionDetach bool `yaml:"allowSessionDetach"`
}
