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
	InitScriptsDir   string           `yaml:"initScriptsDir,omitempty"`
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
