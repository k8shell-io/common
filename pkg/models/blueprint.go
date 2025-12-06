package models

import (
	"bytes"
	"fmt"
	"time"

	"github.com/go-playground/validator/v10"
	v "github.com/k8shell-io/common/pkg/validator"
	"gopkg.in/yaml.v3"
)

// Blueprint represents a single blueprint configuration
type Blueprint struct {
	Metadata        BlueprintMetadata
	Name            string              `yaml:"name" validate:"required,min=1,max=40"`
	IsTemplate      bool                `yaml:"isTemplate,omitempty"`
	Splash          string              `yaml:"splash,omitempty"`
	Template        string              `yaml:"template"`
	Shell           string              `yaml:"shell" validate:"required"`
	Hostname        string              `yaml:"hostname,omitempty" validate:"omitempty,plainhostname"`
	Subdomain       string              `yaml:"subdomain,omitempty" validate:"omitempty,plainhostname"`
	Sudo            bool                `yaml:"sudo" default:"false"`
	Image           string              `yaml:"image" validate:"required"`
	ImagePullSecret string              `yaml:"imagePullSecret,omitempty"`
	ImagePullPolicy string              `yaml:"imagePullPolicy,omitempty" validate:"omitempty,oneof=Always Never IfNotPresent"`
	K8shelld        K8shelld            `yaml:"k8shelld" validate:"required"`
	Env             map[string]string   `yaml:"env,omitempty"`
	PortForwarding  []string            `yaml:"portForwarding,omitempty"`
	Network         Network             `yaml:"network" validate:"required"`
	Resources       Resources           `yaml:"resources" validate:"required"`
	Docker          Docker              `yaml:"docker" validate:"required"`
	Storages        map[string]Storage  `yaml:"storages" validate:"required,min=1,dive"`
	InitScripts     []map[string]string `yaml:"initScripts,omitempty"`
	Capabilities    []string            `yaml:"capabilities,omitempty" validate:"omitempty,dive,oneof=NET_ADMIN NET_BIND_SERVICE NET_RAW SYS_ADMIN SYS_TIME SYS_MODULE SYS_RAWIO DAC_OVERRIDE FOWNER SETUID SETGID KILL CHOWN"`
	ExtFiles        map[string]string   `yaml:"extFiles,omitempty"`
	EnableApps      bool                `yaml:"enableApps,omitempty"`
	Apps            map[string]AppSpec  `yaml:"apps,omitempty" validate:"omitempty,dive,keys,required,endkeys,required"`
}

// K8shellFile represents the overall structure of a k8shell YAML file
type K8shellFile struct {
	Blueprint CustomBlueprint `yaml:"blueprint" validate:"required"`
}

// CustomBlueprint represents a custom blueprint configuration
type CustomBlueprint struct {
	Metadata       BlueprintMetadata
	Name           string              `yaml:"name,omitempty"`
	Template       string              `yaml:"template" validate:"required"`
	Splash         string              `yaml:"splash,omitempty"`
	Shell          string              `yaml:"shell,omitempty"`
	Sudo           bool                `yaml:"sudo,omitempty"`
	Image          string              `yaml:"image,omitempty"`
	Env            map[string]string   `yaml:"env,omitempty"`
	PortForwarding []string            `yaml:"portForwarding,omitempty"`
	Network        Network             `yaml:"network,omitempty"`
	Resources      Resources           `yaml:"resources,omitempty"`
	Storages       map[string]Storage  `yaml:"storages,omitempty"`
	InitScripts    []map[string]string `yaml:"initScripts,omitempty"`
	EnableApps     bool                `yaml:"enableApps,omitempty"`
	Apps           map[string]AppSpec  `yaml:"apps,omitempty"`
}

// BlueprintMetadata holds metadata information for a blueprint.
type BlueprintMetadata struct {
	Name        string `yaml:"name"`
	RepoName    string `yaml:"repoName"`
	RepoOwner   string `yaml:"repoOwner"`
	RepoAddress string `yaml:"repoAddress"`
}

type Conn struct {
	AllowAnyNS bool `yaml:"allowAnyNS,omitempty"`
	AllowAnySA bool `yaml:"allowAnySA,omitempty"`
}

// K8shelld represents k8shelld configuration
type K8shelld struct {
	Image           string   `yaml:"image" validate:"required"`
	ImagePullPolicy string   `yaml:"imagePullPolicy,omitempty" validate:"omitempty,oneof=Always Never IfNotPresent"`
	IgnoreOrphans   []string `yaml:"ignoreOrphans,omitempty"`
	Connection      Conn     `yaml:"connection,omitempty"`
}

// Network represents network configuration
type Network struct {
	NetworkPolicy string   `yaml:"networkPolicy,omitempty" validate:"oneof=workspace system isolated user organization"`
	AllowEgress   []string `yaml:"allowEgress,omitempty" validate:"dive,cidr"`
}

// Resources represents resource limits
type Resources struct {
	CPU    string `yaml:"cpu" validate:"required"`
	Memory string `yaml:"memory" validate:"required"`
}

// Docker represents Docker configuration
type Docker struct {
	Enabled        bool               `yaml:"enabled"`
	Image          string             `yaml:"image" validate:"required_if=Enabled true"`
	Resources      Resources          `yaml:"resources" validate:"required_if=Enabled true"`
	GroupID        int                `yaml:"groupId" validate:"min=0,max=65535"`
	SubGID         int                `yaml:"subgid" validate:"min=0"`
	ParentStorages bool               `yaml:"parentStorages"`
	ExtFiles       map[string]string  `yaml:"extFiles,omitempty"`
	Storages       map[string]Storage `yaml:"storages,omitempty"`
}

// Storage represents storage configuration
type Storage struct {
	Enabled      bool              `yaml:"enabled"`
	StorageClass string            `yaml:"storageClass" validate:"required_if=Enabled true"`
	Size         string            `yaml:"size" validate:"required_if=Enabled true"`
	Path         string            `yaml:"path" validate:"required_if=Enabled true,startswith=/"`
	Readonly     bool              `yaml:"readonly"`
	Annotations  map[string]string `yaml:"annotations,omitempty"`
}

type AppSpec struct {
	Enabled           bool          `yaml:"enabled"`
	Name              string        `yaml:"name"`
	Binary            string        `yaml:"binary" validate:"required_if=Enabled true"`
	VersionCmd        []string      `yaml:"versionCmd,omitempty" validate:"required_if=Enabled true"`
	VersionRegex      string        `yaml:"versionRegex,omitempty" validate:"required_if=Enabled true"`
	Install           string        `yaml:"install" validate:"required_if=Enabled true"`
	Start             []string      `yaml:"start" validate:"required_if=Enabled true"`
	Listen            int           `yaml:"listen" validate:"required_if=Enabled true,min=1,max=65535"`
	RestartPolicy     string        `yaml:"restartPolicy" validate:"omitempty,oneof=always on-failure never"`
	MaxRestartBackoff time.Duration `yaml:"maxRestartBackoff"`
	InstallAsRoot     bool          `yaml:"installAsRoot"`
	AutoStart         bool          `yaml:"autoStart,omitempty"`
}

type Repo struct {
	Address string `yaml:"address" validate:"required"`
	Name    string `yaml:"name" validate:"required"`
	Owner   string `yaml:"owner" validate:"required"`
}

// Validate validates the blueprint and returns user-friendly errors
func (b *Blueprint) Validate() v.Validator {
	return v.NewValidator(b)
}

func ValidateK8shellFile(k8shellFile K8shellFile) (*CustomBlueprint, []string) {
	blueprintOnlyYAML, err := yaml.Marshal(k8shellFile.Blueprint)
	if err != nil {
		return nil, []string{
			fmt.Sprintf("Failed to process blueprint data: %v", err),
		}
	}

	var customBp CustomBlueprint
	decoder := yaml.NewDecoder(bytes.NewReader(blueprintOnlyYAML))
	decoder.KnownFields(true)
	if err := decoder.Decode(&customBp); err != nil {
		return nil, []string{
			fmt.Sprintf("Failed to decode blueprint: %v", err),
		}
	}

	validate := validator.New()
	v.RegisterCustomValidators(validate)
	if err := validate.Struct(customBp); err != nil {
		var validationErrors []string
		for _, err := range err.(validator.ValidationErrors) {
			validationErrors = append(validationErrors,
				fmt.Sprintf("Field '%s' failed validation: %s", err.Field(), err.Tag()))
		}
		return nil, validationErrors
	}
	return &customBp, nil
}
