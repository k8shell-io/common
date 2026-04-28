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
	Name            string                 `yaml:"name" validate:"required,min=1,max=40"`
	Description     string                 `yaml:"description,omitempty" validate:"max=500"`
	IsTemplate      bool                   `yaml:"isTemplate,omitempty" default:"false"`
	Splash          string                 `yaml:"splash,omitempty"`
	Template        string                 `yaml:"template"`
	Hostname        string                 `yaml:"hostname,omitempty" validate:"omitempty,plainhostname"`
	Subdomain       string                 `yaml:"subdomain,omitempty" validate:"omitempty,plainhostname"`
	Image           string                 `yaml:"image" validate:"required"`
	ImagePullSecret string                 `yaml:"imagePullSecret,omitempty"`
	ImagePullPolicy string                 `yaml:"imagePullPolicy,omitempty" validate:"omitempty,oneof=Always Never IfNotPresent"`
	K8shelld        K8shelld               `yaml:"k8shelld" validate:"required"`
	Env             map[string]string      `yaml:"env,omitempty" default:"{}"`
	Network         Network                `yaml:"network,omitempty" default:"{networkPolicyClass:workspace}"`
	Resources       Resources              `yaml:"resources,omitempty" default:"{limits:{cpu:500m,memory:512Mi}}"`
	Podman          Podman                 `yaml:"podman,omitempty" default:"{enabled:false}"`
	Storages        map[string]Storage     `yaml:"storages,omitempty" default:"{}"`
	InitScripts     []InitScript           `yaml:"initScripts,omitempty" default:"[]"`
	SecurityContext map[string]interface{} `yaml:"securityContext,omitempty" default:"{}"`
	ExtFiles        map[string]string      `yaml:"extFiles,omitempty" default:"{}"`
	EnableApps      bool                   `yaml:"enableApps,omitempty" default:"false"`
	Apps            map[string]AppSpec     `yaml:"apps,omitempty" default:"{}"`
}

// BlueprintMetadata holds metadata information for a blueprint.
type BlueprintMetadata struct {
	Name        string `yaml:"name"`
	RepoName    string `yaml:"repoName"`
	RepoRef     string `yaml:"repoRef"`
	RepoOwner   string `yaml:"repoOwner"`
	RepoAddress string `yaml:"repoAddress"`
}

// K8shellFile represents the overall structure of a k8shell YAML file
type K8shellFile struct {
	Blueprint CustomBlueprint `yaml:"blueprint" validate:"required"`
}

// CustomBlueprint represents a custom blueprint configuration
type CustomBlueprint struct {
	Metadata    BlueprintMetadata
	Name        string             `yaml:"name,omitempty"`
	Template    string             `yaml:"template" validate:"required"`
	Splash      string             `yaml:"splash,omitempty"`
	Image       string             `yaml:"image,omitempty"`
	Env         map[string]string  `yaml:"env,omitempty"`
	Network     Network            `yaml:"network,omitempty"`
	Resources   Resources          `yaml:"resources,omitempty"`
	Storages    map[string]Storage `yaml:"storages,omitempty"`
	InitScripts []InitScript       `yaml:"initScripts,omitempty"`
	EnableApps  bool               `yaml:"enableApps,omitempty"`
	Apps        map[string]AppSpec `yaml:"apps,omitempty"`
}

type BlueprintSummary struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	IsTemplate  bool   `json:"isTemplate,omitempty"`
}

// InitScript represents a named initialization script
type InitScript struct {
	Name   string `yaml:"name" validate:"required"`
	Script string `yaml:"script" validate:"required"`
}

type Conn struct {
	AllowAnyNS bool `yaml:"allowAnyNS,omitempty"`
	AllowAnySA bool `yaml:"allowAnySA,omitempty"`
}

// K8shelld represents k8shelld configuration
type K8shelld struct {
	Image           string   `yaml:"image" validate:"required"`
	ImagePullPolicy string   `yaml:"imagePullPolicy,omitempty" validate:"omitempty,oneof=Always Never IfNotPresent"`
	IgnoreOrphans   []string `yaml:"ignoreOrphans,omitempty" default:"[]"`
	Connection      Conn     `yaml:"connection,omitempty"`
}

// Network defines network policy and egress rules for a workspace.
type Network struct {
	// NetworkPolicyClass selects a predefined network policy class (workspace, system, isolated, user, organization).
	NetworkPolicyClass string `yaml:"networkPolicyClass,omitempty" validate:"oneof=workspace system isolated user organization"`
	// NetworkPolicySpec holds a raw Kubernetes NetworkPolicy spec (or CNI-extended spec such as Cilium).
	// When set, it is applied as-is and takes precedence over the NetworkPolicy class for fine-grained control.
	NetworkPolicySpec map[string]interface{} `yaml:"networkPolicySpec,omitempty"`
	// AllowEgressToCIDRs is a convenience shorthand for permitting egress to specific CIDR ranges.
	AllowEgressToCIDRs []string `yaml:"allowEgressToCIDRs,omitempty" validate:"dive,cidr"`
	// AllowEgressToPods is a convenience shorthand for permitting egress to pods matching label selectors.
	AllowEgressToPods []map[string]string `yaml:"allowEgressToPods,omitempty"`
}

// Resources represents resource limits
type Resources struct {
	CPU    string `yaml:"cpu" validate:"required"`
	Memory string `yaml:"memory" validate:"required"`
}

// Podman represents Podman configuration
type Podman struct {
	Enabled                 bool                   `yaml:"enabled" default:"false"`
	Image                   string                 `yaml:"image" validate:"required_if=Enabled true"`
	Resources               Resources              `yaml:"resources" default:"{cpu:500m,memory:512Mi}"`
	CreateDockerSockSymlink bool                   `yaml:"createDockerSockSymlink" default:"false"`
	ParentStorages          bool                   `yaml:"parentStorages" default:"true"`
	ExtFiles                map[string]string      `yaml:"extFiles,omitempty" default:"{}"`
	Storages                map[string]Storage     `yaml:"storages,omitempty" default:"{}"`
	SecurityContext         map[string]interface{} `yaml:"securityContext,omitempty" default:"{}"`
}

// Storage represents storage configuration
type Storage struct {
	Enabled              bool                   `yaml:"enabled" default:"false"`
	Id                   string                 `yaml:"id,omitempty" validate:"omitempty,alphanum"`
	Type                 string                 `yaml:"type,omitempty" validate:"omitempty,oneof=local shared" default:"local"`
	Path                 string                 `yaml:"path" validate:"required_if=Enabled true,startswith=/"`
	Readonly             bool                   `yaml:"readonly" default:"false"`
	ExistingClaim        string                 `yaml:"existingClaim,omitempty" validate:"required_if=Type shared Enabled true"`
	FsOwnerUid           int                    `yaml:"fsOwnerUid,omitempty" default:"0"`
	FsOwnerGid           int                    `yaml:"fsOwnerGid,omitempty" default:"0"`
	ClaimSpec            map[string]interface{} `yaml:"claimSpec,omitempty" default:"{}"`
	ClaimSpecAnnotations map[string]string      `yaml:"claimSpecAnnotations,omitempty" default:"{}"`
}

type AppSpec struct {
	Name              string        `yaml:"name" validate:"required_if=Enabled true"`
	Enabled           bool          `yaml:"enabled" default:"false"`
	Binary            string        `yaml:"binary" validate:"required_if=Enabled true"`
	VersionCmd        []string      `yaml:"versionCmd,omitempty"`
	VersionRegex      string        `yaml:"versionRegex,omitempty"`
	Install           string        `yaml:"install,omitempty"`
	Start             []string      `yaml:"start" validate:"required_if=Enabled true"`
	Listen            int           `yaml:"listen,omitempty"`
	RestartPolicy     string        `yaml:"restartPolicy,omitempty" validate:"oneof=always on-failure never"`
	MaxRestartBackoff time.Duration `yaml:"maxRestartBackoff,omitempty"`
	InstallAsRoot     bool          `yaml:"installAsRoot,omitempty" default:"false"`
	AutoStart         bool          `yaml:"autoStart,omitempty" default:"false"`
	Protocol          string        `yaml:"protocol,omitempty" validate:"omitempty,oneof=http https ws wss tcp udp"`
}

// type Repo struct {
// 	Address string `yaml:"address" validate:"required"`
// 	Name    string `yaml:"name" validate:"required"`
// 	Owner   string `yaml:"owner" validate:"required"`
// }

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

	if customBp.Storages == nil {
		customBp.Storages = map[string]Storage{}
	}
	if customBp.Env == nil {
		customBp.Env = map[string]string{}
	}
	if customBp.Apps == nil {
		customBp.Apps = map[string]AppSpec{}
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
