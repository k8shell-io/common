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
	Metadata             BlueprintMetadata      `yaml:"metadata" json:"metadata"`
	Name                 string                 `yaml:"name" json:"name" validate:"required,min=1,max=40" jsonschema:"required"`
	Description          string                 `yaml:"description,omitempty" json:"description,omitempty" validate:"max=500"`
	IsTemplate           bool                   `yaml:"isTemplate,omitempty" json:"isTemplate,omitempty" default:"false"`
	Splash               string                 `yaml:"splash,omitempty" json:"splash,omitempty"`
	Template             string                 `yaml:"template" json:"template"`
	Hostname             string                 `yaml:"hostname,omitempty" json:"hostname,omitempty" validate:"omitempty,plainhostname"`
	Subdomain            string                 `yaml:"subdomain,omitempty" json:"subdomain,omitempty" validate:"omitempty,plainhostname"`
	Image                string                 `yaml:"image" json:"image" validate:"required" jsonschema:"required"`
	ImagePullPolicy      string                 `yaml:"imagePullPolicy,omitempty" json:"imagePullPolicy,omitempty" validate:"omitempty,oneof=Always Never IfNotPresent" jsonschema:"enum=Always,enum=Never,enum=IfNotPresent"`
	K8shelld             K8shelld               `yaml:"k8shelld" json:"k8shelld" validate:"required" jsonschema:"required"`
	Env                  map[string]string      `yaml:"env,omitempty" json:"env,omitempty" default:"{}"`
	Network              Network                `yaml:"network,omitempty" json:"network,omitempty" default:"{networkPolicyClass:workspace}"`
	Resources            Resources              `yaml:"resources,omitempty" json:"resources,omitempty" default:"{limits:{cpu:500m,memory:512Mi}}"`
	Podman               Podman                 `yaml:"podman,omitempty" json:"podman,omitempty" default:"{enabled:false}"`
	Storages             map[string]Storage     `yaml:"storages,omitempty" json:"storages,omitempty" default:"{}"`
	InitScripts          []InitScript           `yaml:"initScripts,omitempty" json:"initScripts,omitempty" default:"[]" validate:"dive"`
	ShowInitScriptStatus bool                   `yaml:"showInitScriptStatus,omitempty" json:"showInitScriptStatus,omitempty" default:"false"`
	SecurityContext      map[string]interface{} `yaml:"securityContext,omitempty" json:"securityContext,omitempty" default:"{}"`
	ExtFiles             map[string]string      `yaml:"extFiles,omitempty" json:"extFiles,omitempty" default:"{}"`
	EnableApps           bool                   `yaml:"enableApps,omitempty" json:"enableApps,omitempty" default:"false"`
	Apps                 map[string]AppSpec     `yaml:"apps,omitempty" json:"apps,omitempty" default:"{}"`
}

// BlueprintMetadata holds metadata information for a blueprint.
type BlueprintMetadata struct {
	Name        string `yaml:"name" json:"name"`
	RepoName    string `yaml:"repoName" json:"repoName"`
	RepoRef     string `yaml:"repoRef" json:"repoRef"`
	RepoOwner   string `yaml:"repoOwner" json:"repoOwner"`
	RepoAddress string `yaml:"repoAddress" json:"repoAddress"`
}

// K8shellFile represents the overall structure of a k8shell YAML file
type K8shellFile struct {
	Blueprint CustomBlueprint `yaml:"blueprint" validate:"required"`
}

// CustomBlueprint represents a custom blueprint configuration
type CustomBlueprint struct {
	Metadata             BlueprintMetadata  `yaml:"metadata" json:"metadata"`
	Name                 string             `yaml:"name,omitempty" json:"name,omitempty"`
	Template             string             `yaml:"template" json:"template" validate:"required"`
	Splash               string             `yaml:"splash,omitempty" json:"splash,omitempty"`
	Image                string             `yaml:"image,omitempty" json:"image,omitempty"`
	Env                  map[string]string  `yaml:"env,omitempty" json:"env,omitempty"`
	Network              Network            `yaml:"network,omitempty" json:"network,omitempty"`
	Resources            Resources          `yaml:"resources,omitempty" json:"resources,omitempty"`
	Storages             map[string]Storage `yaml:"storages,omitempty" json:"storages,omitempty"`
	InitScripts          []InitScript       `yaml:"initScripts,omitempty" json:"initScripts,omitempty"`
	ShowInitScriptStatus bool               `yaml:"showInitScriptStatus,omitempty" json:"showInitScriptStatus,omitempty"`
	EnableApps           bool               `yaml:"enableApps,omitempty" json:"enableApps,omitempty"`
	Apps                 map[string]AppSpec `yaml:"apps,omitempty" json:"apps,omitempty"`
}

type BlueprintSummary struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	IsTemplate  bool   `json:"isTemplate,omitempty"`
	// Org is the organization the blueprint is scoped to, or empty for a
	// file-based, global blueprint. Always emitted so a client can rely on
	// the field being present (paired with IsGlobal).
	Org string `json:"org"`
	// IsGlobal is true when the blueprint is not scoped to an organization
	// (Org is empty) and is therefore available to every organization.
	IsGlobal bool `json:"isGlobal,omitempty"`
	// Template is the name of the parent template this blueprint derives from,
	// or empty when it does not inherit from one.
	Template string `json:"template,omitempty"`
	// CreatedAt is when the blueprint was first registered. For an org-scoped
	// database blueprint this is the row's creation time; for a file-based
	// blueprint it is the source file's last-modified time (equal to
	// UpdatedAt), since a file has no separate creation record.
	CreatedAt time.Time `json:"createdAt"`
	// UpdatedAt is when the blueprint was last changed. For an org-scoped
	// database blueprint this is the row's last-update time; for a file-based
	// blueprint it is the source file's last-modified time (equal to
	// CreatedAt).
	UpdatedAt time.Time `json:"updatedAt"`
}

// BlueprintValidation reports whether a submitted blueprint is valid, lists
// every problem found, if any, and carries the resolved blueprint document
// (the submission merged with its referenced Template, if any). Blueprint
// is decoded generically rather than into Blueprint/CustomBlueprint above,
// since unresolved CEL expressions may appear in place of their normal
// field type — mirroring how GetBlueprintResponse's raw content is handled.
// It's only populated when Valid is true: a caller should fix the reported
// Errors first rather than preview a document built from an invalid
// submission.
type BlueprintValidation struct {
	Valid     bool                        `yaml:"valid" json:"valid"`
	Errors    []*BlueprintValidationError `yaml:"errors,omitempty" json:"errors,omitempty"`
	Blueprint any                         `yaml:"blueprint,omitempty" json:"blueprint,omitempty"`
}

// BlueprintValidationError describes a single problem found while
// validating a blueprint.
type BlueprintValidationError struct {
	Line    int32  `yaml:"line,omitempty" json:"line,omitempty"`
	Column  int32  `yaml:"column,omitempty" json:"column,omitempty"`
	Field   string `yaml:"field,omitempty" json:"field,omitempty"`
	Message string `yaml:"message" json:"message"`
}

// OrgBlueprint is a blueprint definition stored in the database and scoped
// to a single organization, as opposed to the file-based, global blueprints
// (Blueprint/BlueprintSummary above). Name and Org together identify it.
type OrgBlueprint struct {
	Name        string    `json:"name"`
	Org         string    `json:"org"`
	Description string    `json:"description,omitempty"`
	YAML        []byte    `json:"yaml"`
	IsTemplate  bool      `json:"isTemplate,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// OrgBlueprintWriteRequest is the HTTP request body shared by POST /blueprints
// and PUT /blueprints/{name}, which register or replace an org-scoped
// blueprint. YAML is the full blueprint document (base64-encoded when the
// body is sent as JSON); name, description and isTemplate are read from it.
// Org is optional — it defaults to the caller's own organization (from the
// JWT claims) when omitted. Proto counterpart is
// provisionerv1.CreateBlueprintRequest / UpdateBlueprintRequest.
type OrgBlueprintWriteRequest struct {
	Org  string `json:"org,omitempty"`
	YAML []byte `json:"yaml"`
}

// OrgBlueprintDocument is the API's response shape for a single org blueprint:
// the fully merged spec (Blueprint), the fields defined directly on the
// blueprint itself (OwnBlueprint), the name of its immediate parent Template,
// if any, and the Org the view is scoped to. A field present in Blueprint but
// absent from OwnBlueprint is inherited rather than set on this blueprint —
// comparing the two tells the frontend which fields are inherited versus own.
// Clients editing a blueprint should only write back fields present in
// OwnBlueprint (plus whatever the user changed), so unmodified inherited
// values aren't pinned onto the child. Org is metadata of this wrapper, not
// part of the blueprint spec — the editor carries it into the save request
// since the blueprint YAML has no org of its own. Blueprint/OwnBlueprint are
// decoded generically rather than into Blueprint above, since unevaluated
// "!cel:"-prefixed placeholders may appear in place of a field's normal type.
type OrgBlueprintDocument struct {
	Blueprint    any    `json:"blueprint" yaml:"blueprint"`
	OwnBlueprint any    `json:"ownBlueprint" yaml:"ownBlueprint"`
	Template     string `json:"template,omitempty" yaml:"template,omitempty"`
	Org          string `json:"org,omitempty" yaml:"org,omitempty"`
}

// InitScript represents a named initialization script
type InitScript struct {
	Name   string `yaml:"name" json:"name" validate:"required"`
	Script string `yaml:"script" json:"script" validate:"required"`
}

type Conn struct {
	AllowAnyNS bool `yaml:"allowAnyNS,omitempty" json:"allowAnyNS,omitempty"`
	AllowAnySA bool `yaml:"allowAnySA,omitempty" json:"allowAnySA,omitempty"`
}

// K8shelld represents k8shelld configuration
type K8shelld struct {
	Image           string   `yaml:"image" json:"image" validate:"required" jsonschema:"required"`
	ImagePullPolicy string   `yaml:"imagePullPolicy,omitempty" json:"imagePullPolicy,omitempty" validate:"omitempty,oneof=Always Never IfNotPresent" jsonschema:"enum=Always,enum=Never,enum=IfNotPresent"`
	IgnoreOrphans   []string `yaml:"ignoreOrphans,omitempty" json:"ignoreOrphans,omitempty" default:"[]"`
	Connection      Conn     `yaml:"connection,omitempty" json:"connection,omitempty"`
}

// Network defines network policy and egress rules for a workspace.
type Network struct {
	// NetworkPolicyClass selects a predefined network policy class (workspace, system, isolated, user, organization).
	NetworkPolicyClass string `yaml:"networkPolicyClass,omitempty" json:"networkPolicyClass,omitempty" validate:"omitempty,oneof=workspace system isolated user organization" jsonschema:"enum=workspace,enum=system,enum=isolated,enum=user,enum=organization"`
	// AllowEgressToCIDRs is a convenience shorthand for permitting egress to specific CIDR ranges.
	AllowEgressToCIDRs []string `yaml:"allowEgressToCIDRs,omitempty" json:"allowEgressToCIDRs,omitempty" validate:"dive,cidr"`
	// AllowEgressToPods is a convenience shorthand for permitting egress to pods matching label selectors.
	AllowEgressToPods []map[string]string `yaml:"allowEgressToPods,omitempty" json:"allowEgressToPods,omitempty"`
}

// Resources represents resource limits
type Resources struct {
	CPU    string `yaml:"cpu" json:"cpu" validate:"required" jsonschema:"required"`
	Memory string `yaml:"memory" json:"memory" validate:"required" jsonschema:"required"`
}

// Podman represents Podman configuration
type Podman struct {
	Enabled                 bool                   `yaml:"enabled" json:"enabled" default:"false"`
	Image                   string                 `yaml:"image" json:"image" validate:"required_if=Enabled true"`
	Resources               Resources              `yaml:"resources" json:"resources" default:"{cpu:500m,memory:512Mi}"`
	CreateDockerSockSymlink bool                   `yaml:"createDockerSockSymlink" json:"createDockerSockSymlink" default:"false"`
	ParentStorages          bool                   `yaml:"parentStorages" json:"parentStorages" default:"true"`
	ExtFiles                map[string]string      `yaml:"extFiles,omitempty" json:"extFiles,omitempty" default:"{}"`
	Storages                map[string]Storage     `yaml:"storages,omitempty" json:"storages,omitempty" default:"{}"`
	SecurityContext         map[string]interface{} `yaml:"securityContext,omitempty" json:"securityContext,omitempty" default:"{}"`
}

// Storage represents storage configuration
type Storage struct {
	Enabled  bool   `yaml:"enabled" json:"enabled" default:"false"`
	Id       string `yaml:"id,omitempty" json:"id,omitempty" validate:"omitempty,alphanum"`
	Type     string `yaml:"type,omitempty" json:"type,omitempty" validate:"omitempty,oneof=local shared emptyDir memory" default:"local" jsonschema:"enum=local,enum=shared,enum=emptyDir,enum=memory"`
	Path     string `yaml:"path" json:"path" validate:"required_if=Enabled true,startswith=/"`
	Readonly bool   `yaml:"readonly" json:"readonly" default:"false"`
	// SizeLimit applies to emptyDir and memory types (maps to emptyDir.sizeLimit)
	SizeLimit            string                 `yaml:"sizeLimit,omitempty" json:"sizeLimit,omitempty"`
	ExistingClaim        string                 `yaml:"existingClaim,omitempty" json:"existingClaim,omitempty" validate:"required_if=Type shared Enabled true"`
	FsOwnerUid           *int                   `yaml:"fsOwnerUid,omitempty" json:"fsOwnerUid,omitempty"`
	FsOwnerGid           *int                   `yaml:"fsOwnerGid,omitempty" json:"fsOwnerGid,omitempty"`
	ClaimSpec            map[string]interface{} `yaml:"claimSpec,omitempty" json:"claimSpec,omitempty" default:"{}"`
	ClaimSpecAnnotations map[string]string      `yaml:"claimSpecAnnotations,omitempty" json:"claimSpecAnnotations,omitempty" default:"{}"`
}

type AppSpec struct {
	Name              string        `yaml:"name" json:"name" validate:"required_if=Enabled true"`
	Enabled           bool          `yaml:"enabled" json:"enabled" default:"false"`
	Binary            string        `yaml:"binary" json:"binary" validate:"required_if=Enabled true"`
	VersionCmd        []string      `yaml:"versionCmd,omitempty" json:"versionCmd,omitempty"`
	VersionRegex      string        `yaml:"versionRegex,omitempty" json:"versionRegex,omitempty"`
	Install           string        `yaml:"install,omitempty" json:"install,omitempty"`
	Start             []string      `yaml:"start" json:"start" validate:"required_if=Enabled true"`
	Listen            int           `yaml:"listen,omitempty" json:"listen,omitempty"`
	RestartPolicy     string        `yaml:"restartPolicy,omitempty" json:"restartPolicy,omitempty" validate:"oneof=always on-failure never" jsonschema:"enum=always,enum=on-failure,enum=never"`
	MaxRestartBackoff time.Duration `yaml:"maxRestartBackoff,omitempty" json:"maxRestartBackoff,omitempty"`
	InstallAsRoot     bool          `yaml:"installAsRoot,omitempty" json:"installAsRoot,omitempty" default:"false"`
	AutoStart         bool          `yaml:"autoStart,omitempty" json:"autoStart,omitempty" default:"false"`
	Protocol          string        `yaml:"protocol,omitempty" json:"protocol,omitempty" validate:"omitempty,oneof=http https ws wss tcp udp" jsonschema:"enum=http,enum=https,enum=ws,enum=wss,enum=tcp,enum=udp"`
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
