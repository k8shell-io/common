package models

import (
	"fmt"
	"strconv"
	"strings"
)

// Init script delivery contract between the provisioner and k8shelld.
//
// The provisioner materializes every blueprint InitScript as an executable file
// in the workspace's system directory (InitScriptDir), named by
// InitScriptFileName. k8shelld discovers those files, sorts them lexically (the
// zero-padded ordinal makes lexical order match blueprint order) and executes
// them in order.
//
// The file name is only a delivery and correlation key. Behavior — whether a
// script re-runs on every start (InitScript.Always), and anything added later —
// is read from the blueprint itself (mounted at BlueprintFilePath), which is the
// single source of truth. k8shelld maps a file back to its InitScript with
// ParseInitScriptFileName: the ordinal is the join key (1-based, matching the
// order of Blueprint.InitScripts); the trailing name is human-readable only.
const (
	// InitScriptDir is the workspace directory the provisioner writes init
	// script files into and k8shelld reads them from.
	InitScriptDir = "/usr/local/k8shell/system"

	// BlueprintFilePath is where the composed blueprint is mounted in the
	// workspace. It is authoritative for init script behavior.
	BlueprintFilePath = "/etc/k8shell/blueprint.yaml"

	// initScriptPrefix marks a system file as an init script.
	initScriptPrefix = "__init_"
)

// InitScriptFileName returns the file name for the init script at the given
// zero-based position in Blueprint.InitScripts. name is expected to already
// satisfy the "plainhostname" constraint enforced on InitScript.Name.
func InitScriptFileName(index int, name string) string {
	return fmt.Sprintf("%s%02d_%s", initScriptPrefix, index+1, name)
}

// ParseInitScriptFileName is the inverse of InitScriptFileName. It reports
// whether filename names an init script file and, if so, returns its zero-based
// index into Blueprint.InitScripts and the trailing name. filename may be a full
// path; only its final element is inspected.
func ParseInitScriptFileName(filename string) (index int, name string, ok bool) {
	if i := strings.LastIndexByte(filename, '/'); i >= 0 {
		filename = filename[i+1:]
	}
	rest, found := strings.CutPrefix(filename, initScriptPrefix)
	if !found {
		return 0, "", false
	}
	sep := strings.IndexByte(rest, '_')
	if sep <= 0 {
		return 0, "", false
	}
	ordinal, err := strconv.Atoi(rest[:sep])
	if err != nil || ordinal < 1 {
		return 0, "", false
	}
	return ordinal - 1, rest[sep+1:], true
}
