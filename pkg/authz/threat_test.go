// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package authz

import (
	"reflect"
	"testing"

	"github.com/k8shell-io/common/pkg/threat"
)

func TestParseDetectObligation(t *testing.T) {
	for name, tc := range map[string]struct {
		obligations map[string]string
		want        DetectObligation
		found       bool
	}{
		"absent": {map[string]string{}, DetectObligation{}, false},
		"none":   {map[string]string{"detect": "none"}, DetectObligation{}, true},
		"all":    {map[string]string{"detect": "all"}, DetectObligation{All: true}, true},
		"all wins": {map[string]string{"detect": "container-escape,all"},
			DetectObligation{All: true}, true},
		"categories": {map[string]string{"detect": "container-escape, credential-access"},
			DetectObligation{Categories: []threat.Category{threat.ContainerEscape, threat.CredentialAccess}}, true},
		"duplicates and empty tokens dropped": {map[string]string{"detect": "discovery,,discovery"},
			DetectObligation{Categories: []threat.Category{threat.Discovery}}, true},
		"unknown category kept": {map[string]string{"detect": "future-category"},
			DetectObligation{Categories: []threat.Category{"future-category"}}, true},
	} {
		t.Run(name, func(t *testing.T) {
			got, found := ParseDetectObligation(tc.obligations)
			if !reflect.DeepEqual(got, tc.want) || found != tc.found {
				t.Fatalf("got %+v, %v; want %+v, %v", got, found, tc.want, tc.found)
			}
		})
	}
}

func TestDetectObligationString(t *testing.T) {
	for _, v := range []string{"none", "all", "container-escape,discovery"} {
		ob, _ := ParseDetectObligation(map[string]string{"detect": v})
		if got := ob.String(); got != v {
			t.Errorf("%q: String() = %q", v, got)
		}
	}
}

func TestDetectObligationIncludes(t *testing.T) {
	ob := DetectObligation{Categories: []threat.Category{threat.ContainerEscape}}
	if !ob.Includes(threat.ContainerEscape) || ob.Includes(threat.Discovery) {
		t.Errorf("categories: %+v", ob)
	}
	if !(DetectObligation{All: true}).Includes(threat.Discovery) {
		t.Error("all must include every category")
	}
	if !(DetectObligation{}).None() || (DetectObligation{All: true}).None() {
		t.Error("None() mismatch")
	}
}

func TestValidateDetectObligation(t *testing.T) {
	for _, v := range []string{"none", "all", "container-escape", "container-escape, cryptomining"} {
		if err := ValidateDetectObligation(v); err != nil {
			t.Errorf("%q: unexpected error %v", v, err)
		}
	}
	for _, v := range []string{"", "container-escape,", "bogus", "all,discovery", "none,none"} {
		if err := ValidateDetectObligation(v); err == nil {
			t.Errorf("%q: expected error", v)
		}
	}
	for _, c := range threat.Categories {
		if err := ValidateDetectObligation(string(c)); err != nil {
			t.Errorf("%q: %v", c, err)
		}
	}
}

func TestThreatDetectEvalRequest(t *testing.T) {
	r, err := NewThreatDetectEvalRequest("bruckins-85a782e").WithOwner("bruckins").WithBlueprint("dev").
		WithMode(WorkspaceProvisionModeInject, "k8shell-test").WithWorkload("api", "deployment").Build()
	if err != nil {
		t.Fatal(err)
	}
	back, err := ThreatDetectEvalRequestFromProto(r.ToProto("tok"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, r) {
		t.Errorf("round trip: got %+v, want %+v", back, r)
	}

	for name, b := range map[string]*ThreatDetectEvalRequest{
		"no owner":        NewThreatDetectEvalRequest("ws").WithMode(WorkspaceProvisionModeStandalone, "ns"),
		"no workspace":    NewThreatDetectEvalRequest("").WithOwner("u").WithMode(WorkspaceProvisionModeStandalone, "ns"),
		"bad mode":        NewThreatDetectEvalRequest("ws").WithOwner("u").WithMode("other", "ns"),
		"no namespace":    NewThreatDetectEvalRequest("ws").WithOwner("u").WithMode(WorkspaceProvisionModeStandalone, ""),
		"inject workload": NewThreatDetectEvalRequest("ws").WithOwner("u").WithMode(WorkspaceProvisionModeInject, "ns"),
	} {
		if _, err := b.Build(); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := NewThreatDetectEvalRequest("ws").WithOwner("u").WithMode(WorkspaceProvisionModeStandalone, "ns").Build(); err != nil {
		t.Errorf("standalone: %v", err)
	}
}

func TestThreatDetectionOverrideEvalRequest(t *testing.T) {
	r, err := NewThreatDetectionOverrideEvalRequest("ws").WithOwner("u").Build()
	if err != nil {
		t.Fatal(err)
	}
	back, err := ThreatDetectionOverrideEvalRequestFromProto(r.ToProto(""))
	if err != nil || !reflect.DeepEqual(back, r) {
		t.Errorf("round trip: got %+v, %v", back, err)
	}
	if _, err := NewThreatDetectionOverrideEvalRequest("ws").Build(); err == nil {
		t.Error("expected error without owner")
	}
	if _, err := NewThreatDetectionOverrideEvalRequest("").WithOwner("u").Build(); err != nil {
		t.Errorf("capability probe: %v", err)
	}
}

func TestThreatScopes(t *testing.T) {
	if err := ValidateScope(string(ThreatActionDetectionOverride)); err != nil {
		t.Errorf("override scope: %v", err)
	}
	if err := ValidateScope(string(ThreatActionDetect)); err == nil {
		t.Error("threat:detect must not be a PAT scope")
	}
}
