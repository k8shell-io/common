// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package nats

import (
	"reflect"
	"testing"

	"github.com/k8shell-io/common/pkg/authz"
	"github.com/k8shell-io/common/pkg/threat"
)

func TestThreatDetectionResolve(t *testing.T) {
	escape := authz.DetectObligation{Categories: []threat.Category{threat.ContainerEscape}}
	for name, tc := range map[string]struct {
		value string
		want  authz.DetectObligation
		found bool
	}{
		"empty":           {`{}`, authz.DetectObligation{}, false},
		"policy":          {`{"policy":{"detect":"container-escape"}}`, escape, true},
		"policy none":     {`{"policy":{"detect":"none"}}`, authz.DetectObligation{}, true},
		"policy no value": {`{"policy":{"evaluatedFor":"u"}}`, authz.DetectObligation{}, false},
		"override wins":   {`{"policy":{"detect":"all"},"override":{"detect":"container-escape"}}`, escape, true},
		"override none":   {`{"policy":{"detect":"all"},"override":{"detect":"none"}}`, authz.DetectObligation{}, true},
		"override only":   {`{"override":{"detect":"all"}}`, authz.DetectObligation{All: true}, true},
	} {
		t.Run(name, func(t *testing.T) {
			d, err := ParseThreatDetection([]byte(tc.value))
			if err != nil {
				t.Fatal(err)
			}
			got, found := d.Resolve()
			if !reflect.DeepEqual(got, tc.want) || found != tc.found {
				t.Fatalf("got %+v, %v; want %+v, %v", got, found, tc.want, tc.found)
			}
		})
	}
	var nilDetection *ThreatDetection
	if _, found := nilDetection.Resolve(); found {
		t.Error("nil entry must not be found")
	}
}

func TestParseThreatDetectionInvalid(t *testing.T) {
	if _, err := ParseThreatDetection([]byte("not json")); err == nil {
		t.Error("expected error")
	}
}
