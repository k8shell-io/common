// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"reflect"
	"testing"

	"github.com/invopop/jsonschema"

	"github.com/k8shell-io/common/pkg/threat"
)

// The API schema must enumerate exactly the categories of threat.Categories.
func TestDetectSchemaEnum(t *testing.T) {
	for name, tc := range map[string]struct {
		v        any
		withNone bool
	}{
		"DetectionOverrideRequest": {&DetectionOverrideRequest{}, true},
		"DetectionOverride":        {&DetectionOverride{}, true},
		"WorkspaceDetection":       {&WorkspaceDetection{}, false},
	} {
		t.Run(name, func(t *testing.T) {
			r := &jsonschema.Reflector{DoNotReference: true}
			s := r.Reflect(tc.v)
			detect, ok := s.Properties.Get("detect")
			if !ok || detect.Items == nil {
				t.Fatal("no detect items in schema")
			}
			var got []string
			for _, v := range detect.Items.Enum {
				got = append(got, v.(string))
			}
			want := append([]string{"all"}, threat.Strings()...)
			if tc.withNone {
				want = append([]string{"all", "none"}, threat.Strings()...)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("enum = %v, want %v", got, want)
			}
		})
	}
}
