// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package authz

import (
	"testing"

	authzv1 "github.com/k8shell-io/common/pkg/api/gen/go/authz/v1"
)

func TestScopeForRequest(t *testing.T) {
	tests := []struct {
		name   string
		action string
		ctx    map[string]string
		want   string
	}{
		{"user:auth ssh", "user:auth", map[string]string{"surface": "ssh"}, "user:auth:ssh"},
		{"user:auth web", "user:auth", map[string]string{"surface": "web"}, "user:auth:web"},
		{"user:exists email", "user:exists", map[string]string{"field": "email"}, "user:exists:email"},
		{"user:exists username", "user:exists", map[string]string{"field": "username"}, "user:exists:username"},
		{"user:read profile", "user:read", map[string]string{"data_type": "profile"}, "user:read:profile"},
		{"user:read credentials git", "user:read",
			map[string]string{"data_type": "credentials", "credential_type": "git"}, "user:read:credentials:git"},
		{"user:read credentials kubernetes", "user:read",
			map[string]string{"data_type": "credentials", "credential_type": "kubernetes"}, "user:read:credentials:kubernetes"},
		{"user:write credentials registry", "user:write",
			map[string]string{"data_type": "credentials", "credential_type": "registry"}, "user:write:credentials:registry"},
		{"user:write password", "user:write", map[string]string{"data_type": "password"}, "user:write:password"},
		{"workspace:create standalone", "workspace:create", map[string]string{"mode": "standalone"}, "workspace:create:standalone"},
		{"workspace:create inject", "workspace:create", map[string]string{"mode": "inject"}, "workspace:create:inject"},
		{"workspace:connect webshell", "workspace:connect", map[string]string{"type": "webshell"}, "workspace:connect:webshell"},
		{"workspace:connect portforward", "workspace:connect", map[string]string{"type": "portforward", "port": "8080"}, "workspace:connect:portforward"},
		{"workspace:files upload", "workspace:files", map[string]string{"op": "upload"}, "workspace:files:upload"},
		{"workspace:app start", "workspace:app", map[string]string{"op": "start"}, "workspace:app:start"},

		// Actions with no qualifier fold in unchanged, regardless of context.
		{"user:list unchanged", "user:list", nil, "user:list"},
		{"user:create unchanged", "user:create", nil, "user:create"},
		{"ssh:shell unchanged", "ssh:shell", map[string]string{"host": "10.0.0.1"}, "ssh:shell"},
		{"audit:list unchanged", "audit:list", nil, "audit:list"},

		// A qualifier-bearing action with no context value present falls
		// back to the base action rather than producing a trailing ":".
		{"user:auth missing surface", "user:auth", nil, "user:auth"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &authzv1.EvaluateRequest{Action: tt.action, Context: tt.ctx}
			if got := scopeForRequest(req); got != tt.want {
				t.Errorf("scopeForRequest(%q, %v) = %q, want %q", tt.action, tt.ctx, got, tt.want)
			}
		})
	}
}
