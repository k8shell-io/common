// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package authz

import "testing"

func TestGitEvalRequestRoundTrip(t *testing.T) {
	for _, action := range []GitAction{GitActionFetch, GitActionPush} {
		req, err := NewGitEvalRequest(action, "github.com/acme/app").WithWorkspace("ws1", "alice").Build()
		if err != nil {
			t.Fatalf("%s: Build: %v", action, err)
		}
		p := req.ToProto("tok")
		if p.Action != string(action) || p.Resource.Type != "repo" || p.Resource.Id != "github.com/acme/app" ||
			p.Resource.Attributes["host"] != "github.com" || p.Context["workspace"] != "ws1" || p.Context["workspace_owner"] != "alice" || p.Token != "tok" {
			t.Fatalf("%s: unexpected proto %+v", action, p)
		}
		back, err := GitEvalRequestFromProto(p)
		if err != nil {
			t.Fatalf("%s: FromProto: %v", action, err)
		}
		if *back != *req {
			t.Fatalf("%s: round trip = %+v, want %+v", action, back, req)
		}
	}
}

func TestGitEvalRequestNoWorkspace(t *testing.T) {
	req, err := NewGitEvalRequest(GitActionFetch, "gitlab.com/a/b/c").Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if p := req.ToProto("tok"); p.Context != nil {
		t.Fatalf("context = %v, want nil", p.Context)
	}
}

func TestGitEvalRequestValidate(t *testing.T) {
	if _, err := NewGitEvalRequest("git:clone", "github.com/a/b").Build(); err == nil {
		t.Error("unknown action: want error")
	}
	if _, err := NewGitEvalRequest(GitActionPush, "").Build(); err == nil {
		t.Error("empty repo: want error")
	}
	if _, err := NewGitEvalRequest(GitActionPush, "github.com/a/b").WithWorkspace("ws1", "").Build(); err == nil {
		t.Error("workspace without owner: want error")
	}
	if _, err := NewGitEvalRequest(GitActionPush, "github.com/a/b").WithWorkspace("", "alice").Build(); err == nil {
		t.Error("owner without workspace: want error")
	}
	p := NewGitEvalRequest(GitActionPush, "github.com/a/b").ToProto("tok")
	p.Resource.Attributes["host"] = "evil.example"
	if _, err := GitEvalRequestFromProto(p); err == nil {
		t.Error("host not matching repo: want error")
	}
	p.Resource.Attributes["host"] = "github.com"
	p.Resource.Type = "workspace"
	if _, err := GitEvalRequestFromProto(p); err == nil {
		t.Error("wrong resource type: want error")
	}
}

func TestGitScopes(t *testing.T) {
	for _, s := range []string{"git:fetch", "git:push", "git:*"} {
		if err := ValidateScope(s); err != nil {
			t.Errorf("ValidateScope(%q): %v", s, err)
		}
	}
	for _, s := range []string{"git:fetch:self", "git:push:github.com", "git:clone"} {
		if err := ValidateScope(s); err == nil {
			t.Errorf("ValidateScope(%q): want error", s)
		}
	}
	if !ScopeAllows([]string{"git:*"}, "git:push") {
		t.Error("git:* should allow git:push")
	}
	if ScopeAllows([]string{"git:fetch"}, "git:push") {
		t.Error("git:fetch must not allow git:push")
	}
	if ScopeAllows([]string{"user:read:credentials:git"}, "git:fetch") {
		t.Error("user:read:credentials:git must not allow git:fetch")
	}
}
