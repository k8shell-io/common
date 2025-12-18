package models

import "testing"

func TestDirectBlueprint(t *testing.T) {
	r, err := NewUserStr("tomas~dev")
	if err != nil {
		t.Fatal(err)
	}
	if r.Username != "tomas" {
		t.Fatalf("unexpected user: %+v", r)
	}
	if r.Blueprint != "dev" {
		t.Fatalf("unexpected blueprint: %+v", r.Blueprint)
	}
	if r.ParamsRaw != nil || r.RepoName != "" || r.RepoOwner != "" || r.RepoRef != "" {
		t.Fatalf("expected nil params: %+v", r.ParamsRaw)
	}
}

func TestParams1(t *testing.T) {
	r, err := NewUserStr("tomas~repo=org/svc+ref=feat%2Fabc+mode=inspect")
	if err != nil {
		t.Fatal(err)
	}
	if r.RepoName != "svc" || r.ParamsRaw["repo"] != "org/svc" {
		t.Fatalf("repo decode failed: %q", r.RepoName)
	}
	if r.RepoOwner != "org" {
		t.Fatalf("owner mismatch: %q", r.RepoOwner)
	}
	if r.RepoRef != "feat/abc" || r.ParamsRaw["ref"] != "feat/abc" {
		t.Fatalf("ref decode failed: %q", r.RepoRef)
	}
	if r.ParamsRaw["mode"] != "inspect" {
		t.Fatalf("mode mismatch: %q", r.ParamsRaw["mode"])
	}
}

func TestParams2(t *testing.T) {
	r, err := NewUserStr("bob~repo=alice/projectX+issue=22")
	if err != nil {
		t.Fatal(err)
	}
	if r.RepoName != "projectx" || r.ParamsRaw["repo"] != "alice/projectx" {
		t.Fatalf("repo decode failed: %q", r.RepoName)
	}
	if r.RepoIssue != 22 || r.ParamsRaw["issue"] != "22" {
		t.Fatalf("issue decode failed: %d", r.RepoIssue)
	}
}

func TestNoSpec(t *testing.T) {
	r, err := NewUserStr("alice")
	if err != nil {
		t.Fatal(err)
	}
	if r.Username != "alice" {
		t.Fatalf("unexpected: %+v", r)
	}
	if r.Blueprint != "" || r.ParamsRaw != nil || r.RepoName != "" || r.RepoOwner != "" || r.RepoRef != "" {
		t.Fatalf("expected nil bp/params")
	}
}

func TestErrors(t *testing.T) {
	_, err := NewUserStr("noat")
	if err != nil {
		t.Fatal("expected user")
	}
	_, err = NewUserStr("u~a=b=c@h")
	if err == nil {
		t.Fatal("expected error for malformed kv")
	}
}
