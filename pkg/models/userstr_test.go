package models

import (
	"context"
	"testing"
)

type fakeIssueResolver struct {
	ref string
	err error
}

func (f fakeIssueResolver) ResolveIssueRef(ctx context.Context, repoOwner, repoName string, issueNumber int) (string, error) {
	return f.ref, f.err
}

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
	if r.ParamsRaw != nil || r.RepoName != "" || r.RepoOwner != "" || r.RepoRef != "" || r.RepoIssue != 0 {
		t.Fatalf("expected nil params: %+v", r)
	}

	// Canonicalize blueprint-only (no resolver needed)
	if err := r.Canonicalize(context.Background(), nil, CanonicalizeOptions{
		PreferExplicitRef:     true,
		ResolveIssueToRef:     true,
		IncludeBlueprintInKey: true,
	}); err != nil {
		t.Fatal(err)
	}
	if r.Identity.Blueprint != "dev" {
		t.Fatalf("unexpected canonical blueprint: %+v", r.Identity)
	}
	if r.CanonicalKey != "u=tomas|bp=dev" {
		t.Fatalf("unexpected canonical key: %q", r.CanonicalKey)
	}
}

func TestParams1(t *testing.T) {
	r, err := NewUserStr("tomas~repo=org/svc+ref=feat%2Fabc+mode=inspect")
	if err != nil {
		t.Fatal(err)
	}

	if r.RepoName != "svc" || r.ParamsRaw["repo"] != "org/svc" {
		t.Fatalf("repo decode failed: repoName=%q paramsRepo=%q", r.RepoName, r.ParamsRaw["repo"])
	}
	if r.RepoOwner != "org" {
		t.Fatalf("owner mismatch: %q", r.RepoOwner)
	}
	if r.RepoRef != "feat/abc" || r.ParamsRaw["ref"] != "feat/abc" {
		t.Fatalf("ref decode failed: repoRef=%q paramsRef=%q", r.RepoRef, r.ParamsRaw["ref"])
	}
	if r.ParamsRaw["mode"] != "inspect" {
		t.Fatalf("mode mismatch: %q", r.ParamsRaw["mode"])
	}

	// Canonicalize (ref already provided; no resolver needed)
	if err := r.Canonicalize(context.Background(), nil, CanonicalizeOptions{
		PreferExplicitRef:     true,
		ResolveIssueToRef:     true,
		IncludeBlueprintInKey: true,
	}); err != nil {
		t.Fatal(err)
	}
	if r.Identity.RepoRef != "feat/abc" {
		t.Fatalf("unexpected canonical ref: %+v", r.Identity)
	}
	if r.CanonicalKey != "u=tomas|r=org/svc|ref=feat/abc|bp=repo-org-svc" {
		t.Fatalf("unexpected canonical key: %q", r.CanonicalKey)
	}
	if r.CanonicalUserStr == "" {
		t.Fatalf("expected canonical userstr")
	}
}

func TestParams2_IssueOnly_ResolvesToRef(t *testing.T) {
	r, err := NewUserStr("bob~repo=alice/projectX+issue=22")
	if err != nil {
		t.Fatal(err)
	}

	// NEW behavior: repo values are not lowercased globally anymore.
	if r.RepoName != "projectx" || r.ParamsRaw["repo"] != "alice/projectx" {
		t.Fatalf("repo decode failed: repoName=%q paramsRepo=%q", r.RepoName, r.ParamsRaw["repo"])
	}
	if r.RepoIssue != 22 || r.ParamsRaw["issue"] != "22" {
		t.Fatalf("issue decode failed: repoIssue=%d paramsIssue=%q", r.RepoIssue, r.ParamsRaw["issue"])
	}

	// Canonicalize resolves issue->ref via resolver
	resolver := fakeIssueResolver{ref: "feat/abc"}
	if err := r.Canonicalize(context.Background(), resolver, CanonicalizeOptions{
		PreferExplicitRef:     true,
		ResolveIssueToRef:     true,
		IncludeBlueprintInKey: true,
	}); err != nil {
		t.Fatal(err)
	}

	if r.Identity.RepoRef != "feat/abc" {
		t.Fatalf("expected resolved ref, got: %+v", r.Identity)
	}
	if r.CanonicalKey != "u=bob|r=alice/projectx|ref=feat/abc|bp=repo-alice-projectx" {
		t.Fatalf("unexpected canonical key: %q", r.CanonicalKey)
	}
	// alias should include issue form
	foundIssueAlias := false
	for _, a := range r.Aliases {
		if a == "u=bob|r=alice/projectx|issue=22" {
			foundIssueAlias = true
			break
		}
	}
	if !foundIssueAlias {
		t.Fatalf("expected issue alias, got: %+v", r.Aliases)
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
	if r.Blueprint != "" || r.ParamsRaw != nil || r.RepoName != "" || r.RepoOwner != "" || r.RepoRef != "" || r.RepoIssue != 0 {
		t.Fatalf("expected nil bp/params: %+v", r)
	}

	if err := r.Canonicalize(context.Background(), nil, CanonicalizeOptions{
		PreferExplicitRef:     true,
		ResolveIssueToRef:     true,
		IncludeBlueprintInKey: true,
	}); err != nil {
		t.Fatal(err)
	}
	if r.CanonicalKey != "u=alice" {
		t.Fatalf("unexpected canonical key: %q", r.CanonicalKey)
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
