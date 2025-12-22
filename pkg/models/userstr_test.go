package models

import (
	"testing"
)

type fakeIssueResolver struct {
	ref string
	err error
}

func (f fakeIssueResolver) ResolveIssueRepoRef(username string, repoOwner, repoName string,
	issueNumber int) (string, error) {
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

	cu, err := r.Canonicalize()
	if err != nil {
		t.Fatal(err)
	}

	if cu.Identity.Blueprint != "dev" {
		t.Fatalf("unexpected canonical blueprint: %+v", cu.Identity)
	}
	if cu.CanonicalKey != "u=tomas|bp=dev" {
		t.Fatalf("unexpected canonical key: %q", cu.CanonicalKey)
	}
	if cu.CanonicalUserStr == "" {
		t.Fatalf("expected canonical userstr")
	}
	if cu.WorkspaceName == "" {
		t.Fatalf("expected workspace name")
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

	cu, err := r.Canonicalize()
	if err != nil {
		t.Fatal(err)
	}

	if cu.Identity.RepoRef != "feat/abc" {
		t.Fatalf("unexpected canonical ref: %+v", cu.Identity)
	}
	if cu.CanonicalKey != "u=tomas|r=org/svc|ref=feat/abc|bp=repo-org-svc" {
		t.Fatalf("unexpected canonical key: %q", cu.CanonicalKey)
	}
	if cu.CanonicalUserStr == "" {
		t.Fatalf("expected canonical userstr")
	}
	if cu.WorkspaceName == "" {
		t.Fatalf("expected workspace name")
	}
}

func TestParams2_IssueOnly_ResolvesToRef(t *testing.T) {
	r, err := NewUserStr("bob~repo=alice/projectX+issue=22")
	if err != nil {
		t.Fatal(err)
	}

	// Parsing expectations:
	// - keys are lowercased
	// - values are percent-decoded but not globally lowercased
	if r.RepoName != "projectx" || r.ParamsRaw["repo"] != "alice/projectx" {
		t.Fatalf("repo decode failed: repoName=%q paramsRepo=%q", r.RepoName, r.ParamsRaw["repo"])
	}
	if r.RepoIssue != 22 || r.ParamsRaw["issue"] != "22" {
		t.Fatalf("issue decode failed: repoIssue=%d paramsIssue=%q", r.RepoIssue, r.ParamsRaw["issue"])
	}

	SetIssueRepoRefResolver(fakeIssueResolver{ref: "feat/abc"})
	cu, err := r.Canonicalize()
	if err != nil {
		t.Fatal(err)
	}

	if cu.Identity.RepoRef != "feat/abc" {
		t.Fatalf("expected resolved ref, got: %+v", cu.Identity)
	}
	if cu.CanonicalKey != "u=bob|r=alice/projectx|ref=feat/abc|bp=repo-alice-projectx" {
		t.Fatalf("unexpected canonical key: %q", cu.CanonicalKey)
	}

	// Alias should include issue form (with the same casing as parsed repo)
	foundIssueAlias := false
	wantIssueAlias := "u=bob|r=alice/projectx|issue=22"
	for _, a := range cu.Aliases {
		if a == wantIssueAlias {
			foundIssueAlias = true
			break
		}
	}
	if !foundIssueAlias {
		t.Fatalf("expected issue alias %q, got: %+v", wantIssueAlias, cu.Aliases)
	}

	if cu.WorkspaceName == "" {
		t.Fatalf("expected workspace name")
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

	cu, err := r.Canonicalize()
	if err != nil {
		t.Fatal(err)
	}
	if cu.CanonicalKey != "u=alice" {
		t.Fatalf("unexpected canonical key: %q", cu.CanonicalKey)
	}
	if cu.WorkspaceName == "" {
		t.Fatalf("expected workspace name")
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
