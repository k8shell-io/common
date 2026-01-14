package models

import (
	"encoding/base64"
	"testing"
)

type fakeRefResolver struct {
	prRef string
	err   error
}

func (f fakeRefResolver) ResolvePullRequestRef(username string, repoOwner, repoName string,
	pullRequestNumber int) (string, error) {
	return f.prRef, f.err
}

func TestDirectBlueprint(t *testing.T) {
	r, err := NewUserStr("tomas~dev", false)
	if err != nil {
		t.Fatal(err)
	}
	if r.Username != "tomas" {
		t.Fatalf("unexpected user: %+v", r)
	}
	if r.Blueprint != "dev" {
		t.Fatalf("unexpected blueprint: %+v", r.Blueprint)
	}
	if r.ParamsRaw != nil || r.RepoName != "" || r.RepoOwner != "" || r.RepoRef != "" || r.RepoPullReq != 0 {
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

func TestParams3_PullRequestOnly_ResolvesToRef(t *testing.T) {
	SetRefResolver(nil)

	r, err := NewUserStr("bob~repo=alice/projectX+pr=7", false)
	if err != nil {
		t.Fatal(err)
	}

	if r.RepoName != "projectx" || r.ParamsRaw["repo"] != "alice/projectx" {
		t.Fatalf("repo decode failed: repoName=%q paramsRepo=%q", r.RepoName, r.ParamsRaw["repo"])
	}
	if r.RepoPullReq != 7 || r.ParamsRaw["pr"] != "7" {
		t.Fatalf("pullrequest decode failed: repoPullReq=%d paramsPr=%q", r.RepoPullReq, r.ParamsRaw["pr"])
	}
	if r.RepoRef != "" {
		t.Fatalf("expected empty ref when pullrequest is specified: %+v", r)
	}

	SetRefResolver(fakeRefResolver{prRef: "refs/pull/7/head"})
	cu, err := r.Canonicalize()
	if err != nil {
		t.Fatal(err)
	}

	if cu.Identity.RepoRef != "refs/pull/7/head" {
		t.Fatalf("expected resolved ref, got: %+v", cu.Identity)
	}

	foundPRAlias := false
	wantPRAlias := "u=bob|r=alice/projectx|pr=7"
	for _, a := range cu.Aliases {
		if a == wantPRAlias {
			foundPRAlias = true
			break
		}
	}
	if !foundPRAlias {
		t.Fatalf("expected pullrequest alias %q, got: %+v", wantPRAlias, cu.Aliases)
	}
}

func TestParams4_PRShorthand_Parses(t *testing.T) {
	r, err := NewUserStr("bob~repo=alice/projectx+pr=9", false)
	if err != nil {
		t.Fatal(err)
	}
	if r.RepoPullReq != 9 || r.ParamsRaw["pr"] != "9" {
		t.Fatalf("pr shorthand parse failed: repoPullReq=%d paramsPr=%q", r.RepoPullReq, r.ParamsRaw["pr"])
	}
}

func TestB64Option(t *testing.T) {
	// Duplicate "ref" parameters to validate last-wins behavior in parameter parsing.
	plain := "tomas~repo=org/svc+ref=feat%2Fabc+ref=ref123"
	token := "b64-" + base64.RawURLEncoding.EncodeToString([]byte(plain))

	r, err := NewUserStr(token, false)
	if err != nil {
		t.Fatal(err)
	}

	if r.Username != "tomas" {
		t.Fatalf("unexpected user: %+v", r)
	}
	if r.RepoOwner != "org" || r.RepoName != "svc" {
		t.Fatalf("unexpected repo: owner=%q name=%q", r.RepoOwner, r.RepoName)
	}
	if r.ParamsRaw["ref"] != "ref123" {
		t.Fatalf("mode mismatch: %q", r.ParamsRaw["ref"])
	}
}

func TestNoSpec(t *testing.T) {
	r, err := NewUserStr("alice", false)
	if err != nil {
		t.Fatal(err)
	}
	if r.Username != "alice" {
		t.Fatalf("unexpected: %+v", r)
	}
	if r.Blueprint != "" || r.ParamsRaw != nil || r.RepoName != "" || r.RepoOwner != "" || r.RepoRef != "" ||
		r.RepoPullReq != 0 {
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
	_, err := NewUserStr("noat", false)
	if err != nil {
		t.Fatal("expected user")
	}
	_, err = NewUserStr("u~a=b=c@h", false)
	if err == nil {
		t.Fatal("expected error for malformed kv")
	}

	// mutual exclusion: cannot specify ref with pullrequest
	_, err = NewUserStr("u~repo=a/b+ref=main+pr=2", false)
	if err == nil {
		t.Fatal("expected error for ref+pr")
	}
}
