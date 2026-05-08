package userstr

import "testing"

func TestUserStr_PodForms(t *testing.T) {
	u, err := ParseUserStr("alice~pod=workspace1+ns=test")
	if err != nil {
		t.Fatal(err)
	}
	if u.Form != UserStrFormNamedWorkspace {
		t.Fatalf("unexpected form: %v", u.Form)
	}
	if u.Pod != "workspace1" {
		t.Fatalf("unexpected pod: %q", u.Pod)
	}
	if u.Namespace != "test" {
		t.Fatalf("unexpected namespace: %q", u.Namespace)
	}

	c, err := u.Canonicalize(CanonicalizeOptions{IncludeBlueprintInKey: true})
	if err != nil {
		t.Fatal(err)
	}
	if c.WorkspaceName != "workspace1" {
		t.Fatalf("workspace name mismatch: %q", c.WorkspaceName)
	}
	if c.CanonicalUserStr != "alice~ns=test+pod=workspace1" {
		t.Fatalf("unexpected canonical userstr: %q", c.CanonicalUserStr)
	}
}

func TestUserStr_PodWithUser(t *testing.T) {
	u, err := ParseUserStr("alice~pod=workspace1+ns=test+user=root")
	if err != nil {
		t.Fatal(err)
	}
	if u.Pod != "workspace1" || u.User != "root" {
		t.Fatalf("unexpected parsed values: pod=%q user=%q", u.Pod, u.User)
	}

	c, err := u.Canonicalize(CanonicalizeOptions{IncludeBlueprintInKey: true})
	if err != nil {
		t.Fatal(err)
	}
	if c.WorkspaceName != "workspace1" {
		t.Fatalf("workspace name mismatch: %q", c.WorkspaceName)
	}
	if c.CanonicalUserStr != "alice~ns=test+pod=workspace1+user=root" {
		t.Fatalf("unexpected canonical userstr: %q", c.CanonicalUserStr)
	}
}

func TestUserStr_ExplicitBlueprintWithTargetAndNs(t *testing.T) {
	u, err := ParseUserStr("alice~dev+target=deploy/identity+ns=test+user=root")
	if err != nil {
		t.Fatal(err)
	}
	if u.Form != UserStrFormExplicitBlueprint {
		t.Fatalf("unexpected form: %v", u.Form)
	}
	if u.Blueprint != "dev" || u.Target != "deploy/identity" || u.Namespace != "test" {
		t.Fatalf("unexpected explicit blueprint fields: bp=%q target=%q ns=%q", u.Blueprint, u.Target, u.Namespace)
	}
	if u.TargetKind != "deploy" || u.TargetName != "identity" {
		t.Fatalf("unexpected target parse: kind=%q name=%q", u.TargetKind, u.TargetName)
	}
}

func TestUserStr_PodWithRepoRefRejected(t *testing.T) {
	cases := []string{
		"alice~pod=workspace1+ns=test+repo=org/proj",
		"alice~pod=workspace1+ns=test+ref=main",
	}
	for _, in := range cases {
		_, err := ParseUserStr(in)
		if err == nil {
			t.Fatalf("expected error for input: %s", in)
		}
	}
}

func TestUserStr_PodRequiresNs(t *testing.T) {
	_, err := ParseUserStr("alice~pod=workspace1")
	if err == nil {
		t.Fatal("expected error when pod is missing ns")
	}
}

func TestUserStr_RepoForm(t *testing.T) {
	u, err := ParseUserStr("alice~repo=org/proj+ref=main+user=root")
	if err != nil {
		t.Fatal(err)
	}
	if u.Form != UserStrFormRepoWorkspace {
		t.Fatalf("unexpected form: %v", u.Form)
	}
	if u.RepoOwner != "org" || u.RepoName != "proj" || u.RepoRef != "main" {
		t.Fatalf("unexpected repo fields: owner=%q name=%q ref=%q", u.RepoOwner, u.RepoName, u.RepoRef)
	}
	if u.Blueprint != "repo-org-proj" {
		t.Fatalf("unexpected blueprint: %q", u.Blueprint)
	}
}

func TestUserStr_RepoSimpleForms(t *testing.T) {
	for _, in := range []string{"alice~repo=org/proj", "alice~repo=org/proj+ref=main"} {
		u, err := ParseUserStr(in)
		if err != nil {
			t.Fatalf("unexpected error for %q: %v", in, err)
		}
		if u.Form != UserStrFormRepoWorkspace {
			t.Fatalf("unexpected form for %q: %v", in, u.Form)
		}
	}
}

func TestUserStr_RepoTargetNeedsRefAndNs(t *testing.T) {
	cases := []string{
		"alice~repo=org/proj+target=deploy/identity+ns=test",
		"alice~repo=org/proj+ref=main+target=deploy/identity",
	}
	for _, in := range cases {
		_, err := ParseUserStr(in)
		if err == nil {
			t.Fatalf("expected error for input: %s", in)
		}
	}
}

func TestUserStr_RepoTargetForm(t *testing.T) {
	u, err := ParseUserStr("alice~repo=org/proj+ref=main+target=deploy/identity+ns=test+user=root")
	if err != nil {
		t.Fatal(err)
	}
	if u.Target != "deploy/identity" || u.Namespace != "test" {
		t.Fatalf("unexpected target fields: target=%q ns=%q", u.Target, u.Namespace)
	}
	if u.TargetKind != "deploy" || u.TargetName != "identity" {
		t.Fatalf("unexpected target parse: kind=%q name=%q", u.TargetKind, u.TargetName)
	}

	c, err := u.Canonicalize(CanonicalizeOptions{IncludeBlueprintInKey: true})
	if err != nil {
		t.Fatal(err)
	}
	if c.CanonicalUserStr != "alice~ns=test+ref=main+repo=org%2Fproj+target=deploy%2Fidentity+user=root" {
		t.Fatalf("unexpected canonical userstr: %q", c.CanonicalUserStr)
	}
}

func TestUserStr_ImplicitTargetForm(t *testing.T) {
	u, err := ParseUserStr("alice~target=ds/identity+ns=test")
	if err != nil {
		t.Fatal(err)
	}
	if u.Form != UserStrFormImplicit {
		t.Fatalf("unexpected form: %v", u.Form)
	}
	if u.Target != "ds/identity" || u.Namespace != "test" {
		t.Fatalf("unexpected implicit target fields: target=%q ns=%q", u.Target, u.Namespace)
	}
	if u.TargetKind != "ds" || u.TargetName != "identity" {
		t.Fatalf("unexpected target parse: kind=%q name=%q", u.TargetKind, u.TargetName)
	}
}

func TestUserStr_NSValidation(t *testing.T) {
	cases := []string{
		"alice~ns=test",
		"alice~dev+ns=test",
	}
	for _, in := range cases {
		_, err := ParseUserStr(in)
		if err == nil {
			t.Fatalf("expected error for input: %s", in)
		}
	}
}

func TestUserStr_TargetKindValidation(t *testing.T) {
	_, err := ParseUserStr("alice~target=deployment/identity+ns=test")
	if err == nil {
		t.Fatal("expected error for non-shorthand target kind")
	}
}
