package userstr

import (
	"strings"
	"testing"
)

func TestUserStr(t *testing.T) {
	type testCase struct {
		name     string
		userstr  string
		expected string // PASS | FAIL
	}

	cases := []testCase{
		{name: "implicit", userstr: "alice", expected: "PASS"},
		{name: "explicit blueprint", userstr: "alice~dev+user=root", expected: "PASS"},
		{name: "pod standalone", userstr: "alice~pod=workspace1+ns=test", expected: "PASS"},
		{name: "pod standalone no ns", userstr: "alice~pod=workspace1", expected: "PASS"},
		{name: "pod standalone user", userstr: "alice~pod=workspace1+ns=test+user=root", expected: "PASS"},
		{name: "repo simple", userstr: "alice~repo=org/proj", expected: "PASS"},
		{name: "repo with ref", userstr: "alice~repo=org/proj+ref=main", expected: "PASS"},
		{name: "repo with deploy and ns", userstr: "alice~repo=org/proj+deploy=myapp+ns=k8s-test", expected: "PASS"},
		{name: "repo with ref deploy ns", userstr: "alice~repo=org/proj+ref=main+deploy=myapp+ns=k8s-test", expected: "PASS"},
		{name: "repo with ref deploy ns user", userstr: "alice~repo=org/proj+ref=main+deploy=myapp+ns=k8s-test+user=root", expected: "PASS"},
		{name: "explicit blueprint with deploy and ns", userstr: "alice~dev+deploy=myapp+ns=k8s-test", expected: "PASS"},
		{name: "explicit blueprint with deploy ns user", userstr: "alice~dev+deploy=myapp+ns=k8s-test+user=root", expected: "PASS"},
		{name: "deploy with explicit blueprint", userstr: "alice~dev+deploy=myapp+ns=k8s-test", expected: "PASS"},

		{name: "deploy form standalone", userstr: "alice~deploy=myapp+ns=k8s-test", expected: "FAIL"},
		{name: "deploy form standalone with user", userstr: "alice~deploy=myapp+ns=k8s-test+user=root", expected: "FAIL"},
		{name: "ns without pod", userstr: "alice~ns=test", expected: "FAIL"},
		{name: "pod with ref no repo", userstr: "alice~pod=workspace1+ns=test+ref=main", expected: "FAIL"},
		{name: "target removed", userstr: "alice~target=deploy/identity+ns=test", expected: "FAIL"},
		{name: "repo with ns no deploy", userstr: "alice~repo=org/proj+ns=test", expected: "FAIL"},
		{name: "repo with pod", userstr: "alice~repo=org/proj+pod=workspace1", expected: "FAIL"},
		{name: "explicit blueprint with pod", userstr: "alice~dev+pod=workspace1", expected: "FAIL"},
		{name: "explicit blueprint with ns", userstr: "alice~dev+ns=test", expected: "FAIL"},
		{name: "deploy without ns", userstr: "alice~deploy=myapp", expected: "FAIL"},
		{name: "deploy with pod", userstr: "alice~deploy=myapp+pod=ws1+ns=k8s-test", expected: "FAIL"},
		{name: "repo deploy without ns", userstr: "alice~repo=org/proj+deploy=myapp", expected: "FAIL"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u, err := ParseUserStr(tc.userstr)
			switch tc.expected {
			case "PASS":
				if err != nil {
					t.Fatalf("expected PASS, got error for input %q: %v", tc.userstr, err)
				}
				c, err := u.Canonicalize()
				if err != nil {
					t.Fatalf("failed to canonicalize input %q: %v", tc.userstr, err)
				}
				if u.Pod() != "" && c.WorkspaceName() != u.Pod() {
					t.Fatalf("workspace name must match pod when pod is set for input %q: workspaceName=%q pod=%q", tc.userstr, c.WorkspaceName(), u.Pod())
				}
				t.Logf("success\nUSERSTR: %q\nWORKSPACENAME: %q", tc.userstr, c.WorkspaceName())
			case "FAIL":
				if err == nil {
					t.Fatalf("expected FAIL, got PASS for input %q", tc.userstr)
				}
				t.Logf("failure\nUSERSTR: %q\nMESSAGE: %v", tc.userstr, err)
			default:
				t.Fatalf("invalid expected value %q (must be PASS or FAIL)", tc.expected)
			}
		})
	}
}

func TestCanonicalizePreservesPodAndNamespace(t *testing.T) {
	cases := []struct {
		name              string
		input             string
		wantPod           string
		wantNs            string
		wantForm          UserStrForm
		wantWorkspaceName string // empty string means "should be empty"
		wantWorkspaceSet  bool   // true if workspaceName should be non-empty
	}{
		{
			name:              "named workspace with pod and ns",
			input:             "alice~pod=workspace1+ns=team-a",
			wantPod:           "workspace1",
			wantNs:            "team-a",
			wantForm:          UserStrFormNamedWorkspace,
			wantWorkspaceName: "workspace1",
			wantWorkspaceSet:  true,
		},
		{
			name:              "blueprint with deploy and ns",
			input:             "alice~dev+deploy=myapp+ns=team-a",
			wantPod:           "",
			wantNs:            "team-a",
			wantForm:          UserStrFormExplicitBlueprint,
			wantWorkspaceName: "",
			wantWorkspaceSet:  false,
		},
		{
			name:              "repo with deploy and ns",
			input:             "alice~repo=org/proj+ref=main+deploy=myapp+ns=team-a",
			wantPod:           "",
			wantNs:            "team-a",
			wantForm:          UserStrFormRepoWorkspace,
			wantWorkspaceName: "",
			wantWorkspaceSet:  false,
		},
		{
			name:              "repo without deploy",
			input:             "alice~repo=org/proj",
			wantPod:           "",
			wantNs:            "",
			wantForm:          UserStrFormRepoWorkspace,
			wantWorkspaceName: "",
			wantWorkspaceSet:  true, // no deploy, so canonical ID is generated
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u, err := ParseUserStr(tc.input)
			if err != nil {
				t.Fatalf("parse failed: %v", err)
			}
			c, err := u.Canonicalize()
			if err != nil {
				t.Fatalf("canonicalize failed: %v", err)
			}

			obj := c.CanonicalUserStrObj()
			if obj == nil {
				t.Fatal("CanonicalUserStrObj is nil")
			}
			if obj.Form() != tc.wantForm {
				t.Errorf("form: got %v want %v", obj.Form(), tc.wantForm)
			}
			if obj.Pod() != tc.wantPod {
				t.Errorf("pod: got %q want %q (canonical userstr: %q)", obj.Pod(), tc.wantPod, c.CanonicalUserStr())
			}
			if obj.Namespace("") != tc.wantNs {
				t.Errorf("namespace: got %q want %q", obj.Namespace(""), tc.wantNs)
			}
			if tc.wantWorkspaceSet && c.WorkspaceName() == "" {
				t.Errorf("workspace name should be non-empty")
			}
			if !tc.wantWorkspaceSet && c.WorkspaceName() != "" {
				t.Errorf("workspace name should be empty when deploy is set, got %q", c.WorkspaceName())
			}
			if tc.wantWorkspaceName != "" && c.WorkspaceName() != tc.wantWorkspaceName {
				t.Errorf("workspace name: got %q want %q", c.WorkspaceName(), tc.wantWorkspaceName)
			}
			// identity must not contain pod, deploy, or namespace
			id := c.Identity()
			if id.Username() == "" {
				t.Error("identity username should not be empty")
			}
		})
	}
}

func TestUserStrFieldsToRawUserStr(t *testing.T) {
	t.Run("implicit form", func(t *testing.T) {
		raw, err := (UserStrFields{Username: "Alice"}).ToRawUserStr()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if raw != "alice" {
			t.Fatalf("unexpected raw userstr: got %q want %q", raw, "alice")
		}
	})

	t.Run("explicit blueprint form", func(t *testing.T) {
		raw, err := (UserStrFields{Username: "alice", Blueprint: "dev branch"}).ToRawUserStr()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if raw != "alice~dev%20branch" {
			t.Fatalf("unexpected raw userstr: got %q want %q", raw, "alice~dev%20branch")
		}
	})

	t.Run("repo form defaults owner to username", func(t *testing.T) {
		raw, err := (UserStrFields{Username: "alice", RepoName: "proj"}).ToRawUserStr()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if raw != "alice~repo=alice%2Fproj" {
			t.Fatalf("unexpected raw userstr: got %q want %q", raw, "alice~repo=alice%2Fproj")
		}
	})

	t.Run("repo form with ref", func(t *testing.T) {
		raw, err := (UserStrFields{Username: "alice", RepoOwner: "Org", RepoName: "Proj", RepoRef: "main"}).ToRawUserStr()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if raw != "alice~repo=org%2Fproj+ref=main" {
			t.Fatalf("unexpected raw userstr: got %q want %q", raw, "alice~repo=org%2Fproj+ref=main")
		}
	})

	t.Run("named workspace form", func(t *testing.T) {
		raw, err := (UserStrFields{Username: "alice", Pod: "workspace1", Namespace: "team-a"}).ToRawUserStr()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if raw != "alice~pod=workspace1+ns=team-a" {
			t.Fatalf("unexpected raw userstr: got %q want %q", raw, "alice~pod=workspace1+ns=team-a")
		}
	})

	t.Run("repo form with deploy and ns", func(t *testing.T) {
		raw, err := (UserStrFields{Username: "alice", RepoOwner: "Org", RepoName: "Proj", RepoRef: "main", Deploy: "myapp", Namespace: "team-a"}).ToRawUserStr()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if raw != "alice~repo=org%2Fproj+ref=main+deploy=myapp+ns=team-a" {
			t.Fatalf("unexpected raw userstr: got %q want %q", raw, "alice~repo=org%2Fproj+ref=main+deploy=myapp+ns=team-a")
		}
	})
}

func TestUserStrFieldsValidation(t *testing.T) {
	cases := []struct {
		name   string
		fields UserStrFields
		msg    string
	}{
		{
			name:   "missing username",
			fields: UserStrFields{},
			msg:    "username is required",
		},
		{
			name:   "blueprint with repo fields",
			fields: UserStrFields{Username: "alice", Blueprint: "dev", RepoName: "proj"},
			msg:    "blueprint cannot be specified when repo fields are present",
		},
		{
			name:   "repo fields missing repo name",
			fields: UserStrFields{Username: "alice", RepoOwner: "org"},
			msg:    "repoName is required when specifying repo fields",
		},
		{
			name:   "namespace without pod or deploy",
			fields: UserStrFields{Username: "alice", Namespace: "team-a"},
			msg:    "pod is required",
		},
		{
			name:   "pod with repo fields",
			fields: UserStrFields{Username: "alice", RepoName: "proj", Pod: "ws1"},
			msg:    "pod cannot be combined with repo",
		},
		{
			name:   "deploy without repo or blueprint",
			fields: UserStrFields{Username: "alice", Deploy: "myapp"},
			msg:    "deploy requires repo or blueprint fields",
		},
		{
			name:   "ns without deploy in repo form",
			fields: UserStrFields{Username: "alice", RepoName: "proj", Namespace: "team-a"},
			msg:    "ns requires deploy in repo form",
		},
		{
			name:   "deploy with explicit blueprint",
			fields: UserStrFields{Username: "alice", RepoName: "proj", Blueprint: "dev", Deploy: "myapp", Namespace: "team-a"},
			msg:    "blueprint cannot be specified when repo fields are present",
		},
		{
			name:   "blueprint deploy without ns",
			fields: UserStrFields{Username: "alice", Blueprint: "dev", Deploy: "myapp"},
			msg:    "ns is required with deploy",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.fields.ToRawUserStr()
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.msg) {
				t.Fatalf("unexpected error: got %q, want to contain %q", err.Error(), tc.msg)
			}
		})
	}
}

func TestUserStrFieldsToUserStrAndBack(t *testing.T) {
	fields := UserStrFields{
		Username:  "alice",
		RepoOwner: "org",
		RepoName:  "proj",
		RepoRef:   "main",
		Deploy:    "myapp",
		Namespace: "team-a",
	}

	u, err := fields.ToUserStr()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.Form() != UserStrFormRepoWorkspace {
		t.Fatalf("unexpected form: got %v want %v", u.Form(), UserStrFormRepoWorkspace)
	}

	roundTrip := UserStrFieldsFromUserStr(u)
	if roundTrip.Username != "alice" {
		t.Fatalf("unexpected username: got %q", roundTrip.Username)
	}
	if roundTrip.RepoOwner != "org" {
		t.Fatalf("unexpected repo owner: got %q", roundTrip.RepoOwner)
	}
	if roundTrip.RepoName != "proj" {
		t.Fatalf("unexpected repo name: got %q", roundTrip.RepoName)
	}
	if roundTrip.RepoRef != "main" {
		t.Fatalf("unexpected repo ref: got %q", roundTrip.RepoRef)
	}
	if roundTrip.Deploy != "myapp" {
		t.Fatalf("unexpected deploy: got %q", roundTrip.Deploy)
	}
	if roundTrip.Namespace != "team-a" {
		t.Fatalf("unexpected namespace: got %q", roundTrip.Namespace)
	}
	if roundTrip.Pod != "" {
		t.Fatalf("unexpected pod (should be empty): got %q", roundTrip.Pod)
	}
}
