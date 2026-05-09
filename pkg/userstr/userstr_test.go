package userstr

import "testing"

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
		{name: "repo with ns", userstr: "alice~repo=org/proj+ns=test", expected: "PASS"},
		{name: "repo with ref with ns", userstr: "alice~repo=org/proj+ref=main+ns=test", expected: "PASS"},
		{name: "repo with ref", userstr: "alice~repo=org/proj+ref=main", expected: "PASS"},
		{name: "repo with pod", userstr: "alice~repo=org/proj+pod=workspace1+ns=test", expected: "PASS"},
		{name: "repo with pod no ns", userstr: "alice~repo=org/proj+pod=workspace1", expected: "PASS"},
		{name: "repo with ref and pod", userstr: "alice~repo=org/proj+ref=main+pod=workspace1+ns=test+user=root",
			expected: "PASS"},
		{name: "explicit blueprint with pod", userstr: "alice~dev+pod=workspace1+ns=test", expected: "PASS"},
		{name: "explicit blueprint with pod no ns", userstr: "alice~dev+pod=workspace1", expected: "PASS"},

		{name: "ns without pod", userstr: "alice~ns=test", expected: "FAIL"},
		{name: "pod with ref no repo", userstr: "alice~pod=workspace1+ns=test+ref=main", expected: "FAIL"},
		{name: "target removed", userstr: "alice~target=deploy/identity+ns=test", expected: "FAIL"},
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
