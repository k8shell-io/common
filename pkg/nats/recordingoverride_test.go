package nats

import (
	"testing"

	"github.com/k8shell-io/common/pkg/authz"
)

func TestResolveRecordObligation(t *testing.T) {
	policy := authz.RecordObligation{Shell: true, Exec: true}
	cases := map[string]struct {
		override    *RecordingOverride
		policyFound bool
		want        authz.RecordObligation
		wantFound   bool
	}{
		"no override keeps policy":    {nil, true, policy, true},
		"no override, no policy":      {nil, false, policy, false},
		"override replaces policy":    {&RecordingOverride{Record: "sftp,vscode-input"}, true, authz.RecordObligation{SFTP: true, VscodeTerminals: true, VscodeInput: true}, true},
		"none disables recording":     {&RecordingOverride{Record: "none"}, true, authz.RecordObligation{}, true},
		"override applies w/o policy": {&RecordingOverride{Record: "shell"}, false, authz.RecordObligation{Shell: true}, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, found := ResolveRecordObligation(policy, tc.policyFound, tc.override)
			if got != tc.want || found != tc.wantFound {
				t.Fatalf("got (%+v, %v), want (%+v, %v)", got, found, tc.want, tc.wantFound)
			}
		})
	}
}
