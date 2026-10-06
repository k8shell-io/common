// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package authz

import (
	"strings"
	"testing"
)

func TestParseRecordObligation(t *testing.T) {
	for name, tc := range map[string]struct {
		obligations map[string]string
		want        RecordObligation
		found       bool
	}{
		"absent": {map[string]string{}, RecordObligation{}, false},
		"none":   {map[string]string{"record": "none"}, RecordObligation{}, true},
		"channels": {map[string]string{"record": "shell, direct-tcpip"},
			RecordObligation{Shell: true, DirectTCPIP: true}, true},
		"vscode terminals only": {map[string]string{"record": "vscode-terminals"},
			RecordObligation{VscodeTerminals: true}, true},
		"vscode input implies terminals": {map[string]string{"record": "direct-tcpip,vscode-input"},
			RecordObligation{DirectTCPIP: true, VscodeTerminals: true, VscodeInput: true}, true},
	} {
		t.Run(name, func(t *testing.T) {
			got, found := ParseRecordObligation(tc.obligations)
			if got != tc.want || found != tc.found {
				t.Fatalf("got %+v, %v; want %+v, %v", got, found, tc.want, tc.found)
			}
		})
	}
}

func TestRecordObligationRecordsTCPIP(t *testing.T) {
	if (RecordObligation{Shell: true}).RecordsTCPIP() {
		t.Error("shell only must not record tcpip")
	}
	if !(RecordObligation{VscodeTerminals: true}).RecordsTCPIP() {
		t.Error("vscode terminals must record tcpip")
	}
	if !(RecordObligation{DirectTCPIP: true}).RecordsTCPIP() {
		t.Error("direct-tcpip must record tcpip")
	}
}

func TestValidateRecordObligation(t *testing.T) {
	for _, v := range []string{"shell", "shell,exec", "direct-tcpip, sftp", "vscode-input", "none"} {
		if err := ValidateRecordObligation(v); err != nil {
			t.Errorf("%q: unexpected error %v", v, err)
		}
	}
	for _, v := range []string{"", "shell,", "bogus", "shell,none", "none,none"} {
		if err := ValidateRecordObligation(v); err == nil {
			t.Errorf("%q: expected error", v)
		}
	}
}

func TestRecordObligationTokens(t *testing.T) {
	if got := (RecordObligation{}).Tokens(); got == nil || len(got) != 0 {
		t.Fatalf("zero obligation: got %#v, want empty non-nil", got)
	}
	ob, _ := ParseRecordObligation(map[string]string{ObligationKeyRecord: "vscode-input,sftp,shell"})
	got := strings.Join(ob.Tokens(), ",")
	if want := "shell,sftp,vscode-terminals,vscode-input"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
