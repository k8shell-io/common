// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package authz

import "testing"

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
