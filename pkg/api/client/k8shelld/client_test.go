package k8shelld

import (
	"testing"

	"github.com/k8shell-io/common/pkg/api/client/session"
)

func TestCheckRecording(t *testing.T) {
	sc := &session.Client{}
	tests := []struct {
		name      string
		client    *K8shelld
		enable    bool
		channelID string
		wantErr   bool
	}{
		{"disabled ignores missing IDs", &K8shelld{}, false, "", false},
		{"no session client", &K8shelld{connectionID: "c1"}, true, "sh-c11", true},
		{"no connection ID", &K8shelld{sessionClient: sc}, true, "sh-c11", true},
		{"no channel ID", &K8shelld{sessionClient: sc, connectionID: "c1"}, true, "", true},
		{"all set", &K8shelld{sessionClient: sc, connectionID: "c1"}, true, "sh-c11", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.client.checkRecording(tt.enable, tt.channelID)
			if (err != nil) != tt.wantErr {
				t.Fatalf("checkRecording() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestWithConnectionID(t *testing.T) {
	orig := &K8shelld{connectionID: ""}
	cp := orig.WithConnectionID("ws-abc")
	if cp.connectionID != "ws-abc" {
		t.Fatalf("copy connectionID = %q, want %q", cp.connectionID, "ws-abc")
	}
	if orig.connectionID != "" {
		t.Fatalf("original connectionID changed to %q", orig.connectionID)
	}
}
