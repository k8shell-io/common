package nats

import "testing"

func TestThreatSubject(t *testing.T) {
	tests := []struct{ ns, ws, rule, want string }{
		{"workspaces-staging", "bruckins-9630154", "sensitive-mount-proc-mem", "worktrace.threats.workspaces-staging.bruckins-9630154.sensitive-mount-proc-mem"},
		{"ns", "", "behavioral", "worktrace.threats.ns._.behavioral"},
		{"", "", "", "worktrace.threats._._._"},
		{"a.b", "c*d", "e>f g", "worktrace.threats.a_b.c_d.e_f_g"},
	}
	for _, tt := range tests {
		if got := ThreatSubject(tt.ns, tt.ws, tt.rule); got != tt.want {
			t.Errorf("ThreatSubject(%q,%q,%q) = %q, want %q", tt.ns, tt.ws, tt.rule, got, tt.want)
		}
	}
}
