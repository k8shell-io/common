package models

import "testing"

func TestInitScriptFileNameRoundTrip(t *testing.T) {
	cases := []struct {
		index int
		name  string
		file  string
	}{
		{0, "workspace", "__init_01_workspace"},
		{1, "db-setup", "__init_02_db-setup"},
		{8, "step9", "__init_09_step9"},
		{9, "step10", "__init_10_step10"},
	}
	for _, c := range cases {
		got := InitScriptFileName(c.index, c.name)
		if got != c.file {
			t.Errorf("InitScriptFileName(%d, %q) = %q, want %q", c.index, c.name, got, c.file)
		}
		idx, name, ok := ParseInitScriptFileName(got)
		if !ok || idx != c.index || name != c.name {
			t.Errorf("ParseInitScriptFileName(%q) = (%d, %q, %v), want (%d, %q, true)",
				got, idx, name, ok, c.index, c.name)
		}
	}
}

func TestParseInitScriptFileName(t *testing.T) {
	if idx, name, ok := ParseInitScriptFileName("/usr/local/k8shell/system/__init_03_thing"); !ok || idx != 2 || name != "thing" {
		t.Errorf("full path parse = (%d, %q, %v)", idx, name, ok)
	}
	// Non-zero-padded ordinals are tolerated.
	if idx, name, ok := ParseInitScriptFileName("__init_7_x"); !ok || idx != 6 || name != "x" {
		t.Errorf("unpadded parse = (%d, %q, %v)", idx, name, ok)
	}
	for _, bad := range []string{"README", "__init_", "__init_x", "__init_ab_x", "__init_00_x", "init_01_x", "__init_01x"} {
		if _, _, ok := ParseInitScriptFileName(bad); ok {
			t.Errorf("ParseInitScriptFileName(%q) = ok, want not ok", bad)
		}
	}
}
