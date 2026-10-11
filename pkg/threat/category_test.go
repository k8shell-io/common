// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package threat

import (
	"regexp"
	"testing"
)

// Categories are rule-set folder names, KV values and comma-separated
// obligation tokens, so they must be lowercase slugs, and unique.
func TestCategories(t *testing.T) {
	slug := regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	seen := map[Category]bool{}
	for _, c := range Categories {
		if !slug.MatchString(string(c)) {
			t.Errorf("%q is not a lowercase slug", c)
		}
		if seen[c] {
			t.Errorf("%q listed twice", c)
		}
		seen[c] = true
		if !Known(c) {
			t.Errorf("%q not known", c)
		}
	}
	if Known("all") || Known("none") {
		t.Error("all and none are obligation values, not categories")
	}
	if len(Strings()) != len(Categories) {
		t.Error("Strings length")
	}
}
