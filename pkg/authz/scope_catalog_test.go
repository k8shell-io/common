// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package authz

import "testing"

// TestScopeCatalogDoc_MatchesRegistry guards against the hand-authored
// catalog (scopeCatalogSource) drifting from the validation registry
// (validExactScopes / validWildcardPrefixes) — every catalog entry must be a
// scope ValidateScope actually accepts, and every valid scope must appear
// somewhere in the catalog.
func TestScopeCatalogDoc_MatchesRegistry(t *testing.T) {
	catalog := ScopeCatalogDoc()

	catalogExact := map[string]struct{}{}
	catalogWildcardPrefixes := map[string]struct{}{}

	var walk func(entry ScopeCatalogEntry)
	walk = func(entry ScopeCatalogEntry) {
		if entry.Scope == scopeWildcard {
			return
		}
		if prefix, ok := cutSuffixColonStar(entry.Scope); ok {
			catalogWildcardPrefixes[prefix] = struct{}{}
			return
		}
		catalogExact[entry.Scope] = struct{}{}
	}

	if catalog.Global == nil || catalog.Global.Scope != scopeWildcard {
		t.Errorf("catalog.Global = %+v, want scope %q", catalog.Global, scopeWildcard)
	}

	for _, d := range catalog.Domains {
		if d.Wildcard != nil {
			walk(*d.Wildcard)
		}
		for _, a := range d.Actions {
			for _, e := range a.Entries {
				walk(e)

				if err := ValidateScope(e.Scope); err != nil {
					t.Errorf("catalog entry %q is not a valid scope: %v", e.Scope, err)
				}

				prefix := e.Scope
				if p, ok := cutSuffixColonStar(e.Scope); ok {
					prefix = p
				}
				wantConstrained := scopeConstrainable(prefix)
				gotConstrained := len(e.Constraints) > 0
				if wantConstrained != gotConstrained {
					t.Errorf("catalog entry %q: scopeConstrainable=%v but Constraints=%v", e.Scope, wantConstrained, e.Constraints)
				}
			}
		}
	}

	for scope := range validExactScopes {
		if _, ok := catalogExact[scope]; !ok {
			t.Errorf("valid exact scope %q is missing from the catalog", scope)
		}
	}
	for scope := range catalogExact {
		if _, ok := validExactScopes[scope]; !ok {
			t.Errorf("catalog entry %q is not in validExactScopes", scope)
		}
	}

	for prefix := range validWildcardPrefixes {
		if _, ok := catalogWildcardPrefixes[prefix]; !ok {
			t.Errorf("valid wildcard prefix %q is missing from the catalog", prefix)
		}
	}
	for prefix := range catalogWildcardPrefixes {
		if _, ok := validWildcardPrefixes[prefix]; !ok {
			t.Errorf("catalog wildcard prefix %q is not in validWildcardPrefixes", prefix)
		}
	}
}
