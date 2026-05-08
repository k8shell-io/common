package userstr

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

func normalizedTarget(kind, name, fallback string) string {
	if strings.TrimSpace(kind) != "" && strings.TrimSpace(name) != "" {
		return strings.ToLower(strings.TrimSpace(kind)) + "/" + strings.ToLower(strings.TrimSpace(name))
	}
	return fallback
}

func (u *UserStr) Canonicalize(opt CanonicalizeOptions) (*CanonicalUserStr, error) {
	if u == nil {
		return nil, fmt.Errorf("%w: nil userstr", ErrUserStrInvalid)
	}

	if !opt.IncludeBlueprintInKey {
		opt.IncludeBlueprintInKey = true
	}

	identity := WorkspaceIdentity{
		Username:      u.Username,
		Pod:           u.Pod,
		Target:        normalizedTarget(u.TargetKind, u.TargetName, u.Target),
		TargetKind:    u.TargetKind,
		TargetName:    u.TargetName,
		Namespace:     u.Namespace,
		Blueprint:     u.Blueprint,
		BlueprintKind: u.BlueprintKind,
		RepoOwner:     u.RepoOwner,
		RepoName:      u.RepoName,
		RepoRef:       u.RepoRef,
	}

	out := &CanonicalUserStr{Identity: identity}
	out.CanonicalKey = buildWorkspaceKey(identity, opt.IncludeBlueprintInKey)
	out.CanonicalUserStr = buildCanonicalUserStr(identity, u.User)
	out.Aliases = buildAliases(u)
	if u.Pod != "" {
		out.WorkspaceName = u.Pod
	} else {
		out.WorkspaceName = buildWorkspaceName(u.Username, out.CanonicalKey)
	}

	parsed, err := ParseUserStr(out.CanonicalUserStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse canonical userstr: %w", err)
	}
	out.CanonicalUserStrObj = parsed

	return out, nil
}

func buildWorkspaceKey(id WorkspaceIdentity, includeBlueprint bool) string {
	parts := []string{"u=" + id.Username}
	if id.Pod != "" {
		parts = append(parts, "pod="+id.Pod)
	}
	if id.Target != "" {
		parts = append(parts, "target="+id.Target)
	}
	if id.Namespace != "" {
		parts = append(parts, "ns="+id.Namespace)
	}
	if id.RepoOwner != "" && id.RepoName != "" {
		parts = append(parts, "r="+id.RepoOwner+"/"+id.RepoName)
	}
	if id.RepoRef != "" {
		parts = append(parts, "ref="+id.RepoRef)
	}
	if includeBlueprint && id.Blueprint != "" {
		parts = append(parts, "bp="+id.Blueprint)
	}
	return strings.Join(parts, "|")
}

func buildCanonicalUserStr(id WorkspaceIdentity, user string) string {
	canonicalUser := strings.ToLower(strings.TrimSpace(user))

	if id.Pod != "" {
		params := map[string]string{
			"pod": id.Pod,
			"ns":  id.Namespace,
		}
		if canonicalUser != "" {
			params["user"] = canonicalUser
		}
		return id.Username + "~" + joinParamsCanonical(params)
	}

	if id.RepoOwner != "" && id.RepoName != "" {
		params := map[string]string{"repo": id.RepoOwner + "/" + id.RepoName}
		if id.RepoRef != "" {
			params["ref"] = id.RepoRef
		}
		target := normalizedTarget(id.TargetKind, id.TargetName, id.Target)
		if target != "" {
			params["target"] = target
			params["ns"] = id.Namespace
		}
		if canonicalUser != "" {
			params["user"] = canonicalUser
		}
		return id.Username + "~" + joinParamsCanonical(params)
	}

	if id.Blueprint != "" {
		target := normalizedTarget(id.TargetKind, id.TargetName, id.Target)
		if target != "" {
			params := map[string]string{
				"target": target,
				"ns":     id.Namespace,
			}
			if canonicalUser != "" {
				params["user"] = canonicalUser
			}
			return fmt.Sprintf("%s~%s+%s", id.Username, url.PathEscape(id.Blueprint), joinParamsCanonical(params))
		}
		if canonicalUser != "" {
			return fmt.Sprintf("%s~%s+user=%s", id.Username, url.PathEscape(id.Blueprint), url.PathEscape(canonicalUser))
		}
		return fmt.Sprintf("%s~%s", id.Username, url.PathEscape(id.Blueprint))
	}

	target := normalizedTarget(id.TargetKind, id.TargetName, id.Target)
	if target != "" || id.Namespace != "" {
		params := map[string]string{"target": target}
		if id.Namespace != "" {
			params["ns"] = id.Namespace
		}
		if canonicalUser != "" {
			params["user"] = canonicalUser
		}
		return id.Username + "~" + joinParamsCanonical(params)
	}

	return id.Username
}

func joinParamsCanonical(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, url.PathEscape(params[k])))
	}
	return strings.Join(parts, "+")
}

func buildAliases(u *UserStr) []string {
	aliases := []string{"raw:" + u.Raw}
	if u.RepoOwner != "" && u.RepoName != "" && u.RepoRef != "" {
		aliases = append(aliases, fmt.Sprintf("u=%s|r=%s/%s|ref=%s", u.Username, u.RepoOwner, u.RepoName, u.RepoRef))
	}
	return aliases
}

func shortHash(s string, n int) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])[:n]
}

func buildWorkspaceName(username, canonicalKey string) string {
	const hashLen = 7
	return fmt.Sprintf("%s-%s", username, shortHash(canonicalKey, hashLen))
}
