package userstr

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

func (u *UserStr) Canonicalize() (*CanonicalUserStr, error) {
	if u == nil {
		return nil, fmt.Errorf("%w: nil userstr", ErrUserStrInvalid)
	}

	identity := WorkspaceIdentity{
		username:      u.username,
		blueprint:     u.blueprint,
		blueprintKind: u.blueprintKind,
		repoOwner:     u.repoOwner,
		repoName:      u.repoName,
		repoRef:       u.repoRef,
	}

	out := &CanonicalUserStr{identity: identity}
	out.canonicalKey = buildWorkspaceKey(identity)
	out.canonicalUserStr = buildCanonicalUserStr(identity, u.user, u.pod, u.deploy, u.namespace)
	out.aliases = buildAliases(u)
	if u.pod != "" {
		out.workspaceName = u.pod
	} else {
		out.workspaceName = buildCanonicalId(u.username, out.canonicalKey)
	}

	parsed, err := ParseUserStr(out.canonicalUserStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse canonical userstr: %w", err)
	}
	out.canonicalUserStrObj = parsed

	return out, nil
}

func buildWorkspaceKey(id WorkspaceIdentity) string {
	parts := []string{"u=" + id.username}
	if id.repoOwner != "" && id.repoName != "" {
		parts = append(parts, "r="+id.repoOwner+"/"+id.repoName)
	}
	if id.repoRef != "" {
		parts = append(parts, "ref="+id.repoRef)
	}
	if id.blueprint != "" {
		parts = append(parts, "bp="+id.blueprint)
	}
	return strings.Join(parts, "|")
}

func buildCanonicalUserStr(id WorkspaceIdentity, user, pod, deploy, ns string) string {
	canonicalUser := strings.ToLower(strings.TrimSpace(user))
	canonicalPod := strings.ToLower(strings.TrimSpace(pod))
	canonicalDeploy := strings.ToLower(strings.TrimSpace(deploy))
	canonicalNs := strings.ToLower(strings.TrimSpace(ns))

	// Repo form: deploy+ns are optional and must appear together.
	if id.repoOwner != "" && id.repoName != "" {
		params := map[string]string{"repo": id.repoOwner + "/" + id.repoName}
		if id.repoRef != "" {
			params["ref"] = id.repoRef
		}
		if canonicalDeploy != "" {
			params["deploy"] = canonicalDeploy
			params["ns"] = canonicalNs
		}
		if canonicalUser != "" {
			params["user"] = canonicalUser
		}
		return id.username + "~" + joinParamsCanonical(params)
	}

	// Blueprint form.
	if id.blueprint != "" {
		raw := id.username + "~" + url.PathEscape(id.blueprint)
		if canonicalDeploy != "" {
			raw += "+deploy=" + url.PathEscape(canonicalDeploy)
			raw += "+ns=" + url.PathEscape(canonicalNs)
		}
		if canonicalUser != "" {
			raw += "+user=" + url.PathEscape(canonicalUser)
		}
		return raw
	}

	// Named workspace form.
	if canonicalPod != "" {
		parts := []string{"pod=" + url.PathEscape(canonicalPod)}
		if canonicalNs != "" {
			parts = append(parts, "ns="+url.PathEscape(canonicalNs))
		}
		if canonicalUser != "" {
			parts = append(parts, "user="+url.PathEscape(canonicalUser))
		}
		return id.username + "~" + strings.Join(parts, "+")
	}

	return id.username
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
	aliases := []string{"raw:" + u.raw}
	if u.repoOwner != "" && u.repoName != "" && u.repoRef != "" {
		aliases = append(aliases, fmt.Sprintf("u=%s|r=%s/%s|ref=%s", u.username, u.repoOwner, u.repoName, u.repoRef))
	}
	return aliases
}

func shortHash(s string, n int) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])[:n]
}

func buildCanonicalId(username, canonicalKey string) string {
	const hashLen = 7
	return fmt.Sprintf("%s-%s", username, shortHash(canonicalKey, hashLen))
}
