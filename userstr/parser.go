package userstr

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"
)

var allowedTargetKinds = map[string]bool{
	"deploy": true,
	"sts":    true,
	"ds":     true,
}

func parseTarget(target string) (kind string, name string, err error) {
	k, n, ok := cutOnce(strings.TrimSpace(target), "/")
	if !ok {
		return "", "", fmt.Errorf("%w: target must be kind/name", ErrUserStrInvalid)
	}
	kind = strings.ToLower(strings.TrimSpace(k))
	name = strings.ToLower(strings.TrimSpace(n))
	if kind == "" || name == "" {
		return "", "", fmt.Errorf("%w: target kind and name are required", ErrUserStrInvalid)
	}
	if !allowedTargetKinds[kind] {
		return "", "", fmt.Errorf("%w: target kind %q is not supported, use deploy|sts|ds", ErrUserStrInvalid, kind)
	}
	return kind, name, nil
}

func ParseUserStr(input string) (*UserStr, error) {
	g := DefaultGrammar()
	return ParseUserStrWithGrammar(input, g)
}

func ParseUserStrWithGrammar(input string, grammar UserStrGrammar) (*UserStr, error) {
	rawTrimmed := strings.TrimSpace(input)
	if rawTrimmed == "" {
		return nil, fmt.Errorf("%w: empty input", ErrUserStrMalformed)
	}

	lowerRaw := strings.ToLower(rawTrimmed)
	if strings.HasPrefix(lowerRaw, "b64-") || strings.HasPrefix(lowerRaw, "base64-") {
		_, payload, ok := cutOnce(rawTrimmed, "-")
		if !ok {
			return nil, fmt.Errorf("%w: malformed b64 prefix", ErrUserStrMalformed)
		}
		decoded, err := base64.RawURLEncoding.DecodeString(payload)
		if err != nil {
			return nil, fmt.Errorf("%w: base64 decode failed: %v", ErrB64UserStrInvalid, err)
		}
		return ParseUserStrWithGrammar(string(decoded), grammar)
	}

	if grammar.MaxTotalLen > 0 && utf8.RuneCountInString(rawTrimmed) > grammar.MaxTotalLen {
		return nil, fmt.Errorf("%w: raw>%d", ErrTooLong, grammar.MaxTotalLen)
	}

	usernamePart, wsSpec, _ := cutOnce(rawTrimmed, "~")
	username := strings.ToLower(strings.TrimSpace(usernamePart))
	if username == "" {
		return nil, fmt.Errorf("%w: username is required", ErrUserStrMalformed)
	}

	if strings.TrimSpace(wsSpec) == "" {
		return &UserStr{
			Raw:           rawTrimmed,
			Form:          UserStrFormImplicit,
			Username:      username,
			BlueprintKind: BlueprintKindImplicit,
		}, nil
	}

	wsSpec = strings.TrimSpace(wsSpec)
	parts := strings.Split(wsSpec, "+")
	if len(parts) == 0 {
		return nil, fmt.Errorf("%w: empty workspace spec", ErrUserStrMalformed)
	}

	first := strings.TrimSpace(parts[0])
	if first == "" {
		return nil, fmt.Errorf("%w: empty workspace segment", ErrUserStrMalformed)
	}

	if !strings.Contains(first, "=") {
		bpDecoded, err := url.PathUnescape(first)
		if err != nil {
			return nil, fmt.Errorf("%w: blueprint decode failed: %v", ErrUserStrMalformed, err)
		}

		params, err := parseKVParts(parts[1:], grammar)
		if err != nil {
			return nil, err
		}

		for k := range params {
			if !isParamAllowedInForm(grammar, k, UserStrFormExplicitBlueprint) {
				return nil, fmt.Errorf("%w: param %q is not allowed with explicit blueprint", ErrUserStrInvalid, k)
			}
		}

		target, hasTarget := params["target"]
		ns, hasNS := params["ns"]
		targetKind := ""
		targetName := ""
		if hasNS && (!hasTarget || strings.TrimSpace(target) == "") {
			return nil, fmt.Errorf("%w: ns requires non-empty target", ErrUserStrInvalid)
		}
		if hasTarget && strings.TrimSpace(target) != "" && !hasNS {
			return nil, fmt.Errorf("%w: target requires ns", ErrUserStrInvalid)
		}
		if strings.TrimSpace(target) != "" {
			var targetErr error
			targetKind, targetName, targetErr = parseTarget(target)
			if targetErr != nil {
				return nil, targetErr
			}
			target = targetKind + "/" + targetName
		}

		return &UserStr{
			Raw:           rawTrimmed,
			Form:          UserStrFormExplicitBlueprint,
			Username:      username,
			User:          params["user"],
			Target:        target,
			TargetKind:    targetKind,
			TargetName:    targetName,
			Namespace:     ns,
			Blueprint:     bpDecoded,
			BlueprintKind: BlueprintKindExplicit,
			ParamsRaw:     cloneMap(params),
		}, nil
	}

	params, err := parseKVParts(parts, grammar)
	if err != nil {
		return nil, err
	}

	target, hasTarget := params["target"]
	ns, hasNS := params["ns"]
	targetKind := ""
	targetName := ""
	if hasNS && ((params["pod"] == "" && strings.TrimSpace(target) == "") || (!hasTarget && params["pod"] == "")) {
		return nil, fmt.Errorf("%w: ns requires pod or non-empty target", ErrUserStrInvalid)
	}
	if hasTarget && strings.TrimSpace(target) != "" && !hasNS {
		return nil, fmt.Errorf("%w: target requires ns", ErrUserStrInvalid)
	}
	if strings.TrimSpace(target) != "" {
		var targetErr error
		targetKind, targetName, targetErr = parseTarget(target)
		if targetErr != nil {
			return nil, targetErr
		}
		target = targetKind + "/" + targetName
	}

	if params["pod"] != "" {
		for k := range params {
			if !isParamAllowedInForm(grammar, k, UserStrFormNamedWorkspace) {
				return nil, fmt.Errorf("%w: param %q is not allowed with pod form", ErrUserStrInvalid, k)
			}
		}
		if !hasNS || strings.TrimSpace(ns) == "" {
			return nil, fmt.Errorf("%w: pod requires ns", ErrUserStrInvalid)
		}
		return &UserStr{
			Raw:           rawTrimmed,
			Form:          UserStrFormNamedWorkspace,
			Username:      username,
			User:          params["user"],
			Pod:           params["pod"],
			Namespace:     ns,
			BlueprintKind: BlueprintKindImplicit,
			ParamsRaw:     cloneMap(params),
		}, nil
	}

	if strings.TrimSpace(target) != "" && params["repo"] == "" {
		return &UserStr{
			Raw:           rawTrimmed,
			Form:          UserStrFormImplicit,
			Username:      username,
			User:          params["user"],
			Target:        target,
			TargetKind:    targetKind,
			TargetName:    targetName,
			Namespace:     ns,
			BlueprintKind: BlueprintKindImplicit,
			ParamsRaw:     cloneMap(params),
		}, nil
	}

	for k := range params {
		if !isParamAllowedInForm(grammar, k, UserStrFormRepoWorkspace) {
			return nil, fmt.Errorf("%w: param %q is not allowed in repo form", ErrUserStrInvalid, k)
		}
	}

	repo := params["repo"]
	if repo == "" {
		return nil, fmt.Errorf("%w: repo is required in param-list form", ErrUserStrInvalid)
	}

	repoRef := params["ref"]
	if strings.TrimSpace(target) != "" && strings.TrimSpace(repoRef) == "" {
		return nil, fmt.Errorf("%w: target in repo form requires ref", ErrUserStrInvalid)
	}

	repoOwner := username
	repoName := repo
	if owner, name, found := cutOnce(repo, "/"); found {
		repoOwner = owner
		repoName = name
	}
	if strings.TrimSpace(repoName) == "" {
		return nil, fmt.Errorf("%w: repo name is empty", ErrUserStrInvalid)
	}

	blueprint := fmt.Sprintf("repo-%s-%s", repoOwner, repoName)

	return &UserStr{
		Raw:           rawTrimmed,
		Form:          UserStrFormRepoWorkspace,
		Username:      username,
		User:          params["user"],
		Target:        target,
		TargetKind:    targetKind,
		TargetName:    targetName,
		Namespace:     ns,
		Blueprint:     blueprint,
		BlueprintKind: BlueprintKindCustom,
		ParamsRaw:     cloneMap(params),
		RepoOwner:     repoOwner,
		RepoName:      repoName,
		RepoRef:       repoRef,
	}, nil
}

func parseKVParts(parts []string, grammar UserStrGrammar) (map[string]string, error) {
	params := make(map[string]string, len(parts))
	for _, p := range parts {
		part := strings.TrimSpace(p)
		if part == "" {
			return nil, fmt.Errorf("%w: empty parameter segment", ErrUserStrMalformed)
		}
		k, v, ok := cutOnce(part, "=")
		if !ok || strings.TrimSpace(k) == "" {
			return nil, fmt.Errorf("%w: expected key=value, got %q", ErrUserStrMalformed, part)
		}
		if strings.Contains(v, "=") {
			return nil, fmt.Errorf("%w: unescaped '=' in value: %q", ErrUserStrMalformed, part)
		}

		key := strings.ToLower(strings.TrimSpace(k))
		if _, ok := grammar.Params[key]; !ok {
			return nil, fmt.Errorf("%w: unknown param key %q", ErrUserStrInvalid, key)
		}

		decoded, err := url.PathUnescape(strings.TrimSpace(v))
		if err != nil {
			return nil, fmt.Errorf("%w: value decode failed for key %q: %v", ErrUserStrMalformed, key, err)
		}
		params[key] = strings.ToLower(decoded)
	}
	if len(params) == 0 {
		return nil, nil
	}
	return params, nil
}

func cutOnce(s, sep string) (string, string, bool) {
	i := strings.Index(s, sep)
	if i < 0 {
		return s, "", false
	}
	return s[:i], s[i+len(sep):], true
}
