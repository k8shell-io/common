package userstr

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"
)

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
			raw:           rawTrimmed,
			form:          UserStrFormImplicit,
			username:      username,
			blueprintKind: BlueprintKindImplicit,
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

		bpWorkload := params["workload"]
		bpNs := params["ns"]
		if bpWorkload != "" && bpNs == "" {
			return nil, fmt.Errorf("%w: ns is required with workload", ErrUserStrInvalid)
		}
		if bpNs != "" && bpWorkload == "" {
			return nil, fmt.Errorf("%w: workload is required with ns in blueprint form", ErrUserStrInvalid)
		}
		bpWorkloadKind, bpWorkloadName, _ := strings.Cut(bpWorkload, "/")
		return &UserStr{
			raw:           rawTrimmed,
			form:          UserStrFormExplicitBlueprint,
			username:      username,
			user:          params["user"],
			workloadKind:  bpWorkloadKind,
			workloadName:  bpWorkloadName,
			namespace:     bpNs,
			blueprint:     bpDecoded,
			blueprintKind: BlueprintKindExplicit,
			paramsRaw:     cloneMap(params),
		}, nil
	}

	params, err := parseKVParts(parts, grammar)
	if err != nil {
		return nil, err
	}

	ns := params["ns"]
	pod := params["pod"]
	workload := params["workload"]
	repo := params["repo"]
	workloadKind, workloadName, _ := strings.Cut(workload, "/")

	// Named workspace form: pod is the primary key; no repo, no deploy allowed.
	if pod != "" {
		if repo != "" {
			return nil, fmt.Errorf("%w: pod cannot be combined with repo", ErrUserStrInvalid)
		}
		if params["workload"] != "" {
			return nil, fmt.Errorf("%w: pod cannot be combined with workload", ErrUserStrInvalid)
		}
		for k := range params {
			if !isParamAllowedInForm(grammar, k, UserStrFormNamedWorkspace) {
				return nil, fmt.Errorf("%w: param %q is not allowed with pod form", ErrUserStrInvalid, k)
			}
		}
		return &UserStr{
			raw:           rawTrimmed,
			form:          UserStrFormNamedWorkspace,
			username:      username,
			user:          params["user"],
			pod:           pod,
			namespace:     ns,
			blueprintKind: BlueprintKindImplicit,
			paramsRaw:     cloneMap(params),
		}, nil
	}

	// Repo form (repo required; deploy+ns optional but must appear together).
	for k := range params {
		if !isParamAllowedInForm(grammar, k, UserStrFormRepoWorkspace) {
			return nil, fmt.Errorf("%w: param %q is not allowed in repo form", ErrUserStrInvalid, k)
		}
	}

	if repo == "" {
		return nil, fmt.Errorf("%w: repo is required in param-list form", ErrUserStrInvalid)
	}
	if workload != "" && ns == "" {
		return nil, fmt.Errorf("%w: ns is required with workload", ErrUserStrInvalid)
	}
	if ns != "" && workload == "" {
		return nil, fmt.Errorf("%w: ns requires workload in repo form", ErrUserStrInvalid)
	}

	repoRef := params["ref"]

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
		raw:           rawTrimmed,
		form:          UserStrFormRepoWorkspace,
		username:      username,
		user:          params["user"],
		workloadKind:  workloadKind,
		workloadName:  workloadName,
		namespace:     ns,
		blueprint:     blueprint,
		blueprintKind: BlueprintKindCustom,
		paramsRaw:     cloneMap(params),
		repoOwner:     repoOwner,
		repoName:      repoName,
		repoRef:       repoRef,
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
		// workload kind is case-sensitive (e.g. Deployment, StatefulSet); preserve case
		if key == "workload" {
			params[key] = decoded
		} else {
			params[key] = strings.ToLower(decoded)
		}
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
