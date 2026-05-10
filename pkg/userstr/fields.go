package userstr

import (
	"fmt"
	"net/url"
	"strings"
)

// UserStrFields is a JSON-friendly representation.
type UserStrFields struct {
	Username  string `json:"username"`
	Blueprint string `json:"blueprint,omitempty"`
	Pod       string `json:"pod,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	RepoOwner string `json:"repoOwner,omitempty"`
	RepoName  string `json:"repoName,omitempty"`
	RepoRef   string `json:"repoRef,omitempty"`
}

// ToUserStr builds a userstr from the fields and parses it (single source of validation truth).
func (f UserStrFields) ToUserStr() (*UserStr, error) {
	raw, err := f.ToRawUserStr()
	if err != nil {
		return nil, err
	}
	return ParseUserStr(raw)
}

// ToRawUserStr returns the serialized userstr that would be parsed.
func (f UserStrFields) ToRawUserStr() (string, error) {
	username := strings.ToLower(strings.TrimSpace(f.Username))
	if username == "" {
		return "", fmt.Errorf("%w: username is required", ErrUserStrInvalid)
	}

	pod := strings.ToLower(strings.TrimSpace(f.Pod))
	ns := strings.ToLower(strings.TrimSpace(f.Namespace))
	repoOwner := strings.ToLower(strings.TrimSpace(f.RepoOwner))
	repoName := strings.ToLower(strings.TrimSpace(f.RepoName))
	repoRef := strings.TrimSpace(f.RepoRef)
	blueprint := strings.TrimSpace(f.Blueprint)

	hasAnyRepoField := repoOwner != "" || repoName != "" || repoRef != ""
	if hasAnyRepoField {
		if blueprint != "" {
			return "", fmt.Errorf("%w: blueprint cannot be specified when repo fields are present", ErrUserStrInvalid)
		}
		if repoName == "" {
			return "", fmt.Errorf("%w: repoName is required when specifying repo fields", ErrUserStrInvalid)
		}
		if repoOwner == "" {
			repoOwner = username
		}

		params := []string{"repo=" + url.PathEscape(repoOwner+"/"+repoName)}
		if repoRef != "" {
			params = append(params, "ref="+url.PathEscape(repoRef))
		}
		if pod != "" {
			params = append(params, "pod="+url.PathEscape(pod))
		}
		if ns != "" {
			params = append(params, "ns="+url.PathEscape(ns))
		}

		raw := username + "~" + strings.Join(params, "+")
		if _, err := ParseUserStr(raw); err != nil {
			return "", err
		}
		return raw, nil
	}

	if blueprint != "" {
		raw := username + "~" + url.PathEscape(blueprint)
		params := make([]string, 0, 3)
		if pod != "" {
			params = append(params, "pod="+url.PathEscape(pod))
		}
		if ns != "" {
			params = append(params, "ns="+url.PathEscape(ns))
		}
		if len(params) > 0 {
			raw += "+" + strings.Join(params, "+")
		}
		if _, err := ParseUserStr(raw); err != nil {
			return "", err
		}
		return raw, nil
	}

	if pod != "" || ns != "" {
		if pod == "" {
			return "", fmt.Errorf("%w: pod is required when specifying namespace or user without blueprint or repo", ErrUserStrInvalid)
		}

		params := []string{"pod=" + url.PathEscape(pod)}
		if ns != "" {
			params = append(params, "ns="+url.PathEscape(ns))
		}

		raw := username + "~" + strings.Join(params, "+")
		if _, err := ParseUserStr(raw); err != nil {
			return "", err
		}
		return raw, nil
	}

	return username, nil
}

// UserStrFieldsFromUserStr creates a payload from a parsed *UserStr.
// Note: Blueprint will be populated from u.Blueprint() (even for repo-derived blueprints).
func UserStrFieldsFromUserStr(u *UserStr) UserStrFields {
	if u == nil {
		return UserStrFields{}
	}

	return UserStrFields{
		Username:  u.Username(),
		Blueprint: u.Blueprint(),
		Pod:       u.Pod(),
		Namespace: u.Namespace(""),
		RepoOwner: u.RepoOwner(),
		RepoName:  u.RepoName(),
		RepoRef:   u.RepoRef(),
	}
}
