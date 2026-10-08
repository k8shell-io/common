package nats

import "strings"

// ThreatSubject builds the subject a threat is published on:
//
//	worktrace.threats.<namespace>.<workspace>.<rule>
//
// so consumers can filter by namespace, workspace or rule without parsing the
// payload. Empty parts become "_", and characters that are not allowed in a
// NATS subject token (. * > whitespace) are replaced with "_".
func ThreatSubject(namespace, workspace, rule string) string {
	return strings.Join([]string{
		THREATS_SUBJECT_PREFIX,
		subjectToken(namespace),
		subjectToken(workspace),
		subjectToken(rule),
	}, ".")
}

func subjectToken(s string) string {
	if s == "" {
		return "_"
	}
	return strings.Map(func(r rune) rune {
		switch r {
		case '.', '*', '>', ' ', '\t', '\n', '\r':
			return '_'
		}
		return r
	}, s)
}
