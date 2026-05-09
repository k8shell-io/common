package userstr

type UserStrParamSpec struct {
	AllowedIn map[UserStrForm]bool
}

type UserStrGrammar struct {
	MaxTotalLen int
	Params      map[string]UserStrParamSpec
}

func DefaultGrammar() UserStrGrammar {
	return UserStrGrammar{
		MaxTotalLen: MAX_TOTAL_LEN,
		Params: map[string]UserStrParamSpec{
			"repo": {
				AllowedIn: map[UserStrForm]bool{UserStrFormRepoWorkspace: true},
			},
			"ref": {
				AllowedIn: map[UserStrForm]bool{UserStrFormRepoWorkspace: true},
			},
			"user": {
				AllowedIn: map[UserStrForm]bool{
					UserStrFormExplicitBlueprint: true,
					UserStrFormNamedWorkspace:    true,
					UserStrFormRepoWorkspace:     true,
					UserStrFormImplicit:          true,
				},
			},
			"pod": {
				AllowedIn: map[UserStrForm]bool{
					UserStrFormExplicitBlueprint: true,
					UserStrFormNamedWorkspace:    true,
					UserStrFormRepoWorkspace:     true,
				},
			},
			"ns": {
				AllowedIn: map[UserStrForm]bool{
					UserStrFormExplicitBlueprint: true,
					UserStrFormNamedWorkspace:    true,
					UserStrFormRepoWorkspace:     true,
				},
			},
		},
	}
}

func isParamAllowedInForm(grammar UserStrGrammar, key string, form UserStrForm) bool {
	spec, ok := grammar.Params[key]
	if !ok {
		return false
	}
	return spec.AllowedIn[form]
}

func cloneMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
