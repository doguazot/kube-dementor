package rbacutil

import "testing"

func TestResourceRuleRestrictions(t *testing.T) {
	for _, tc := range []struct {
		name, group, resource, sub, verb, target string
		groups, resources, verbs, names          []string
		want                                     bool
	}{
		{"named-exec", "", "pods", "exec", "create", "target", []string{""}, []string{"pods/exec"}, []string{"create"}, []string{"target"}, true},
		{"wrong-name", "", "pods", "exec", "create", "other", []string{""}, []string{"pods/exec"}, []string{"create"}, []string{"target"}, false},
		{"wrong-group", "", "pods", "exec", "create", "target", []string{"custom.example"}, []string{"pods/exec"}, []string{"create"}, nil, false},
		{"subresource-wildcard", "", "serviceaccounts", "token", "create", "runner", []string{""}, []string{"*/token"}, []string{"create"}, nil, true},
		{"not-parent-resource", "", "pods", "exec", "create", "target", []string{""}, []string{"pods"}, []string{"create"}, nil, false},
		{"not-resource-prefix-wildcard", "", "pods", "exec", "create", "target", []string{""}, []string{"pods/*"}, []string{"create"}, nil, false},
		{"create-cannot-select-name", "", "pods", "", "create", "", []string{""}, []string{"pods"}, []string{"create"}, []string{"target"}, false},
		{"all-wildcards", "apps", "deployments", "", "patch", "target", []string{"*"}, []string{"*"}, []string{"*"}, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Matches(tc.groups, tc.resources, tc.verbs, tc.names, tc.group, tc.resource, tc.sub, tc.verb, tc.target); got != tc.want {
				t.Fatalf("match=%v, want %v", got, tc.want)
			}
		})
	}
}
