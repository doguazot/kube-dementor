package rbacutil

import "strings"

func Contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func Matches(groups, resources, verbs, names []string, group, resource, subresource, verb, name string) bool {
	if !Contains(groups, "*") && !Contains(groups, group) {
		return false
	}
	if !Contains(verbs, "*") && !Contains(verbs, verb) {
		return false
	}
	combined := resource
	if subresource != "" {
		combined += "/" + subresource
	}
	if !Contains(resources, "*") && !Contains(resources, combined) &&
		!(subresource != "" && Contains(resources, "*/"+subresource)) {
		return false
	}
	return len(names) == 0 || (name != "" && Contains(names, name))
}

func SplitResource(resource string) (string, string) {
	parts := strings.SplitN(resource, "/", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return resource, ""
}
