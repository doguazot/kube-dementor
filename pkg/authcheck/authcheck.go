package authcheck

import (
	"context"
	"fmt"
	"log"
	"sort"

	authnv1 "k8s.io/api/authentication/v1"
	authv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type PermCheck struct {
	Namespace string
	Resource  string
	Verb      string
	Allowed   bool
}

type UserPerms struct {
	checks     map[string]bool
	User       string
	Groups     []string
	Namespaces []string
	Errors     map[string]string
}

func NewChecker(ctx context.Context, client kubernetes.Interface, namespaces []string) *UserPerms {
	up := &UserPerms{
		checks: make(map[string]bool),
		Errors: make(map[string]string),
	}

	review, err := client.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authnv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err == nil {
		up.User = review.Status.UserInfo.Username
		up.Groups = append(up.Groups, review.Status.UserInfo.Groups...)
	} else {
		up.Errors["identity"] = err.Error()
	}
	if up.User != "" {
		log.Printf("[authcheck] Current user: %s", up.User)
	} else {
		log.Println("[authcheck] Could not determine current user identity")
	}

	checks := []struct {
		verb     string
		resource string
		group    string
		sub      string
	}{
		{"create", "pods", "", "exec"},
		{"list", "secrets", "", ""},
		{"get", "secrets", "", ""},
		{"create", "pods", "", ""},
		{"list", "pods", "", ""},
		{"get", "pods", "", ""},
		{"get", "serviceaccounts", "", ""},
		{"impersonate", "users", "", ""},
		{"impersonate", "serviceaccounts", "", ""},
		{"impersonate", "groups", "", ""},
	}

	nsSet := make(map[string]bool)
	nsSet[""] = true
	for _, ns := range namespaces {
		nsSet[ns] = true
	}
	for ns := range nsSet {
		up.Namespaces = append(up.Namespaces, ns)
	}
	sort.Strings(up.Namespaces)

	total := 0
	allowed := 0
	for _, ns := range up.Namespaces {
		for _, c := range checks {
			res, err := checkAccess(ctx, client, ns, c.verb, c.group, c.resource, c.sub)
			key := permKey(c.verb, c.resource, c.sub, ns)
			if err != nil {
				up.Errors[key] = err.Error()
			}
			up.checks[key] = res
			total++
			if res {
				allowed++
			}
		}
	}

	log.Printf("[authcheck] Checked %d permissions across %d namespaces — %d allowed", total, len(nsSet), allowed)
	return up
}

func (u *UserPerms) CanI(verb, resource, subresource, namespace string) bool {

	key := permKey(verb, resource, subresource, namespace)
	if v, ok := u.checks[key]; ok {
		return v
	}

	key = permKey(verb, resource, subresource, "")
	if v, ok := u.checks[key]; ok {
		return v
	}
	return false
}

func (u *UserPerms) CanExecInNamespace(ns string) bool {
	return u.CanI("create", "pods", "exec", ns)
}

func (u *UserPerms) CanListSecrets(ns string) bool {
	return u.CanI("list", "secrets", "", ns)
}

func (u *UserPerms) CanImpersonate() bool {
	return u.CanI("impersonate", "users", "", "") ||
		u.CanI("impersonate", "serviceaccounts", "", "") ||
		u.CanI("impersonate", "groups", "", "")
}

func permKey(verb, resource, sub, namespace string) string {
	if sub != "" {
		return fmt.Sprintf("%s:%s/%s:%s", verb, resource, sub, namespace)
	}
	return fmt.Sprintf("%s:%s:%s", verb, resource, namespace)
}

func checkAccess(ctx context.Context, client kubernetes.Interface, namespace, verb, group, resource, subresource string) (bool, error) {
	review := &authv1.SelfSubjectAccessReview{
		Spec: authv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authv1.ResourceAttributes{
				Namespace:   namespace,
				Verb:        verb,
				Group:       group,
				Resource:    resource,
				Subresource: subresource,
			},
		},
	}

	result, err := client.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, review, metav1.CreateOptions{})
	if err != nil {
		return false, err
	}
	if !result.Status.Allowed && result.Status.EvaluationError != "" {
		return false, fmt.Errorf("authorization evaluation: %s", result.Status.EvaluationError)
	}
	return result.Status.Allowed, nil
}
