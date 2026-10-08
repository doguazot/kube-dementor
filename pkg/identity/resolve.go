package identity

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"

	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type Identity struct {
	User                          string
	UID                           string
	Groups                        []string
	Extra                         map[string][]string
	ImpersonatableUsers           []string
	ImpersonatableGroups          []string
	ImpersonatableServiceAccounts []string
	TokenRequestSAs               []string
	DiscoverySource               string

	NamespacedRules map[string][]RuleSummary `json:"namespacedRules,omitempty"`
	Warnings        []string
}

type RuleSummary struct {
	Verbs           []string `json:"verbs,omitempty"`
	APIGroups       []string `json:"apiGroups,omitempty"`
	Resources       []string `json:"resources,omitempty"`
	ResourceNames   []string `json:"resourceNames,omitempty"`
	NonResourceURLs []string `json:"nonResourceURLs,omitempty"`
}

func Resolve(ctx context.Context, client kubernetes.Interface, namespaces []string) (*Identity, error) {
	id := &Identity{Extra: map[string][]string{}}

	if ssr, err := client.AuthenticationV1().SelfSubjectReviews().
		Create(ctx, &authnv1.SelfSubjectReview{}, metav1.CreateOptions{}); err == nil {
		u := ssr.Status.UserInfo
		id.User = u.Username
		id.UID = u.UID
		id.Groups = append(id.Groups, u.Groups...)
		for k, v := range u.Extra {
			id.Extra[k] = append(id.Extra[k], v...)
		}
		id.DiscoverySource = "SelfSubjectReview"
	} else {

		id.DiscoverySource = "fallback-ssar"
		id.Warnings = append(id.Warnings, fmt.Sprintf("SelfSubjectReview unavailable: %v", err))
		if u := whoamiFallback(ctx, client); u != "" {
			id.User = u
		}
	}

	if id.User != "" {
		has := func(needle string) bool {
			for _, g := range id.Groups {
				if g == needle {
					return true
				}
			}
			return false
		}
		group := "system:authenticated"
		if id.User == "system:anonymous" {
			group = "system:unauthenticated"
		}
		if !has(group) {
			id.Groups = append(id.Groups, group)
		}
		if strings.HasPrefix(id.User, "system:serviceaccount:") {
			if !has("system:serviceaccounts") {
				id.Groups = append(id.Groups, "system:serviceaccounts")
			}

			parts := strings.SplitN(strings.TrimPrefix(id.User, "system:serviceaccount:"), ":", 2)
			if len(parts) == 2 {
				nsGroup := "system:serviceaccounts:" + parts[0]
				if !has(nsGroup) {
					id.Groups = append(id.Groups, nsGroup)
				}
			}
		}
	}
	sort.Strings(id.Groups)

	canImp := func(resource string) bool {
		return ssarAllowed(ctx, client, "", "impersonate", "", resource, "", "")
	}
	if canImp("users") {
		id.ImpersonatableUsers = []string{"*"}
	}
	if canImp("groups") {
		id.ImpersonatableGroups = []string{"*"}
	}
	if canImp("serviceaccounts") {
		id.ImpersonatableServiceAccounts = []string{"*"}
	}

	for _, ns := range namespaces {
		if ssarAllowed(ctx, client, ns, "create", "", "serviceaccounts", "token", "") {
			id.TokenRequestSAs = append(id.TokenRequestSAs, ns+"/*")
		}
	}

	id.NamespacedRules = map[string][]RuleSummary{}
	for _, ns := range namespaces {
		if ns == "" {
			continue
		}
		rls, err := resolveRules(ctx, client, ns)
		if err != nil {
			id.Warnings = append(id.Warnings, fmt.Sprintf("SelfSubjectRulesReview namespace=%q: %v", ns, err))
		}
		if len(rls) > 0 {
			id.NamespacedRules[ns] = rls
		}
	}

	log.Printf("[identity] resolved: user=%q groups=%d imp-users=%v imp-groups=%v imp-sas=%v tokenreq=%v (source=%s)",
		id.User, len(id.Groups),
		id.ImpersonatableUsers, id.ImpersonatableGroups,
		id.ImpersonatableServiceAccounts, id.TokenRequestSAs, id.DiscoverySource)

	return id, nil
}

func (id *Identity) Summary() string {
	if id == nil {
		return ""
	}
	parts := []string{fmt.Sprintf("user=%s", id.User)}
	if len(id.Groups) > 0 {
		short := id.Groups
		if len(short) > 4 {
			short = append([]string{}, id.Groups[:4]...)
			short = append(short, fmt.Sprintf("+%d more", len(id.Groups)-4))
		}
		parts = append(parts, "groups=["+strings.Join(short, ",")+"]")
	}
	if len(id.ImpersonatableUsers)+len(id.ImpersonatableGroups)+len(id.ImpersonatableServiceAccounts) > 0 {
		parts = append(parts, "impersonate=yes")
	}
	return strings.Join(parts, " · ")
}

func ssarAllowed(ctx context.Context, client kubernetes.Interface, ns, verb, group, resource, subresource, name string) bool {
	r := &authzv1.SelfSubjectAccessReview{
		Spec: authzv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authzv1.ResourceAttributes{
				Namespace:   ns,
				Verb:        verb,
				Group:       group,
				Resource:    resource,
				Subresource: subresource,
				Name:        name,
			},
		},
	}
	res, err := client.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, r, metav1.CreateOptions{})
	if err != nil {
		return false
	}
	return res.Status.Allowed
}

func resolveRules(ctx context.Context, client kubernetes.Interface, ns string) ([]RuleSummary, error) {
	r := &authzv1.SelfSubjectRulesReview{
		Spec: authzv1.SelfSubjectRulesReviewSpec{Namespace: ns},
	}
	res, err := client.AuthorizationV1().SelfSubjectRulesReviews().Create(ctx, r, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}
	out := make([]RuleSummary, 0, len(res.Status.ResourceRules)+len(res.Status.NonResourceRules))
	for _, r := range res.Status.ResourceRules {
		out = append(out, RuleSummary{
			Verbs:         r.Verbs,
			APIGroups:     r.APIGroups,
			Resources:     r.Resources,
			ResourceNames: r.ResourceNames,
		})
	}
	for _, r := range res.Status.NonResourceRules {
		out = append(out, RuleSummary{
			Verbs:           r.Verbs,
			NonResourceURLs: r.NonResourceURLs,
		})
	}
	if res.Status.Incomplete || res.Status.EvaluationError != "" {
		return out, fmt.Errorf("incomplete authorization rules: %s", res.Status.EvaluationError)
	}
	return out, nil
}

func whoamiFallback(ctx context.Context, client kubernetes.Interface) string {
	r := &authzv1.SelfSubjectAccessReview{
		Spec: authzv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authzv1.ResourceAttributes{
				Verb:     "get",
				Resource: "namespaces",
			},
		},
	}
	res, err := client.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, r, metav1.CreateOptions{})
	if err != nil {

		msg := err.Error()
		if i := strings.Index(msg, `User "`); i >= 0 {
			if j := strings.Index(msg[i+6:], `"`); j > 0 {
				return msg[i+6 : i+6+j]
			}
		}
		return ""
	}
	if res.Status.EvaluationError != "" {
		msg := res.Status.EvaluationError
		if i := strings.Index(msg, `User "`); i >= 0 {
			if j := strings.Index(msg[i+6:], `"`); j > 0 {
				return msg[i+6 : i+6+j]
			}
		}
	}
	return ""
}
