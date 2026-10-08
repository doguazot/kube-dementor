package scanner

import (
	"context"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/kube-dementor/kube-dementor/pkg/kubectx"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Inventory struct {
	Pods                []corev1.Pod
	Nodes               []corev1.Node
	Namespaces          []corev1.Namespace
	ServiceAccounts     []corev1.ServiceAccount
	Secrets             []corev1.Secret
	ConfigMaps          []corev1.ConfigMap
	Services            []corev1.Service
	Roles               []rbacv1.Role
	ClusterRoles        []rbacv1.ClusterRole
	RoleBindings        []rbacv1.RoleBinding
	ClusterRoleBindings []rbacv1.ClusterRoleBinding
	NetworkPolicies     []netv1.NetworkPolicy
	APIResources        []metav1.APIResource
	MutatingWebhooks    []admissionv1.MutatingWebhookConfiguration
	ValidatingWebhooks  []admissionv1.ValidatingWebhookConfiguration
	CronJobs            []batchv1.CronJob
	Jobs                []batchv1.Job
	Deployments         []appsv1.Deployment
	DaemonSets          []appsv1.DaemonSet
	StatefulSets        []appsv1.StatefulSet
	NamespaceTargets    []string
	CollectionIssues    []CollectionIssue
	PodAdmission        []PodAdmissionResult
	EphemeralAssessment []EphemeralAssessment
}

type RuleFn func(inv *Inventory, sess *kubectx.Session) []Finding

type Rule struct {
	ID       string
	Title    string
	Category Category
	Fn       RuleFn
}

type Scanner struct {
	rules []Rule
}

func New() *Scanner {
	return &Scanner{}
}

func (s *Scanner) Register(rules ...Rule) {
	s.rules = append(s.rules, rules...)
}

func (s *Scanner) Rules() []Rule {
	return s.rules
}

func (s *Scanner) Scan(inv *Inventory, sess *kubectx.Session) []Finding {
	var all []Finding
	for _, r := range s.rules {
		start := time.Now()
		results := r.Fn(inv, sess)
		for i := range results {
			if results[i].RuleID == "" {
				results[i].RuleID = r.ID
			}
			if results[i].Category == "" {
				results[i].Category = r.Category
			}
			if results[i].DetectedAt.IsZero() {
				results[i].DetectedAt = time.Now()
			}
			if results[i].ID == "" {
				results[i].ID = fmt.Sprintf("%s-%s", r.ID, results[i].Resource.String())
			}
		}
		all = append(all, results...)
		if len(results) > 0 {
			log.Printf("[scanner] rule=%s findings=%d (%s)", r.ID, len(results), time.Since(start))
		}
	}
	return all
}

func BuildInventory(ctx context.Context, sess *kubectx.Session, namespace string) (*Inventory, error) {
	inv := &Inventory{}
	if sess == nil || sess.Client == nil {
		return nil, fmt.Errorf("nil Kubernetes session")
	}
	cs := sess.Client

	fallback := namespace
	if fallback == "" {
		fallback = sess.Info.Namespace
	}
	if fallback == "" {
		fallback = metav1.NamespaceDefault
	}
	inv.NamespaceTargets = []string{fallback}

	nsErr := collectPages(ctx, "", cs.CoreV1().Namespaces().List, func(l *corev1.NamespaceList) {
		for _, ns := range l.Items {
			if namespace == "" || ns.Name == namespace {
				inv.Namespaces = append(inv.Namespaces, ns)
			}
		}
	})
	if namespace == "" {
		for _, ns := range inv.Namespaces {
			inv.NamespaceTargets = append(inv.NamespaceTargets, ns.Name)
		}
	}
	if len(inv.Namespaces) == 0 {
		ns, err := cs.CoreV1().Namespaces().Get(ctx, fallback, metav1.GetOptions{})
		if err == nil {
			inv.Namespaces = append(inv.Namespaces, *ns)
		} else {
			inv.recordIssue("namespaces", fallback, "get", err)
		}
	}
	if nsErr != nil && namespace == "" {
		inv.recordIssue("namespaces", "", "list", nsErr)
	}
	inv.NamespaceTargets = uniqueNamespaces(inv.NamespaceTargets)

	type task struct {
		name       string
		namespaced bool
		fn         func(string) error
	}

	tasks := []task{
		{"pods", true, func(ns string) error {
			return collectPages(ctx, ns, cs.CoreV1().Pods(ns).List, func(l *corev1.PodList) {
				inv.Pods = append(inv.Pods, l.Items...)
			})
		}},
		{"nodes", false, func(_ string) error {
			return collectPages(ctx, "", cs.CoreV1().Nodes().List, func(l *corev1.NodeList) {
				inv.Nodes = append(inv.Nodes, l.Items...)
			})
		}},
		{"service-accounts", true, func(ns string) error {
			return collectPages(ctx, ns, cs.CoreV1().ServiceAccounts(ns).List, func(l *corev1.ServiceAccountList) {
				inv.ServiceAccounts = append(inv.ServiceAccounts, l.Items...)
			})
		}},
		{"secrets", true, func(ns string) error {
			return collectPages(ctx, ns, cs.CoreV1().Secrets(ns).List, func(l *corev1.SecretList) {
				inv.Secrets = append(inv.Secrets, l.Items...)
			})
		}},
		{"configmaps", true, func(ns string) error {
			return collectPages(ctx, ns, cs.CoreV1().ConfigMaps(ns).List, func(l *corev1.ConfigMapList) {
				inv.ConfigMaps = append(inv.ConfigMaps, l.Items...)
			})
		}},
		{"services", true, func(ns string) error {
			return collectPages(ctx, ns, cs.CoreV1().Services(ns).List, func(l *corev1.ServiceList) {
				inv.Services = append(inv.Services, l.Items...)
			})
		}},
		{"roles", true, func(ns string) error {
			return collectPages(ctx, ns, cs.RbacV1().Roles(ns).List, func(l *rbacv1.RoleList) {
				inv.Roles = append(inv.Roles, l.Items...)
			})
		}},
		{"clusterroles", false, func(_ string) error {
			return collectPages(ctx, "", cs.RbacV1().ClusterRoles().List, func(l *rbacv1.ClusterRoleList) {
				inv.ClusterRoles = append(inv.ClusterRoles, l.Items...)
			})
		}},
		{"rolebindings", true, func(ns string) error {
			return collectPages(ctx, ns, cs.RbacV1().RoleBindings(ns).List, func(l *rbacv1.RoleBindingList) {
				inv.RoleBindings = append(inv.RoleBindings, l.Items...)
			})
		}},
		{"clusterrolebindings", false, func(_ string) error {
			return collectPages(ctx, "", cs.RbacV1().ClusterRoleBindings().List, func(l *rbacv1.ClusterRoleBindingList) {
				inv.ClusterRoleBindings = append(inv.ClusterRoleBindings, l.Items...)
			})
		}},
		{"networkpolicies", true, func(ns string) error {
			return collectPages(ctx, ns, cs.NetworkingV1().NetworkPolicies(ns).List, func(l *netv1.NetworkPolicyList) {
				inv.NetworkPolicies = append(inv.NetworkPolicies, l.Items...)
			})
		}},
		{"mutating-webhooks", false, func(_ string) error {
			return collectPages(ctx, "", cs.AdmissionregistrationV1().MutatingWebhookConfigurations().List, func(l *admissionv1.MutatingWebhookConfigurationList) {
				inv.MutatingWebhooks = append(inv.MutatingWebhooks, l.Items...)
			})
		}},
		{"validating-webhooks", false, func(_ string) error {
			return collectPages(ctx, "", cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().List, func(l *admissionv1.ValidatingWebhookConfigurationList) {
				inv.ValidatingWebhooks = append(inv.ValidatingWebhooks, l.Items...)
			})
		}},
		{"cronjobs", true, func(ns string) error {
			return collectPages(ctx, ns, cs.BatchV1().CronJobs(ns).List, func(l *batchv1.CronJobList) {
				inv.CronJobs = append(inv.CronJobs, l.Items...)
			})
		}},
		{"jobs", true, func(ns string) error {
			return collectPages(ctx, ns, cs.BatchV1().Jobs(ns).List, func(l *batchv1.JobList) {
				inv.Jobs = append(inv.Jobs, l.Items...)
			})
		}},
		{"deployments", true, func(ns string) error {
			return collectPages(ctx, ns, cs.AppsV1().Deployments(ns).List, func(l *appsv1.DeploymentList) {
				inv.Deployments = append(inv.Deployments, l.Items...)
			})
		}},
		{"daemonsets", true, func(ns string) error {
			return collectPages(ctx, ns, cs.AppsV1().DaemonSets(ns).List, func(l *appsv1.DaemonSetList) {
				inv.DaemonSets = append(inv.DaemonSets, l.Items...)
			})
		}},
		{"statefulsets", true, func(ns string) error {
			return collectPages(ctx, ns, cs.AppsV1().StatefulSets(ns).List, func(l *appsv1.StatefulSetList) {
				inv.StatefulSets = append(inv.StatefulSets, l.Items...)
			})
		}},
	}

	for _, t := range tasks {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		scope := namespace
		if !t.namespaced {
			scope = ""
		}
		if err := t.fn(scope); err != nil {
			inv.recordIssue(t.name, scope, "list", err)
			if t.namespaced && namespace == "" && apierrors.IsForbidden(err) {
				for _, ns := range inv.NamespaceTargets {
					if err := t.fn(ns); err != nil {
						inv.recordIssue(t.name, ns, "list", err)
					}
				}
			}
		}
	}

	if sess.Discovery != nil {
		apiLists, err := sess.Discovery.ServerPreferredResources()
		for _, group := range apiLists {
			if group != nil {
				inv.APIResources = append(inv.APIResources, group.APIResources...)
			}
		}
		if err != nil {
			inv.recordIssue("api-resources", "", "discover", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	log.Printf("[scanner] inventory: pods=%d nodes=%d ns=%d sas=%d secrets=%d roles=%d crbs=%d netpol=%d",
		len(inv.Pods), len(inv.Nodes), len(inv.Namespaces),
		len(inv.ServiceAccounts), len(inv.Secrets),
		len(inv.Roles)+len(inv.ClusterRoles),
		len(inv.ClusterRoleBindings),
		len(inv.NetworkPolicies))

	return inv, nil
}

func collectPages[T interface{ GetContinue() string }](ctx context.Context, _ string,
	list func(context.Context, metav1.ListOptions) (T, error), consume func(T)) error {
	opts := metav1.ListOptions{Limit: 500}
	for {
		page, err := list(ctx, opts)
		if err != nil {
			return err
		}
		consume(page)
		if page.GetContinue() == "" {
			return nil
		}
		if page.GetContinue() == opts.Continue {
			return fmt.Errorf("pagination returned a repeated continue token")
		}
		opts.Continue = page.GetContinue()
	}
}

func uniqueNamespaces(names []string) []string {
	set := map[string]bool{}
	for _, name := range names {
		if name != "" {
			set[name] = true
		}
	}
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func (inv *Inventory) recordIssue(resource, namespace, operation string, err error) {
	inv.CollectionIssues = append(inv.CollectionIssues, CollectionIssue{
		Resource: resource, Namespace: namespace, Operation: operation, Error: err.Error(),
	})
	log.Printf("[scanner] warn: %s %s namespace=%q failed (partial coverage): %v", operation, resource, namespace, err)
}
