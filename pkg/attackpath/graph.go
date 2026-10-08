package attackpath

import (
	"fmt"
	"strings"

	"github.com/kube-dementor/kube-dementor/pkg/rbacutil"
	"github.com/kube-dementor/kube-dementor/pkg/scanner"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

type NodeKind string

const (
	KindUser           NodeKind = "User"
	KindGroup          NodeKind = "Group"
	KindServiceAccount NodeKind = "ServiceAccount"
	KindRole           NodeKind = "Role"
	KindClusterRole    NodeKind = "ClusterRole"
	KindPod            NodeKind = "Pod"
	KindSecret         NodeKind = "Secret"
	KindConfigMap      NodeKind = "ConfigMap"
	KindNode           NodeKind = "Node"
	KindNamespace      NodeKind = "Namespace"
	KindClusterAdmin   NodeKind = "ClusterAdmin"
)

type EdgeKind string

const (
	EdgeBoundTo            EdgeKind = "BoundTo"
	EdgeGrantsRead         EdgeKind = "GrantsRead"
	EdgeGrantsWrite        EdgeKind = "GrantsWrite"
	EdgeGrantsExec         EdgeKind = "GrantsExec"
	EdgeCanInjectEphemeral EdgeKind = "CanInjectEphemeral"
	EdgeCanInteract        EdgeKind = "CanInteract"
	EdgeMountedBy          EdgeKind = "MountedBy"
	EdgeUsedBy             EdgeKind = "UsedBy"
	EdgeContainsToken      EdgeKind = "ContainsToken"
	EdgeReadsMountedSecret EdgeKind = "ReadsMountedSecret"
	EdgeCanEscape          EdgeKind = "CanEscape"
	EdgeImpersonate        EdgeKind = "Impersonate"

	EdgeMemberOf            EdgeKind = "MemberOf"
	EdgeCanImpersonateIdent EdgeKind = "CanImpersonateIdentity"
	EdgeCanTokenRequest     EdgeKind = "CanTokenRequest"
	EdgeCanDo               EdgeKind = "CanDo"
)

type Node struct {
	ID        string
	Kind      NodeKind
	Namespace string
	Name      string
	HighValue bool
	Status    string
	Detail    string
}

type Edge struct {
	Kind EdgeKind
	Note string
	To   string
}

type Graph struct {
	Nodes map[string]*Node
	Out   map[string][]Edge
}

func NewGraph() *Graph {
	return &Graph{Nodes: map[string]*Node{}, Out: map[string][]Edge{}}
}

func (g *Graph) addNode(n *Node) *Node {
	if existing, ok := g.Nodes[n.ID]; ok {
		if n.HighValue {
			existing.HighValue = true
		}
		return existing
	}
	g.Nodes[n.ID] = n
	return n
}

func (g *Graph) addEdge(from, to string, k EdgeKind, note string) {
	for _, edge := range g.Out[from] {
		if edge.To == to && edge.Kind == k && edge.Note == note {
			return
		}
	}
	g.Out[from] = append(g.Out[from], Edge{Kind: k, Note: note, To: to})
}

func nodeID(kind NodeKind, ns, name string) string {
	if ns == "" {
		return fmt.Sprintf("%s/%s", kind, name)
	}
	return fmt.Sprintf("%s/%s/%s", kind, ns, name)
}

func Build(inv *scanner.Inventory) *Graph {
	g := NewGraph()

	for _, ns := range inv.Namespaces {
		g.addNode(&Node{ID: nodeID(KindNamespace, "", ns.Name), Kind: KindNamespace, Name: ns.Name})
	}

	for _, sa := range inv.ServiceAccounts {
		AddIdentity(g, "system:serviceaccount:"+sa.Namespace+":"+sa.Name,
			[]string{"system:authenticated", "system:serviceaccounts", "system:serviceaccounts:" + sa.Namespace}, nil, nil, nil)
	}
	for _, node := range inv.Nodes {
		g.addNode(&Node{ID: nodeID(KindNode, "", node.Name), Kind: KindNode, Name: node.Name, HighValue: true})
	}

	for _, binding := range inv.ClusterRoleBindings {
		for _, subject := range binding.Subjects {
			subjectID(g, subject)
		}
	}
	for _, binding := range inv.RoleBindings {
		for _, subject := range binding.Subjects {
			if subject.Kind == "ServiceAccount" && subject.Namespace == "" {
				subject.Namespace = binding.Namespace
			}
			subjectID(g, subject)
		}
	}

	tokenSecrets := map[string]bool{}
	for _, secret := range inv.Secrets {
		tokenSecrets[secret.Namespace+"/"+secret.Name] = secret.Type == corev1.SecretTypeServiceAccountToken
	}
	for _, p := range inv.Pods {
		pid := nodeID(KindPod, p.Namespace, p.Name)
		g.addNode(&Node{ID: pid, Kind: KindPod, Namespace: p.Namespace, Name: p.Name})
		saName := p.Spec.ServiceAccountName
		if saName == "" {
			saName = "default"
		}
		sid := nodeID(KindServiceAccount, p.Namespace, saName)
		AddIdentity(g, "system:serviceaccount:"+p.Namespace+":"+saName,
			[]string{"system:authenticated", "system:serviceaccounts", "system:serviceaccounts:" + p.Namespace}, nil, nil, nil)
		g.addEdge(sid, pid, EdgeUsedBy, "SA runs pod")
		canReadCredential := func(name string) bool {
			return !tokenSecrets[p.Namespace+"/"+name] || scanner.SecretTokenExposed(&p, name)
		}
		if scanner.HasServiceAccountToken(inv, &p) {
			g.addEdge(pid, sid, EdgeContainsToken, "pod SA token; projected audience and runtime access may require verification")
		}

		if p.Spec.NodeName != "" {
			nid := nodeID(KindNode, "", p.Spec.NodeName)
			g.addNode(&Node{ID: nid, Kind: KindNode, Name: p.Spec.NodeName, HighValue: true})
			if reason := scanner.PodEscapeReason(&p); reason != "" {
				g.addEdge(pid, nid, EdgeCanEscape, reason)
			}
		}

		for _, v := range p.Spec.Volumes {
			if v.Secret != nil {
				sid := nodeID(KindSecret, p.Namespace, v.Secret.SecretName)
				g.addNode(&Node{ID: sid, Kind: KindSecret, Namespace: p.Namespace, Name: v.Secret.SecretName})
				g.addEdge(sid, pid, EdgeMountedBy, "volume")
				if volumeMounted(&p, v.Name) && canReadCredential(v.Secret.SecretName) {
					g.addEdge(pid, sid, EdgeReadsMountedSecret, "mounted secret volume")
				}
			}
			if v.Projected != nil {
				for _, src := range v.Projected.Sources {
					if src.Secret != nil {
						sid := nodeID(KindSecret, p.Namespace, src.Secret.Name)
						g.addNode(&Node{ID: sid, Kind: KindSecret, Namespace: p.Namespace, Name: src.Secret.Name})
						g.addEdge(sid, pid, EdgeMountedBy, "projected")
						if volumeMounted(&p, v.Name) && canReadCredential(src.Secret.Name) {
							g.addEdge(pid, sid, EdgeReadsMountedSecret, "mounted projected secret")
						}
					}
				}
			}
		}
		for _, c := range scanner.Containers(&p) {
			for _, ef := range c.EnvFrom {
				if ef.SecretRef != nil {
					sid := nodeID(KindSecret, p.Namespace, ef.SecretRef.Name)
					g.addNode(&Node{ID: sid, Kind: KindSecret, Namespace: p.Namespace, Name: ef.SecretRef.Name})
					g.addEdge(sid, pid, EdgeMountedBy, "envFrom")
					if canReadCredential(ef.SecretRef.Name) {
						g.addEdge(pid, sid, EdgeReadsMountedSecret, "secret environment")
					}
				}
			}
			for _, e := range c.Env {
				if e.ValueFrom != nil && e.ValueFrom.SecretKeyRef != nil {
					sid := nodeID(KindSecret, p.Namespace, e.ValueFrom.SecretKeyRef.Name)
					g.addNode(&Node{ID: sid, Kind: KindSecret, Namespace: p.Namespace, Name: e.ValueFrom.SecretKeyRef.Name})
					g.addEdge(sid, pid, EdgeMountedBy, "env")
					if canReadCredential(e.ValueFrom.SecretKeyRef.Name) {
						g.addEdge(pid, sid, EdgeReadsMountedSecret, "secret environment")
					}
				}
			}
		}
	}

	for _, s := range inv.Secrets {
		sid := nodeID(KindSecret, s.Namespace, s.Name)
		g.addNode(&Node{ID: sid, Kind: KindSecret, Namespace: s.Namespace, Name: s.Name})
		if s.Type == corev1.SecretTypeServiceAccountToken && len(s.Data["token"]) > 0 {
			saName := s.Annotations["kubernetes.io/service-account.name"]
			if saName != "" {
				said := nodeID(KindServiceAccount, s.Namespace, saName)
				AddIdentity(g, "system:serviceaccount:"+s.Namespace+":"+saName,
					[]string{"system:authenticated", "system:serviceaccounts", "system:serviceaccounts:" + s.Namespace}, nil, nil, nil)
				g.addEdge(sid, said, EdgeContainsToken, "legacy SA token")
			}
		}
	}

	clusterRoles := map[string]rbacv1.ClusterRole{}
	for _, r := range inv.ClusterRoles {
		clusterRoles[r.Name] = r
		crid := nodeID(KindClusterRole, "", r.Name)
		g.addNode(&Node{ID: crid, Kind: KindClusterRole, Name: r.Name})
	}
	for _, r := range inv.Roles {
		rid := nodeID(KindRole, r.Namespace, r.Name)
		g.addNode(&Node{ID: rid, Kind: KindRole, Namespace: r.Namespace, Name: r.Name})
		for _, rule := range r.Rules {
			addRuleEdges(g, rid, rule, r.Namespace, inv)
		}
	}

	for _, crb := range inv.ClusterRoleBindings {
		if crb.RoleRef.Kind != "ClusterRole" {
			continue
		}
		crid := nodeID(KindClusterRole, "", crb.RoleRef.Name)
		if role, ok := clusterRoles[crb.RoleRef.Name]; ok {
			for _, rule := range role.Rules {
				addRuleEdges(g, crid, rule, "", inv)
			}
		}
		for _, s := range crb.Subjects {
			subID := subjectID(g, s)
			if subID == "" {
				continue
			}
			g.addEdge(subID, crid, EdgeBoundTo, "ClusterRoleBinding "+crb.Name)
		}
	}
	for _, rb := range inv.RoleBindings {
		var target string
		switch rb.RoleRef.Kind {
		case "ClusterRole":
			target = nodeID(KindClusterRole, rb.Namespace, rb.RoleRef.Name)
			g.addNode(&Node{ID: target, Kind: KindClusterRole, Namespace: rb.Namespace, Name: rb.RoleRef.Name})
			if role, ok := clusterRoles[rb.RoleRef.Name]; ok {
				for _, rule := range role.Rules {
					addRuleEdges(g, target, rule, rb.Namespace, inv)
				}
			}
		case "Role":
			target = nodeID(KindRole, rb.Namespace, rb.RoleRef.Name)
		default:
			continue
		}
		for _, s := range rb.Subjects {
			if s.Kind == "ServiceAccount" && s.Namespace == "" {
				s.Namespace = rb.Namespace
			}
			subID := subjectID(g, s)
			if subID == "" {
				continue
			}
			g.addEdge(subID, target, EdgeBoundTo, "RoleBinding "+rb.Name)
		}
	}

	return g
}

func AugmentRules(g *Graph, me string, rules map[string][]scanner.NamespacedRule, inv *scanner.Inventory) {
	for ns, entries := range rules {
		if ns == "" || me == "" {
			continue
		}
		holder := "EffectiveRole/" + ns + "/" + me
		g.addNode(&Node{ID: holder, Kind: "EffectiveRole", Namespace: ns, Name: "effective permissions"})
		g.addEdge(me, holder, EdgeBoundTo, "SelfSubjectRulesReview; namespace-scoped authorization")
		for _, entry := range entries {
			addRuleEdges(g, holder, rbacv1.PolicyRule{
				APIGroups: entry.APIGroups, Resources: entry.Resources,
				Verbs: entry.Verbs, ResourceNames: entry.ResourceNames,
				NonResourceURLs: entry.NonResourceURLs,
			}, ns, inv)
		}
	}
}

func AddIdentity(g *Graph, user string, groups []string, impUsers, impGroups, impSAs []string) string {
	if user == "" {
		return ""
	}
	var me string
	if strings.HasPrefix(user, "system:serviceaccount:") {
		parts := strings.SplitN(strings.TrimPrefix(user, "system:serviceaccount:"), ":", 2)
		if len(parts) == 2 {
			me = nodeID(KindServiceAccount, parts[0], parts[1])
			g.addNode(&Node{ID: me, Kind: KindServiceAccount, Namespace: parts[0], Name: parts[1]})
		}
	}
	if me == "" {
		me = nodeID(KindUser, "", user)
		g.addNode(&Node{ID: me, Kind: KindUser, Name: user})
	}
	for _, grp := range groups {
		gid := nodeID(KindGroup, "", grp)
		g.addNode(&Node{ID: gid, Kind: KindGroup, Name: grp})
		g.addEdge(me, gid, EdgeMemberOf, "authenticated group")
	}

	if hasWild(impUsers) {
		tgt := nodeID(KindUser, "", "*")
		g.addNode(&Node{ID: tgt, Kind: KindUser, Name: "*", HighValue: true})
		g.addEdge(me, tgt, EdgeCanImpersonateIdent, "impersonate any user")
	}
	if hasWild(impGroups) {
		tgt := nodeID(KindGroup, "", "*")
		g.addNode(&Node{ID: tgt, Kind: KindGroup, Name: "*", HighValue: true})
		g.addEdge(me, tgt, EdgeCanImpersonateIdent, "impersonate any group (incl. system:masters!)")
	}
	if hasWild(impSAs) {
		tgt := nodeID(KindServiceAccount, "*", "*")
		g.addNode(&Node{ID: tgt, Kind: KindServiceAccount, Namespace: "*", Name: "*", HighValue: true})
		g.addEdge(me, tgt, EdgeCanImpersonateIdent, "impersonate any SA")
	}
	for _, target := range g.Nodes {
		if target.ID == me {
			continue
		}
		switch target.Kind {
		case KindUser:
			if hasWild(impUsers) || rbacutil.Contains(impUsers, target.Name) {
				g.addEdge(me, target.ID, EdgeCanImpersonateIdent, "impersonate "+target.ID)
			}
		case KindGroup:
			if hasWild(impGroups) || rbacutil.Contains(impGroups, target.Name) {
				g.addEdge(me, target.ID, EdgeCanImpersonateIdent, "impersonate "+target.ID)
			}
		case KindServiceAccount:
			if hasWild(impSAs) || rbacutil.Contains(impSAs, target.Namespace+"/"+target.Name) {
				g.addEdge(me, target.ID, EdgeCanImpersonateIdent, "impersonate "+target.ID)
			}
		}
	}
	return me
}

func hasWild(ss []string) bool {
	for _, s := range ss {
		if s == "*" {
			return true
		}
	}
	return false
}

func emitImpersonateEdges(g *Graph, holder string, rule rbacv1.PolicyRule, ns string) {
	if !hasAny(rule.Verbs, "impersonate", "*") || !hasAny(rule.APIGroups, "", "*") {
		return
	}
	for _, res := range []string{"users", "groups", "serviceaccounts"} {
		if !hasAny(rule.Resources, res, "*") || (ns != "" && res != "serviceaccounts") {
			continue
		}
		names := rule.ResourceNames
		if len(names) == 0 {
			names = []string{"*"}
		}
		var kind NodeKind
		switch res {
		case "users":
			kind = KindUser
		case "groups":
			kind = KindGroup
		case "serviceaccounts":
			kind = KindServiceAccount
		default:
			continue
		}
		for _, n := range names {
			if kind == KindServiceAccount {
				for _, target := range g.Nodes {
					if target.Kind == kind && (ns == "" || target.Namespace == ns) &&
						(n == "*" || target.Name == n) {
						g.addEdge(holder, target.ID, EdgeCanImpersonateIdent, "impersonate "+target.ID)
					}
				}
			} else {
				if n == "*" {
					for _, target := range g.Nodes {
						if target.Kind == kind {
							g.addEdge(holder, target.ID, EdgeCanImpersonateIdent, "impersonate "+target.ID)
						}
					}
				}
				tid := nodeID(kind, "", n)
				g.addNode(&Node{ID: tid, Kind: kind, Name: n, HighValue: n == "*" || n == "system:masters"})
				g.addEdge(holder, tid, EdgeCanImpersonateIdent, "impersonate "+res+":"+n)
			}
		}
	}
}

func subjectID(g *Graph, s rbacv1.Subject) string {
	switch s.Kind {
	case "User":
		n := g.addNode(&Node{ID: nodeID(KindUser, "", s.Name), Kind: KindUser, Name: s.Name})
		return n.ID
	case "Group":
		n := g.addNode(&Node{ID: nodeID(KindGroup, "", s.Name), Kind: KindGroup, Name: s.Name})
		return n.ID
	case "ServiceAccount":
		return AddIdentity(g, "system:serviceaccount:"+s.Namespace+":"+s.Name,
			[]string{"system:authenticated", "system:serviceaccounts", "system:serviceaccounts:" + s.Namespace}, nil, nil, nil)
	}
	return ""
}

func addRuleEdges(g *Graph, roleID string, rule rbacv1.PolicyRule, ns string, inv *scanner.Inventory) {
	hasWildcardVerb := hasAny(rule.Verbs, "*")
	hasWildcardRes := hasAny(rule.Resources, "*")

	if ns == "" && hasWildcardVerb && hasWildcardRes && hasAny(rule.APIGroups, "*") && len(rule.ResourceNames) == 0 {

		caID := nodeID(KindClusterAdmin, "", "*")
		g.addNode(&Node{ID: caID, Kind: KindClusterAdmin, Name: "*", HighValue: true})
		g.addEdge(roleID, caID, EdgeGrantsWrite, "verbs=* resources=*")
	}
	allowed := func(group, resource, sub, verb, name string) bool {
		return rbacutil.Matches(rule.APIGroups, rule.Resources, rule.Verbs, rule.ResourceNames, group, resource, sub, verb, name)
	}
	for _, pod := range inv.Pods {
		if ns != "" && pod.Namespace != ns {
			continue
		}
		pid := nodeID(KindPod, pod.Namespace, pod.Name)
		if allowed("", "pods", "exec", "create", pod.Name) || allowed("", "pods", "exec", "get", pod.Name) {
			g.addEdge(roleID, pid, EdgeGrantsExec, "authorized pods/exec")
		}
		if allowed("", "pods", "ephemeralcontainers", "update", pod.Name) ||
			allowed("", "pods", "ephemeralcontainers", "patch", pod.Name) {
			g.addEdge(roleID, pid, EdgeCanInjectEphemeral, "debug-container mutation authorization; admission, startup and exec/attach unverified")
		}
	}
	for _, secret := range inv.Secrets {
		if ns != "" && secret.Namespace != ns {
			continue
		}
		if allowed("", "secrets", "", "get", secret.Name) || allowed("", "secrets", "", "list", secret.Name) ||
			allowed("", "secrets", "", "watch", secret.Name) {
			note := "authorized secret read"
			if len(rule.ResourceNames) > 0 {
				note += "; list/watch requires metadata.name=" + secret.Name + " field selector"
			}
			g.addEdge(roleID, nodeID(KindSecret, secret.Namespace, secret.Name), EdgeGrantsRead, note)
		}
	}
	for _, target := range g.Nodes {
		if target.Kind != KindServiceAccount || (ns != "" && target.Namespace != ns) {
			continue
		}
		if allowed("", "serviceaccounts", "token", "create", target.Name) {
			g.addEdge(roleID, target.ID, EdgeCanTokenRequest, "authorized TokenRequest")
		}
		if allowed("", "pods", "", "create", "") {
			g.addEdge(roleID, target.ID, EdgeCanTokenRequest, "create a workload using this SA; admission and API-token availability unverified")
		}
	}
	emitImpersonateEdges(g, roleID, rule, ns)
	if allowed("", "pods", "", "create", "") {
		r := CanDoResult{Namespace: ns, Allowed: true, Check: CanDoCheck{
			Verb: "create", Resource: "pods", Label: "create pods", HV: true,
		}}
		addActionNode(g, r)
		g.addEdge(roleID, actionNodeID(r), EdgeCanDo, "RBAC permits pod creation; privileged admission and node placement unverified")
	}
}

func volumeMounted(pod *corev1.Pod, volume string) bool {
	for _, container := range scanner.Containers(pod) {
		for _, mount := range container.VolumeMounts {
			if mount.Name == volume {
				return true
			}
		}
	}
	return false
}

func hasAny(ss []string, wants ...string) bool {
	for _, s := range ss {
		for _, w := range wants {
			if strings.EqualFold(s, w) {
				return true
			}
		}
	}
	return false
}
