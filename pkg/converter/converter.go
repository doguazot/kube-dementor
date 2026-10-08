package converter

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/kube-dementor/kube-dementor/pkg/ingestor"
	"github.com/kube-dementor/kube-dementor/pkg/models"
	"github.com/kube-dementor/kube-dementor/pkg/scanner"
)

type Converter struct{}

func New() *Converter {
	return &Converter{}
}

func (c *Converter) Convert(raw *ingestor.RawClusterData) *models.ClusterData {
	data := &models.ClusterData{}

	data.Nodes = c.convertNodes(raw.Nodes)
	data.Identities = c.convertServiceAccounts(raw.ServiceAccounts)
	data.PermissionSets = c.convertPermissionSets(raw.Roles, raw.ClusterRoles)
	data.Bindings = c.convertBindings(raw.RoleBindings, raw.ClusterRoleBindings)

	pods, containers, volumes := c.convertPods(raw.Pods)
	data.Pods = pods
	data.Containers = containers
	data.Volumes = volumes
	identities := map[string]bool{}
	for _, identity := range data.Identities {
		identities[fmt.Sprintf("%s/%s/%s", identity.Kind, identity.Namespace, identity.Name)] = true
	}
	for _, binding := range data.Bindings {
		key := fmt.Sprintf("%s/%s/%s", binding.SubjectKind, binding.SubjectNS, binding.SubjectName)
		if identities[key] {
			continue
		}
		identities[key] = true
		data.Identities = append(data.Identities, models.IdentityNode{
			UID: "identity/" + key, Name: binding.SubjectName, Namespace: binding.SubjectNS,
			Kind: models.IdentityKind(binding.SubjectKind),
		})
	}
	for _, pod := range data.Pods {
		key := fmt.Sprintf("ServiceAccount/%s/%s", pod.Namespace, pod.ServiceAccountName)
		if !identities[key] {
			identities[key] = true
			data.Identities = append(data.Identities, models.IdentityNode{
				UID: "identity/" + key, Kind: models.IdentityKindServiceAccount,
				Namespace: pod.Namespace, Name: pod.ServiceAccountName,
			})
		}
	}
	for _, identity := range data.Identities {
		if identity.Kind == models.IdentityKindServiceAccount {
			data.Memberships = append(data.Memberships, AddOperator(data,
				"system:serviceaccount:"+identity.Namespace+":"+identity.Name,
				[]string{"system:authenticated", "system:serviceaccounts", "system:serviceaccounts:" + identity.Namespace})...)
		}
	}
	nodes := map[string]bool{}
	for _, node := range data.Nodes {
		nodes[node.Name] = true
	}
	for _, pod := range data.Pods {
		if pod.NodeName != "" && !nodes[pod.NodeName] {
			nodes[pod.NodeName] = true
			data.Nodes = append(data.Nodes, models.NodeNode{UID: "node/" + pod.NodeName, Name: pod.NodeName, Partial: true})
		}
	}

	return data
}

func (c *Converter) convertNodes(nodes []corev1.Node) []models.NodeNode {
	out := make([]models.NodeNode, 0, len(nodes))
	for _, n := range nodes {
		nn := models.NodeNode{
			UID:             string(n.UID),
			Name:            n.Name,
			Labels:          n.Labels,
			IsControlPlane:  isControlPlane(n.Labels),
			KubeletVersion:  n.Status.NodeInfo.KubeletVersion,
			OperatingSystem: n.Status.NodeInfo.OperatingSystem,
			Architecture:    n.Status.NodeInfo.Architecture,
		}
		for _, addr := range n.Status.Addresses {
			if addr.Type == corev1.NodeInternalIP {
				nn.InternalIP = addr.Address
				break
			}
		}
		out = append(out, nn)
	}
	return out
}

func isControlPlane(labels map[string]string) bool {
	if _, ok := labels["node-role.kubernetes.io/control-plane"]; ok {
		return true
	}
	if _, ok := labels["node-role.kubernetes.io/master"]; ok {
		return true
	}
	return false
}

func (c *Converter) convertServiceAccounts(sas []corev1.ServiceAccount) []models.IdentityNode {
	out := make([]models.IdentityNode, 0, len(sas))
	for _, sa := range sas {
		node := models.IdentityNode{
			UID:            string(sa.UID),
			Name:           sa.Name,
			Namespace:      sa.Namespace,
			Kind:           models.IdentityKindServiceAccount,
			AutomountToken: sa.AutomountServiceAccountToken,
		}
		out = append(out, node)
	}
	return out
}

func (c *Converter) convertPermissionSets(roles []rbacv1.Role, clusterRoles []rbacv1.ClusterRole) []models.PermissionSetNode {
	out := make([]models.PermissionSetNode, 0, len(roles)+len(clusterRoles))

	for _, r := range roles {
		out = append(out, models.PermissionSetNode{
			UID:       string(r.UID),
			Name:      r.Name,
			Namespace: r.Namespace,
			Kind:      models.PermissionSetKindRole,
			Rules:     convertPolicyRules(r.Rules),
		})
	}

	for _, cr := range clusterRoles {
		out = append(out, models.PermissionSetNode{
			UID:   string(cr.UID),
			Name:  cr.Name,
			Kind:  models.PermissionSetKindClusterRole,
			Rules: convertPolicyRules(cr.Rules),
		})
	}

	return out
}

func convertPolicyRules(rules []rbacv1.PolicyRule) []models.PolicyRule {
	out := make([]models.PolicyRule, 0, len(rules))
	for _, r := range rules {
		out = append(out, models.PolicyRule{
			APIGroups:       r.APIGroups,
			Resources:       r.Resources,
			Verbs:           r.Verbs,
			ResourceNames:   r.ResourceNames,
			NonResourceURLs: r.NonResourceURLs,
		})
	}
	return out
}

func (c *Converter) convertBindings(rbs []rbacv1.RoleBinding, crbs []rbacv1.ClusterRoleBinding) []models.BindingInfo {
	var out []models.BindingInfo

	for _, rb := range rbs {
		for _, subj := range rb.Subjects {
			if subj.Kind == "ServiceAccount" && subj.Namespace == "" {
				subj.Namespace = rb.Namespace
			}
			out = append(out, models.BindingInfo{
				UID:            string(rb.UID),
				Name:           rb.Name,
				Namespace:      rb.Namespace,
				IsClusterScope: false,
				RoleRefKind:    rb.RoleRef.Kind,
				RoleRefName:    rb.RoleRef.Name,
				SubjectKind:    subj.Kind,
				SubjectName:    subj.Name,
				SubjectNS:      subj.Namespace,
			})
		}
	}

	for _, crb := range crbs {
		for _, subj := range crb.Subjects {
			out = append(out, models.BindingInfo{
				UID:            string(crb.UID),
				Name:           crb.Name,
				IsClusterScope: true,
				RoleRefKind:    crb.RoleRef.Kind,
				RoleRefName:    crb.RoleRef.Name,
				SubjectKind:    subj.Kind,
				SubjectName:    subj.Name,
				SubjectNS:      subj.Namespace,
			})
		}
	}

	return out
}

func (c *Converter) convertPods(pods []corev1.Pod) ([]models.PodNode, []models.ContainerNode, []models.VolumeNode) {
	podNodes := make([]models.PodNode, 0, len(pods))
	var containerNodes []models.ContainerNode
	var volumeNodes []models.VolumeNode

	for _, p := range pods {
		podUID := string(p.UID)

		pn := models.PodNode{
			UID:                podUID,
			Name:               p.Name,
			Namespace:          p.Namespace,
			NodeName:           p.Spec.NodeName,
			ServiceAccountName: p.Spec.ServiceAccountName,
			HostPID:            p.Spec.HostPID,
			HostNetwork:        p.Spec.HostNetwork,
			HostIPC:            p.Spec.HostIPC,
			AutomountToken:     p.Spec.AutomountServiceAccountToken,
		}
		if pn.ServiceAccountName == "" {
			pn.ServiceAccountName = "default"
		}

		for _, ct := range scanner.Containers(&p) {
			cn := convertContainer(ct, podUID, p.Name, p.Namespace)
			if p.Spec.SecurityContext != nil {
				if cn.RunAsUser == nil {
					cn.RunAsUser = p.Spec.SecurityContext.RunAsUser
				}
				if cn.RunAsNonRoot == nil {
					cn.RunAsNonRoot = p.Spec.SecurityContext.RunAsNonRoot
				}
			}
			containerNodes = append(containerNodes, cn)
			for _, mount := range ct.VolumeMounts {
				for _, volume := range p.Spec.Volumes {
					if volume.Name != mount.Name || volume.Projected == nil {
						continue
					}
					for _, source := range volume.Projected.Sources {
						pn.HasProjectedToken = pn.HasProjectedToken || (source.ServiceAccountToken != nil &&
							scanner.VolumePathExposed(&p, volume.Name, source.ServiceAccountToken.Path))
					}
				}
			}
		}
		podNodes = append(podNodes, pn)

		for _, v := range p.Spec.Volumes {
			vn := convertVolume(v, podUID, p.Name, p.Namespace)
			if vn != nil {
				volumeNodes = append(volumeNodes, *vn)
			}
		}
	}

	return podNodes, containerNodes, volumeNodes
}

func AddOperator(data *models.ClusterData, username string, groups []string) []models.Edge {
	kind, namespace, name := models.IdentityKindUser, "", username
	if strings.HasPrefix(username, "system:serviceaccount:") {
		parts := strings.SplitN(strings.TrimPrefix(username, "system:serviceaccount:"), ":", 2)
		if len(parts) == 2 {
			kind, namespace, name = models.IdentityKindServiceAccount, parts[0], parts[1]
		}
	}
	ensure := func(kind models.IdentityKind, namespace, name string) string {
		for _, identity := range data.Identities {
			if identity.Kind == kind && identity.Namespace == namespace && identity.Name == name {
				return identity.UID
			}
		}
		uid := fmt.Sprintf("identity/%s/%s/%s", kind, namespace, name)
		data.Identities = append(data.Identities, models.IdentityNode{UID: uid, Kind: kind, Namespace: namespace, Name: name})
		return uid
	}
	if username == "" {
		return nil
	}
	operator := ensure(kind, namespace, name)
	var edges []models.Edge
	seen := map[string]bool{}
	for _, group := range groups {
		if group == "" || seen[group] {
			continue
		}
		seen[group] = true
		target := ensure(models.IdentityKindGroup, "", group)
		edges = append(edges, models.Edge{SourceUID: operator, TargetUID: target, Type: models.EdgeMemberOf})
	}
	return edges
}

func convertContainer(ct corev1.Container, podUID, podName, podNS string) models.ContainerNode {
	cn := models.ContainerNode{
		UID:    fmt.Sprintf("%s/%s", podUID, ct.Name),
		Name:   ct.Name,
		Image:  ct.Image,
		PodUID: podUID,
	}

	if ct.SecurityContext != nil {
		cn.RunAsUser = ct.SecurityContext.RunAsUser
		cn.RunAsNonRoot = ct.SecurityContext.RunAsNonRoot
		if ct.SecurityContext.Privileged != nil {
			cn.Privileged = *ct.SecurityContext.Privileged
		}
		if ct.SecurityContext.Capabilities != nil {
			for _, cap := range ct.SecurityContext.Capabilities.Add {
				cn.Capabilities = append(cn.Capabilities, string(cap))
			}
		}
	}

	for _, vm := range ct.VolumeMounts {
		cn.VolumeMounts = append(cn.VolumeMounts, models.VolumeMount{
			Name:        vm.Name,
			MountPath:   vm.MountPath,
			ReadOnly:    vm.ReadOnly,
			SubPath:     vm.SubPath,
			SubPathExpr: vm.SubPathExpr,
		})
	}

	return cn
}

func convertVolume(v corev1.Volume, podUID, podName, podNS string) *models.VolumeNode {
	vn := &models.VolumeNode{
		UID:    fmt.Sprintf("%s/vol/%s", podUID, v.Name),
		Name:   v.Name,
		PodUID: podUID,
	}

	switch {
	case v.HostPath != nil:
		vn.Source = models.VolumeSource{
			Type:     "HostPath",
			HostPath: v.HostPath.Path,
		}
	case v.Secret != nil:
		vn.Source = models.VolumeSource{Type: "Secret"}
	case v.ConfigMap != nil:
		vn.Source = models.VolumeSource{Type: "ConfigMap"}
	case v.PersistentVolumeClaim != nil:
		vn.Source = models.VolumeSource{Type: "PVC"}
	case v.Projected != nil:
		hasToken := false
		if v.Projected.Sources != nil {
			for _, src := range v.Projected.Sources {
				if src.ServiceAccountToken != nil {
					hasToken = true
					break
				}
			}
		}
		if hasToken {
			vn.Source = models.VolumeSource{Type: "ProjectedServiceAccountToken"}
		} else {
			vn.Source = models.VolumeSource{Type: "Projected"}
		}
	default:

		return nil
	}

	return vn
}

func IsDangerousVerb(verb string) bool {
	verb = strings.ToLower(verb)
	return verb == "*" || verb == "create" || verb == "update" || verb == "patch" || verb == "delete" || verb == "escalate" || verb == "impersonate" || verb == "bind"
}

func IsWildcard(s string) bool {
	return s == "*"
}
