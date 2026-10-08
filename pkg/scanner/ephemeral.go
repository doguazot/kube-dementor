package scanner

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type EphemeralPermission struct {
	Allowed bool
	Error   string
}

type EphemeralContainerState struct {
	Name             string
	State            string
	TargetContainer  string
	EscapeConditions string
}

type EphemeralAssessment struct {
	Namespace      string
	PodName        string
	NodeName       string
	NodeRole       string
	Running        bool
	HostConditions string
	Permissions    map[string]EphemeralPermission
	Containers     []EphemeralContainerState
}

func (a EphemeralAssessment) CanInject() bool {
	return a.Permissions["update pods/ephemeralcontainers"].Allowed ||
		a.Permissions["patch pods/ephemeralcontainers"].Allowed
}

func (a EphemeralAssessment) CanInteract() bool {
	for _, key := range []string{"create pods/exec", "get pods/exec", "create pods/attach", "get pods/attach"} {
		if a.Permissions[key].Allowed {
			return true
		}
	}
	return false
}

func AssessEphemeralContainers(ctx context.Context, client kubernetes.Interface, inv *Inventory) []EphemeralAssessment {
	var results []EphemeralAssessment
	seen := map[string]bool{}
	for _, pod := range inv.Pods {
		running := pod.Status.Phase == corev1.PodRunning && pod.DeletionTimestamp == nil
		if !running && len(pod.Spec.EphemeralContainers) == 0 {
			continue
		}
		result := EphemeralAssessment{
			Namespace: pod.Namespace, PodName: pod.Name, NodeName: pod.Spec.NodeName,
			NodeRole: "unknown", Running: running, Permissions: map[string]EphemeralPermission{},
		}
		for _, node := range inv.Nodes {
			if node.Name != pod.Spec.NodeName {
				continue
			}
			if _, ok := node.Labels["node-role.kubernetes.io/control-plane"]; ok {
				result.NodeRole = "control-plane"
			} else if _, ok := node.Labels["node-role.kubernetes.io/master"]; ok {
				result.NodeRole = "control-plane"
			} else if _, ok := node.Labels["node-role.kubernetes.io/worker"]; ok {
				result.NodeRole = "worker"
			}
		}
		if pod.Spec.HostPID {
			result.HostConditions = "pod already uses hostPID; a root privileged ephemeral container would still require admission and runtime verification"
		}
		for _, volume := range pod.Spec.Volumes {
			if volume.HostPath != nil && DangerousHostPath(volume.HostPath.Path) {
				result.HostConditions += fmt.Sprintf("; existing hostPath volume %s=%s would require an admitted debug-container mount", volume.Name, volume.HostPath.Path)
			}
		}
		result.HostConditions = strings.TrimPrefix(result.HostConditions, "; ")
		for _, container := range pod.Spec.EphemeralContainers {
			state := "unknown"
			for _, status := range pod.Status.EphemeralContainerStatuses {
				if status.Name != container.Name {
					continue
				}
				switch {
				case status.State.Running != nil:
					state = "running"
				case status.State.Terminated != nil:
					state = "terminated"
				case status.State.Waiting != nil:
					state = "waiting"
				}
			}
			scoped := pod.DeepCopy()
			scoped.Spec.Containers, scoped.Spec.InitContainers = nil, nil
			scoped.Spec.EphemeralContainers = []corev1.EphemeralContainer{container}
			result.Containers = append(result.Containers, EphemeralContainerState{
				Name: container.Name, State: state, TargetContainer: container.TargetContainerName,
				EscapeConditions: PodEscapeReason(scoped),
			})
		}
		results = append(results, result)
		seen[pod.Namespace] = true
	}
	namespaces := append([]string(nil), inv.NamespaceTargets...)
	for _, namespace := range inv.Namespaces {
		namespaces = append(namespaces, namespace.Name)
	}
	for _, namespace := range namespaces {
		if namespace != "" && !seen[namespace] {
			results = append(results, EphemeralAssessment{
				Namespace: namespace, NodeRole: "unknown", Permissions: map[string]EphemeralPermission{},
			})
			seen[namespace] = true
		}
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].Namespace+"/"+results[i].PodName < results[j].Namespace+"/"+results[j].PodName
	})
	jobs := make(chan int, len(results))
	for i := range results {
		jobs <- i
	}
	close(jobs)
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				result := &results[index]
				for _, verb := range []string{"update", "patch"} {
					key := verb + " pods/ephemeralcontainers"
					result.Permissions[key] = ephemeralPermission(ctx, client, result.Namespace, result.PodName, verb, "ephemeralcontainers")
				}
				if result.PodName == "" || (!result.CanInject() && len(result.Containers) == 0) {
					continue
				}
				for _, subresource := range []string{"exec", "attach"} {
					for _, verb := range []string{"create", "get"} {
						key := verb + " pods/" + subresource
						result.Permissions[key] = ephemeralPermission(ctx, client, result.Namespace, result.PodName, verb, subresource)
					}
				}
			}
		}()
	}
	workers.Wait()
	return results
}

func ephemeralPermission(ctx context.Context, client kubernetes.Interface, namespace, name, verb, subresource string) EphemeralPermission {
	if client == nil {
		return EphemeralPermission{Error: "Kubernetes client is unavailable"}
	}
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	review, err := client.AuthorizationV1().SelfSubjectAccessReviews().Create(probeCtx, &authzv1.SelfSubjectAccessReview{
		Spec: authzv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authzv1.ResourceAttributes{
			Group: "", Resource: "pods", Subresource: subresource, Verb: verb, Namespace: namespace, Name: name,
		}},
	}, metav1.CreateOptions{})
	if err != nil {
		return EphemeralPermission{Error: err.Error()}
	}
	if review.Status.EvaluationError != "" {
		return EphemeralPermission{Error: review.Status.EvaluationError}
	}
	return EphemeralPermission{Allowed: review.Status.Allowed}
}

func EphemeralCollectionIssues(results []EphemeralAssessment) []CollectionIssue {
	var issues []CollectionIssue
	for _, result := range results {
		keys := make([]string, 0, len(result.Permissions))
		for key := range result.Permissions {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if permission := result.Permissions[key]; permission.Error != "" {
				issues = append(issues, CollectionIssue{
					Resource: "pods", Namespace: result.Namespace,
					Operation: "authorize " + key + " name=" + result.PodName, Error: permission.Error,
				})
			}
		}
	}
	return issues
}

func ephemeralEvidence(result EphemeralAssessment) string {
	lines := []string{fmt.Sprintf("namespace=%s pod=%s running=%t node=%s nodeRole=%s; admission and runtime unverified",
		result.Namespace, result.PodName, result.Running, result.NodeName, result.NodeRole)}
	for _, key := range []string{
		"update pods/ephemeralcontainers", "patch pods/ephemeralcontainers",
		"create pods/exec", "get pods/exec", "create pods/attach", "get pods/attach",
	} {
		status := "not assessed"
		if permission, ok := result.Permissions[key]; ok {
			status = "denied"
			if permission.Error != "" {
				status = "unknown: " + permission.Error
			} else if permission.Allowed {
				status = "allowed"
			}
		}
		lines = append(lines, key+"="+status)
	}
	for _, container := range result.Containers {
		lines = append(lines, fmt.Sprintf("ephemeral=%s state=%s targetContainer=%s; %s",
			container.Name, container.State, container.TargetContainer, container.EscapeConditions))
	}
	if result.HostConditions != "" {
		lines = append(lines, result.HostConditions)
	}
	return strings.Join(lines, "\n")
}

func EphemeralFindings(results []EphemeralAssessment) []Finding {
	var findings []Finding
	byNamespace := map[string][]string{}
	for _, result := range results {
		evidence := ephemeralEvidence(result)
		byNamespace[result.Namespace] = append(byNamespace[result.Namespace], evidence)
		if result.CanInject() && result.Running && result.PodName != "" {
			findings = append(findings, Finding{
				ID:     "KH-RBAC-EPHEMERAL-" + result.Namespace + "/" + result.PodName,
				RuleID: "KH-RBAC-EPHEMERAL", Category: CatRBAC, Severity: SevHigh,
				Title:          "Current identity may inject an ephemeral container into " + result.PodName,
				Resource:       Resource{Kind: "Pod", Namespace: result.Namespace, Name: result.PodName},
				Description:    "A named SelfSubjectAccessReview authorizes update or patch of pods/ephemeralcontainers. Admission, API support, image startup and interactive access remain unverified. Pod-level settings still apply; targetContainerName is not proof of process sharing. Debug containers cannot change hostPID/node placement or add new pod volumes. Exec/attach permission is assessed separately. No container was injected.",
				Evidence:       evidence,
				Impact:         "Potential code execution in the existing pod. Host access additionally requires an admitted escape-capable profile, existing pod prerequisites and runtime verification; this is not a worker or control-plane shell.",
				Recommendation: "Limit pods/ephemeralcontainers update/patch, including resourceNames. Apply admission policy to ephemeral container securityContext, images and mounts; restrict exec/attach.",
				Tags:           []string{"ephemeral-containers", "authorization", "admission-unverified", "not-exploited"},
				MitreATTACK:    []string{"T1610", "T1609"}, DetectedAt: time.Now(),
			})
		}
		for _, container := range result.Containers {
			if container.EscapeConditions == "" {
				continue
			}
			severity := SevInfo
			if result.Running && container.State == "running" {
				severity = SevHigh
			}
			findings = append(findings, Finding{
				ID:     "KH-WRK-EPHEMERAL-" + result.Namespace + "/" + result.PodName + "/" + container.Name,
				RuleID: "KH-WRK-EPHEMERAL", Category: CatWorkload, Severity: severity,
				Title:       fmt.Sprintf("Ephemeral container %s has host-access prerequisites (%s)", container.Name, container.State),
				Resource:    Resource{Kind: "Pod", Namespace: result.Namespace, Name: result.PodName},
				Description: "The ephemeral container specification has escape-related settings. Waiting, terminated, or missing status is not an active exec target. An unspecified image UID is not proof of root. Authorization and host execution remain unverified.",
				Evidence:    evidence, Recommendation: "Remove unnecessary privilege and host exposure from debug profiles. Limit debug-container access and enforce admission policy.",
				Tags:       []string{"ephemeral-containers", "state-" + container.State, "runtime-unverified"},
				DetectedAt: time.Now(),
			})
		}
	}
	namespaces := make([]string, 0, len(byNamespace))
	for namespace := range byNamespace {
		namespaces = append(namespaces, namespace)
	}
	sort.Strings(namespaces)
	for _, namespace := range namespaces {
		findings = append(findings, Finding{
			ID:     "KH-EPHEMERAL-ASSESSMENT-" + namespace,
			RuleID: "KH-EPHEMERAL-ASSESSMENT", Category: CatAudit, Severity: SevInfo,
			Title:          "Read-only ephemeral container assessment in " + namespace,
			Resource:       Resource{Kind: "Namespace", Namespace: namespace, Name: namespace},
			Description:    "Authorization checks and existing ephemeral container state only. No container was added, patched, attached or exec'd. No visible running target or a denied review is not an exhaustive proof of safety; inventory and authorization errors are reported as incomplete coverage.",
			Evidence:       strings.Join(byNamespace[namespace], "\n\n"),
			Recommendation: "Review named-target permission, exec/attach status, admission and visible node placement before any explicitly authorized live test.",
			Tags:           []string{"ephemeral-containers", "read-only-assessment"}, DetectedAt: time.Now(),
		})
	}
	return findings
}

func EphemeralPotentialGraph(results []EphemeralAssessment, me string) *GraphSnapshot {
	graph := &GraphSnapshot{Me: me}
	seen := map[string]bool{}
	addCandidate := func(result EphemeralAssessment, id, kind, name, conditions, note string) {
		if !seen[me] {
			graph.Nodes = append(graph.Nodes, GraphNode{ID: me, Kind: "Operator", Name: "Current credentials"})
			seen[me] = true
		}
		graph.Nodes = append(graph.Nodes, GraphNode{
			ID: id, Kind: kind, Namespace: result.Namespace,
			Name: name, HighValue: true,
			Status: "potential", Phase: "ephemeral-assessment", Detail: ephemeralEvidence(result),
		})
		graph.Edges = append(graph.Edges, GraphEdge{
			From: me, To: id, Kind: "CanInjectEphemeral", Status: "potential",
			Note: note,
		})
		if kind == "EphemeralContainer" {
			graph.Edges[len(graph.Edges)-1].Kind = "CanInteract"
		}
		if conditions == "" {
			return
		}
		target := "NodeAccess/" + id
		graph.Nodes = append(graph.Nodes, GraphNode{
			ID: target, Kind: "NodeAccess", Name: "Potential host access on " + result.NodeName,
			Namespace: result.Namespace, HighValue: true, Status: "potential", Phase: "ephemeral-assessment",
			Detail: "nodeRole=" + result.NodeRole + "; " + conditions + "; no host execution was attempted or proven",
		})
		graph.Edges = append(graph.Edges, GraphEdge{
			From: id, To: target, Kind: "CanEscape", Status: "potential",
			Note: "Potential escape under the stated profile, placement and runtime conditions; not attempted; host access is not inferred from a shell label",
		})
	}
	for _, result := range results {
		if !result.Running || result.PodName == "" {
			continue
		}
		if result.CanInject() {
			addCandidate(result, "EphemeralCandidate/"+result.Namespace+"/"+result.PodName,
				"EphemeralCandidate", "Potential debug container in "+result.PodName, result.HostConditions,
				"Named authorization only; admission and container startup unverified; not injected")
		}
		if !result.CanInteract() {
			continue
		}
		for _, container := range result.Containers {
			if container.State == "running" {
				addCandidate(result, "EphemeralContainer/"+result.Namespace+"/"+result.PodName+"/"+container.Name,
					"EphemeralContainer", "Potential exec/attach to "+container.Name, container.EscapeConditions,
					"Existing running ephemeral container; named exec/attach authorization, actual interaction and stdin/runtime unverified; no exec was run")
			}
		}
	}
	return graph
}
