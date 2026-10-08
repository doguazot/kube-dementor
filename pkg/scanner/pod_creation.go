package scanner

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type AdmissionStatus string

const (
	AdmissionAdmitted AdmissionStatus = "admitted"
	AdmissionDenied   AdmissionStatus = "denied"
	AdmissionUnknown  AdmissionStatus = "unknown"
)

type PodAdmissionResult struct {
	Namespace    string          `json:"namespace"`
	Technique    string          `json:"technique"`
	NodeName     string          `json:"nodeName,omitempty"`
	ControlPlane bool            `json:"controlPlane,omitempty"`
	Status       AdmissionStatus `json:"status"`
	Reason       string          `json:"reason,omitempty"`
}

func AssessPodCreation(ctx context.Context, client kubernetes.Interface, namespaces []string, nodes []corev1.Node, verify bool) []PodAdmissionResult {
	var results []PodAdmissionResult
	for _, ns := range uniqueNamespaces(namespaces) {
		for _, technique := range []string{"privileged-hostpath", "privileged-hostpid"} {
			targets := []PodAdmissionResult{{Namespace: ns, Technique: technique}}
			for _, node := range nodes {
				if IsControlPlane(node) {
					targets = append(targets, PodAdmissionResult{
						Namespace: ns, Technique: technique,
						NodeName: node.Name, ControlPlane: true,
					})
				}
			}
			for _, result := range targets {
				result.Status = AdmissionUnknown
				result.Reason = "Pod creation is RBAC-authorized; admission and placement have not been verified."
				if verify && ctx.Err() == nil {
					pod := admissionProbePod(result)
					probeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
					admitted, err := client.CoreV1().Pods(ns).Create(probeCtx, pod, metav1.CreateOptions{
						DryRun: []string{metav1.DryRunAll},
					})
					cancel()
					switch {
					case err == nil && admitted != nil && dangerousProbePreserved(result, admitted):
						result.Status = AdmissionAdmitted
						result.Reason = "Server-side dry-run accepted the dangerous specification. No pod was created or executed; scheduling and host access remain unverified."
					case err == nil && admitted != nil:
						result.Status = AdmissionDenied
						result.Reason = "Admission removed the tested dangerous settings."
					case securityAdmissionDenied(err):
						result.Status = AdmissionDenied
						result.Reason = err.Error()
					default:

						result.Reason = fmt.Sprintf("Admission check inconclusive: %v", err)
					}
				}
				results = append(results, result)
			}
		}
	}
	return results
}

func securityAdmissionDenied(err error) bool {
	if err == nil || !apierrors.IsForbidden(err) {
		return false
	}
	message := strings.ToLower(err.Error())

	if strings.Contains(message, "quota") || strings.Contains(message, "limitrange") ||
		strings.Contains(message, "must specify") {
		return false
	}
	return strings.Contains(message, "violates podsecurity") ||
		strings.Contains(message, "podsecuritypolicy") ||
		strings.Contains(message, "denied the request")
}

func IsControlPlane(node corev1.Node) bool {
	for _, key := range []string{"node-role.kubernetes.io/control-plane", "node-role.kubernetes.io/master"} {
		if _, ok := node.Labels[key]; ok {
			return true
		}
	}
	return false
}

func admissionProbePod(result PodAdmissionResult) *corev1.Pod {
	privileged, automount := true, false
	root := int64(0)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "kube-dementor-admission-",
			Namespace:    result.Namespace,
			Labels:       map[string]string{"app.kubernetes.io/name": "kube-dementor-admission"},
		},
		Spec: corev1.PodSpec{
			AutomountServiceAccountToken: &automount,
			RestartPolicy:                corev1.RestartPolicyNever,
			NodeName:                     result.NodeName,
			Containers: []corev1.Container{{
				Name:  "admission-check",
				Image: "registry.k8s.io/pause:3.10",
				Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceCPU: resource.MustParse("10m"), corev1.ResourceMemory: resource.MustParse("32Mi"),
						corev1.ResourceEphemeralStorage: resource.MustParse("16Mi"),
					},
					Limits: corev1.ResourceList{
						corev1.ResourceCPU: resource.MustParse("10m"), corev1.ResourceMemory: resource.MustParse("32Mi"),
						corev1.ResourceEphemeralStorage: resource.MustParse("16Mi"),
					},
				},
				SecurityContext: &corev1.SecurityContext{
					Privileged: &privileged, RunAsUser: &root,
				},
			}},
		},
	}
	if result.Technique == "privileged-hostpid" {
		pod.Spec.HostPID = true
	} else {
		pod.Spec.Volumes = []corev1.Volume{{
			Name: "host-root",
			VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{
				Path: "/", Type: hostPathDirectory(),
			}},
		}}
		pod.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{
			Name: "host-root", MountPath: "/host", ReadOnly: false,
		}}
	}
	if result.ControlPlane {

		pod.Spec.Tolerations = []corev1.Toleration{{Operator: corev1.TolerationOpExists}}
	}
	return pod
}

func hostPathDirectory() *corev1.HostPathType {
	t := corev1.HostPathDirectory
	return &t
}

func dangerousProbePreserved(result PodAdmissionResult, pod *corev1.Pod) bool {
	if result.NodeName != "" && pod.Spec.NodeName != result.NodeName {
		return false
	}
	for _, container := range Containers(pod) {
		if !ContainerRunsAsRoot(pod, container) || container.SecurityContext == nil ||
			container.SecurityContext.Privileged == nil || !*container.SecurityContext.Privileged {
			continue
		}
		if result.Technique == "privileged-hostpid" && pod.Spec.HostPID {
			return true
		}
		if result.Technique == "privileged-hostpath" {
			for _, mount := range container.VolumeMounts {
				if mount.ReadOnly || mount.SubPath != "" || mount.SubPathExpr != "" {
					continue
				}
				for _, volume := range pod.Spec.Volumes {
					if volume.Name == mount.Name && volume.HostPath != nil && volume.HostPath.Path == "/" {
						return true
					}
				}
			}
		}
	}
	return false
}

func PodCreationFindings(results []PodAdmissionResult) []Finding {
	var findings []Finding
	for _, result := range results {
		if result.Status == AdmissionDenied {
			continue
		}
		severity := SevMedium
		title := "Pod creation may permit node access; admission unverified"
		if result.Status == AdmissionAdmitted {
			severity = SevHigh
			title = "Admission accepts an escape-capable pod specification"
			if result.ControlPlane {
				severity = SevCritical
				title = "Admission accepts an escape-capable pod targeting a control-plane node"
			}
		}
		findings = append(findings, Finding{
			RuleID:   "KH-ESC-POD-CREATE",
			Category: CatEscape, Severity: severity, Title: title,
			Resource:    Resource{Kind: "Namespace", Namespace: result.Namespace, Name: result.Namespace},
			Description: "This identity can create pods even when no workloads currently exist. A root privileged container with a writable host-root mount or hostPID can expose node access if runtime and placement conditions allow it.",
			Evidence: fmt.Sprintf("namespace=%s technique=%s admission=%s node=%s controlPlane=%t; %s",
				result.Namespace, result.Technique, result.Status, result.NodeName, result.ControlPlane, result.Reason),
			Impact:         "Potential node compromise. Control-plane targeting can expose cluster credentials, but admission alone does not prove scheduling, escape, credential access, or cluster-admin.",
			Recommendation: "Enforce Pod Security Admission restricted or equivalent policy. Block privileged containers, host namespaces, hostPath and unapproved nodeName/tolerations. Limit workload creation and isolate control-plane nodes with admission policy, not taints alone.",
			MitreATTACK:    []string{"T1610", "T1611"},
			Tags:           []string{"pod-creation", "admission-" + string(result.Status), result.Technique},
			DetectedAt:     time.Now(),
		})
	}
	return findings
}

func Containers(pod *corev1.Pod) []corev1.Container {
	out := make([]corev1.Container, 0, len(pod.Spec.Containers)+len(pod.Spec.InitContainers)+len(pod.Spec.EphemeralContainers))
	out = append(out, pod.Spec.Containers...)
	out = append(out, pod.Spec.InitContainers...)
	for _, container := range pod.Spec.EphemeralContainers {
		out = append(out, corev1.Container(container.EphemeralContainerCommon))
	}
	return out
}

func ContainerRunsAsRoot(pod *corev1.Pod, container corev1.Container) bool {
	var uid *int64
	var nonroot *bool
	if pod.Spec.SecurityContext != nil {
		uid = pod.Spec.SecurityContext.RunAsUser
		nonroot = pod.Spec.SecurityContext.RunAsNonRoot
	}
	if container.SecurityContext != nil {
		if container.SecurityContext.RunAsUser != nil {
			uid = container.SecurityContext.RunAsUser
		}
		if container.SecurityContext.RunAsNonRoot != nil {
			nonroot = container.SecurityContext.RunAsNonRoot
		}
	}
	if nonroot != nil && *nonroot {
		return false
	}
	if uid != nil {
		return *uid == 0
	}

	return true
}

func CollectionFinding(issues []CollectionIssue) *Finding {
	if len(issues) == 0 {
		return nil
	}
	var lines []string
	for _, issue := range issues {
		lines = append(lines, fmt.Sprintf("%s %s namespace=%q: %s", issue.Operation, issue.Resource, issue.Namespace, issue.Error))
	}
	return &Finding{
		RuleID: "KH-AUDIT-COVERAGE", Category: CatAudit, Severity: SevInfo,
		Title:          "Assessment coverage is incomplete",
		Resource:       Resource{Kind: "Cluster", Name: "assessment-coverage"},
		Description:    "Some resources or authorization checks could not be read. Zero findings in missing data are not evidence of a secure cluster.",
		Evidence:       strings.Join(lines, "\n"),
		Recommendation: "Review collection errors, set the intended --namespace or kubeconfig namespace, and rerun with approved read permissions for the missing resources.",
		Tags:           []string{"coverage", "incomplete"}, DetectedAt: time.Now(),
	}
}
