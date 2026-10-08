package scanner

import (
	"path"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

func AutomountToken(inv *Inventory, pod *corev1.Pod) bool {
	if pod.Spec.AutomountServiceAccountToken != nil {
		return *pod.Spec.AutomountServiceAccountToken
	}
	name := pod.Spec.ServiceAccountName
	if name == "" {
		name = "default"
	}
	for _, sa := range inv.ServiceAccounts {
		if sa.Namespace == pod.Namespace && sa.Name == name && sa.AutomountServiceAccountToken != nil {
			return *sa.AutomountServiceAccountToken
		}
	}
	return true
}

func HasServiceAccountToken(inv *Inventory, pod *corev1.Pod) bool {
	name := pod.Spec.ServiceAccountName
	if name == "" {
		name = "default"
	}
	for _, container := range Containers(pod) {
		for _, mount := range container.VolumeMounts {
			for _, volume := range pod.Spec.Volumes {
				if volume.Name != mount.Name {
					continue
				}
				if volume.Projected != nil {
					for _, source := range volume.Projected.Sources {
						if source.ServiceAccountToken != nil &&
							VolumePathExposed(pod, volume.Name, source.ServiceAccountToken.Path) {
							return true
						}
					}
				}
			}
		}
	}
	for _, secret := range inv.Secrets {
		if secret.Namespace == pod.Namespace && secret.Type == corev1.SecretTypeServiceAccountToken &&
			secret.Annotations["kubernetes.io/service-account.name"] == name && len(secret.Data["token"]) > 0 &&
			SecretTokenExposed(pod, secret.Name) {
			return true
		}
	}
	return AutomountToken(inv, pod)
}

func VolumePathExposed(pod *corev1.Pod, volumeName, filePath string) bool {
	filePath = path.Clean(filePath)
	for _, container := range Containers(pod) {
		for _, mount := range container.VolumeMounts {
			if mount.Name != volumeName || mount.SubPathExpr != "" {
				continue
			}
			subPath := path.Clean(mount.SubPath)
			if mount.SubPath == "" || filePath == subPath || strings.HasPrefix(filePath, subPath+"/") {
				return true
			}
		}
	}
	return false
}

func secretTokenPathExposed(pod *corev1.Pod, volumeName string, items []corev1.KeyToPath) bool {
	if len(items) == 0 {
		return VolumePathExposed(pod, volumeName, "token")
	}
	for _, item := range items {
		if item.Key == "token" && VolumePathExposed(pod, volumeName, item.Path) {
			return true
		}
	}
	return false
}

func SecretTokenExposed(pod *corev1.Pod, secretName string) bool {
	for _, volume := range pod.Spec.Volumes {
		if volume.Secret != nil && volume.Secret.SecretName == secretName &&
			secretTokenPathExposed(pod, volume.Name, volume.Secret.Items) {
			return true
		}
		if volume.Projected != nil {
			for _, source := range volume.Projected.Sources {
				if source.Secret != nil && source.Secret.Name == secretName &&
					secretTokenPathExposed(pod, volume.Name, source.Secret.Items) {
					return true
				}
			}
		}
	}
	for _, container := range Containers(pod) {
		for _, env := range container.EnvFrom {
			if env.SecretRef != nil && env.SecretRef.Name == secretName {
				return true
			}
		}
		for _, env := range container.Env {
			if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil &&
				env.ValueFrom.SecretKeyRef.Name == secretName && env.ValueFrom.SecretKeyRef.Key == "token" {
				return true
			}
		}
	}
	return false
}

func PodEscapeReason(pod *corev1.Pod) string {
	for _, container := range Containers(pod) {
		if !ContainerRunsAsRoot(pod, container) {
			continue
		}
		sc := container.SecurityContext
		privileged := sc != nil && sc.Privileged != nil && *sc.Privileged
		if pod.Spec.HostPID && privileged {
			return "root privileged container " + container.Name + " with hostPID; host namespace access may permit escape"
		}
		for _, mount := range container.VolumeMounts {
			if mount.ReadOnly || mount.SubPathExpr != "" {
				continue
			}
			for _, volume := range pod.Spec.Volumes {
				if volume.Name != mount.Name || volume.HostPath == nil {
					continue
				}
				hostPath := path.Clean(path.Join(volume.HostPath.Path, mount.SubPath))
				if DangerousHostPath(hostPath) {
					return "root container " + container.Name + " has writable hostPath=" + hostPath + "; host access is a potential escape"
				}
			}
		}
		if privileged {
			return "root privileged container " + container.Name + "; host-device access may permit escape"
		}
	}
	return ""
}

func DangerousHostPath(hostPath string) bool {
	hostPath = path.Clean(hostPath)
	if hostPath == "/" {
		return true
	}
	for _, target := range []string{
		"/etc", "/root", "/var/lib/kubelet", "/var/lib/etcd",
		"/var/run/docker.sock", "/run/docker.sock",
		"/run/containerd/containerd.sock", "/var/run/containerd/containerd.sock",
		"/var/run/crio/crio.sock", "/proc/sys", "/sys",
	} {
		if hostPath == target || strings.HasPrefix(target, hostPath+"/") {
			return true
		}
	}
	for _, directory := range []string{
		"/etc/kubernetes", "/etc/cron.d", "/etc/systemd/system", "/root",
		"/var/lib/kubelet", "/var/lib/etcd", "/proc/sys", "/sys",
	} {
		if hostPath == directory || strings.HasPrefix(hostPath, directory+"/") {
			return true
		}
	}
	for _, file := range []string{"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ld.so.preload"} {
		if hostPath == file {
			return true
		}
	}
	return false
}
