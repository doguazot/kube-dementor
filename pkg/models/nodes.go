package models

type NodeType string

const (
	NodeTypeIdentity      NodeType = "Identity"
	NodeTypePermissionSet NodeType = "PermissionSet"
	NodeTypePod           NodeType = "Pod"
	NodeTypeContainer     NodeType = "Container"
	NodeTypeNode          NodeType = "Node"
	NodeTypeVolume        NodeType = "Volume"
)

type IdentityKind string

const (
	IdentityKindUser           IdentityKind = "User"
	IdentityKindGroup          IdentityKind = "Group"
	IdentityKindServiceAccount IdentityKind = "ServiceAccount"
	IdentityKindOperator       IdentityKind = "Operator"
)

type PermissionSetKind string

const (
	PermissionSetKindRole        PermissionSetKind = "Role"
	PermissionSetKindClusterRole PermissionSetKind = "ClusterRole"
)

type PolicyRule struct {
	APIGroups       []string `json:"apiGroups"`
	Resources       []string `json:"resources"`
	Verbs           []string `json:"verbs"`
	ResourceNames   []string `json:"resourceNames,omitempty"`
	NonResourceURLs []string `json:"nonResourceURLs,omitempty"`
}

type IdentityNode struct {
	UID       string       `json:"uid"`
	Name      string       `json:"name"`
	Namespace string       `json:"namespace,omitempty"`
	Kind      IdentityKind `json:"kind"`

	AutomountToken *bool `json:"automountToken,omitempty"`
}

type PermissionSetNode struct {
	UID       string            `json:"uid"`
	Name      string            `json:"name"`
	Namespace string            `json:"namespace,omitempty"`
	Kind      PermissionSetKind `json:"kind"`
	Rules     []PolicyRule      `json:"rules"`
}

type VolumeMount struct {
	Name        string `json:"name"`
	MountPath   string `json:"mountPath"`
	ReadOnly    bool   `json:"readOnly"`
	SubPath     string `json:"subPath,omitempty"`
	SubPathExpr string `json:"subPathExpr,omitempty"`
}

type ContainerNode struct {
	UID          string        `json:"uid"`
	Name         string        `json:"name"`
	Image        string        `json:"image"`
	PodUID       string        `json:"podUID"`
	Privileged   bool          `json:"privileged"`
	Capabilities []string      `json:"capabilities,omitempty"`
	VolumeMounts []VolumeMount `json:"volumeMounts,omitempty"`
	RunAsUser    *int64        `json:"runAsUser,omitempty"`
	RunAsNonRoot *bool         `json:"runAsNonRoot,omitempty"`
}

type VolumeSource struct {
	Type     string `json:"type"`
	HostPath string `json:"hostPath,omitempty"`
}

type VolumeNode struct {
	UID    string       `json:"uid"`
	Name   string       `json:"name"`
	PodUID string       `json:"podUID"`
	Source VolumeSource `json:"source"`
}

type PodNode struct {
	UID                string `json:"uid"`
	Name               string `json:"name"`
	Namespace          string `json:"namespace"`
	NodeName           string `json:"nodeName"`
	ServiceAccountName string `json:"serviceAccountName"`
	HostPID            bool   `json:"hostPID"`
	HostNetwork        bool   `json:"hostNetwork"`
	HostIPC            bool   `json:"hostIPC"`
	AutomountToken     *bool  `json:"automountToken,omitempty"`
	HasProjectedToken  bool   `json:"hasProjectedToken,omitempty"`
}

type NodeNode struct {
	UID             string            `json:"uid"`
	Name            string            `json:"name"`
	Labels          map[string]string `json:"labels,omitempty"`
	IsControlPlane  bool              `json:"isControlPlane"`
	KubeletVersion  string            `json:"kubeletVersion,omitempty"`
	InternalIP      string            `json:"internalIP,omitempty"`
	OperatingSystem string            `json:"operatingSystem,omitempty"`
	Architecture    string            `json:"architecture,omitempty"`
	Partial         bool              `json:"partial,omitempty"`
}

type ActionNode struct {
	UID       string `json:"uid"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	Kind      string `json:"kind"`
	Admission string `json:"admission,omitempty"`
	NodeName  string `json:"nodeName,omitempty"`
	Technique string `json:"technique,omitempty"`
	OwnerUID  string `json:"ownerUID,omitempty"`
}

type BindingInfo struct {
	UID            string `json:"uid"`
	Name           string `json:"name"`
	Namespace      string `json:"namespace,omitempty"`
	IsClusterScope bool   `json:"isClusterScope"`
	RoleRefKind    string `json:"roleRefKind"`
	RoleRefName    string `json:"roleRefName"`
	SubjectKind    string `json:"subjectKind"`
	SubjectName    string `json:"subjectName"`
	SubjectNS      string `json:"subjectNamespace,omitempty"`
}

type ClusterData struct {
	Identities     []IdentityNode      `json:"identities"`
	PermissionSets []PermissionSetNode `json:"permissionSets"`
	Pods           []PodNode           `json:"pods"`
	Containers     []ContainerNode     `json:"containers"`
	Nodes          []NodeNode          `json:"nodes"`
	Volumes        []VolumeNode        `json:"volumes"`
	Bindings       []BindingInfo       `json:"bindings"`
	Actions        []ActionNode        `json:"actions,omitempty"`
	Memberships    []Edge              `json:"memberships,omitempty"`
}
