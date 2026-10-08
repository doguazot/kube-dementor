package models

type EdgeType string

const (
	EdgeContains      EdgeType = "CONTAINS"
	EdgeHasPermission EdgeType = "HAS_PERMISSION"
	EdgeMemberOf      EdgeType = "MEMBER_OF"
)

const (
	EdgeRoleBind            EdgeType = "ROLE_BIND"
	EdgePodExec             EdgeType = "POD_EXEC"
	EdgeTokenSteal          EdgeType = "TOKEN_STEAL"
	EdgeIdentityImpersonate EdgeType = "IDENTITY_IMPERSONATE"
	EdgePodCreate           EdgeType = "POD_CREATE"
	EdgePodCreateEscape     EdgeType = "POD_CREATE_ESCAPE"
)

const (
	EdgeCEPrivMount EdgeType = "CE_PRIV_MOUNT"
	EdgeCENsenter   EdgeType = "CE_NSENTER"
)

type Edge struct {
	SourceUID  string            `json:"sourceUID"`
	TargetUID  string            `json:"targetUID"`
	Type       EdgeType          `json:"type"`
	Properties map[string]string `json:"properties,omitempty"`
}

type AttackGraph struct {
	ClusterData ClusterData `json:"clusterData"`
	Edges       []Edge      `json:"edges"`
}

func ValidEdgeType(kind EdgeType) bool {
	switch kind {
	case EdgeContains, EdgeHasPermission, EdgeMemberOf, EdgeRoleBind,
		EdgePodExec, EdgeTokenSteal, EdgeIdentityImpersonate, EdgePodCreate,
		EdgePodCreateEscape, EdgeCEPrivMount, EdgeCENsenter:
		return true
	}
	return false
}
