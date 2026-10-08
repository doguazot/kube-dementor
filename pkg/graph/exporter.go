package graph

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/kube-dementor/kube-dementor/pkg/models"
)

const batchSize = 500

type Exporter struct {
	uri      string
	user     string
	password string
	database string
}

func New(uri, user, password, database string) *Exporter {
	return &Exporter{
		uri:      uri,
		user:     user,
		password: password,
		database: database,
	}
}

func (ex *Exporter) Export(ctx context.Context, graph *models.AttackGraph) error {
	driver, err := neo4j.NewDriverWithContext(ex.uri, neo4j.BasicAuth(ex.user, ex.password, ""))
	if err != nil {
		return fmt.Errorf("neo4j driver: %w", err)
	}
	defer driver.Close(ctx)

	if err := driver.VerifyConnectivity(ctx); err != nil {
		return fmt.Errorf("neo4j connectivity: %w", err)
	}
	log.Println("[graph] Connected to Neo4j")

	session := driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: ex.database})
	defer session.Close(ctx)

	if err := ex.initSchema(ctx, session); err != nil {
		return fmt.Errorf("init schema: %w", err)
	}

	if err := ex.clearDB(ctx, session); err != nil {
		return fmt.Errorf("clear db: %w", err)
	}

	data := &graph.ClusterData
	if err := ex.insertNodes(ctx, session, data); err != nil {
		return fmt.Errorf("insert nodes: %w", err)
	}

	if err := ex.insertEdges(ctx, session, graph.Edges); err != nil {
		return fmt.Errorf("insert edges: %w", err)
	}

	log.Println("[graph] Export complete")
	return nil
}

func (ex *Exporter) initSchema(ctx context.Context, session neo4j.SessionWithContext) error {
	log.Println("[graph] Initializing schema...")
	constraints := []string{
		"CREATE CONSTRAINT identity_uid IF NOT EXISTS FOR (n:Identity) REQUIRE n.uid IS UNIQUE",
		"CREATE CONSTRAINT permissionset_uid IF NOT EXISTS FOR (n:PermissionSet) REQUIRE n.uid IS UNIQUE",
		"CREATE CONSTRAINT pod_uid IF NOT EXISTS FOR (n:Pod) REQUIRE n.uid IS UNIQUE",
		"CREATE CONSTRAINT container_uid IF NOT EXISTS FOR (n:Container) REQUIRE n.uid IS UNIQUE",
		"CREATE CONSTRAINT k8snode_uid IF NOT EXISTS FOR (n:K8sNode) REQUIRE n.uid IS UNIQUE",
		"CREATE CONSTRAINT volume_uid IF NOT EXISTS FOR (n:Volume) REQUIRE n.uid IS UNIQUE",
		"CREATE CONSTRAINT action_uid IF NOT EXISTS FOR (n:Action) REQUIRE n.uid IS UNIQUE",
	}
	for _, q := range constraints {
		if err := consumeWrite(ctx, session, q, nil); err != nil {
			return fmt.Errorf("constraint [%s]: %w", q, err)
		}
	}
	return nil
}

func (ex *Exporter) clearDB(ctx context.Context, session neo4j.SessionWithContext) error {
	log.Println("[graph] Clearing existing data...")
	return consumeWrite(ctx, session, "MATCH (n) DETACH DELETE n", nil)
}

func (ex *Exporter) insertNodes(ctx context.Context, session neo4j.SessionWithContext, data *models.ClusterData) error {
	if err := ex.insertIdentities(ctx, session, data.Identities); err != nil {
		return err
	}
	if err := ex.insertPermissionSets(ctx, session, data.PermissionSets); err != nil {
		return err
	}
	if err := ex.insertPods(ctx, session, data.Pods); err != nil {
		return err
	}
	if err := ex.insertContainers(ctx, session, data.Containers); err != nil {
		return err
	}
	if err := ex.insertK8sNodes(ctx, session, data.Nodes); err != nil {
		return err
	}
	if err := ex.insertVolumes(ctx, session, data.Volumes); err != nil {
		return err
	}
	if err := batchWrite(ctx, session, `UNWIND $batch AS row CREATE (n:Action) SET n = row`, data.Actions,
		func(action models.ActionNode) map[string]any {
			return map[string]any{
				"uid": action.UID, "name": action.Name, "namespace": action.Namespace, "kind": action.Kind,
				"admission": action.Admission, "nodeName": action.NodeName, "technique": action.Technique, "ownerUID": action.OwnerUID,
			}
		}, "Action"); err != nil {
		return err
	}
	return nil
}

func (ex *Exporter) insertIdentities(ctx context.Context, session neo4j.SessionWithContext, items []models.IdentityNode) error {
	cypher := `UNWIND $batch AS row
		CREATE (n:Identity {
			uid: row.uid, name: row.name, namespace: row.namespace,
			kind: row.kind, automountToken: row.automountToken
		})`
	return ex.batchWrite(ctx, session, cypher, items, func(item models.IdentityNode) map[string]any {
		automount := true
		if item.AutomountToken != nil {
			automount = *item.AutomountToken
		}
		return map[string]any{
			"uid": item.UID, "name": item.Name, "namespace": item.Namespace,
			"kind": string(item.Kind), "automountToken": automount,
		}
	}, "Identity")
}

func (ex *Exporter) insertPermissionSets(ctx context.Context, session neo4j.SessionWithContext, items []models.PermissionSetNode) error {
	cypher := `UNWIND $batch AS row
		CREATE (n:PermissionSet {
			uid: row.uid, name: row.name, namespace: row.namespace,
			kind: row.kind, rules: row.rules
		})`
	return ex.batchWrite(ctx, session, cypher, items, func(item models.PermissionSetNode) map[string]any {
		return map[string]any{
			"uid": item.UID, "name": item.Name, "namespace": item.Namespace,
			"kind": string(item.Kind), "rules": serializeRules(item.Rules),
		}
	}, "PermissionSet")
}

func (ex *Exporter) insertPods(ctx context.Context, session neo4j.SessionWithContext, items []models.PodNode) error {
	cypher := `UNWIND $batch AS row
		CREATE (n:Pod {
			uid: row.uid, name: row.name, namespace: row.namespace,
			nodeName: row.nodeName, serviceAccountName: row.serviceAccountName,
			hostPID: row.hostPID, hostNetwork: row.hostNetwork, hostIPC: row.hostIPC,
			hasProjectedToken: row.hasProjectedToken
		})`
	return ex.batchWrite(ctx, session, cypher, items, func(item models.PodNode) map[string]any {
		return map[string]any{
			"uid": item.UID, "name": item.Name, "namespace": item.Namespace,
			"nodeName": item.NodeName, "serviceAccountName": item.ServiceAccountName,
			"hostPID": item.HostPID, "hostNetwork": item.HostNetwork, "hostIPC": item.HostIPC,
			"hasProjectedToken": item.HasProjectedToken,
		}
	}, "Pod")
}

func (ex *Exporter) insertContainers(ctx context.Context, session neo4j.SessionWithContext, items []models.ContainerNode) error {
	cypher := `UNWIND $batch AS row
		CREATE (n:Container {
			uid: row.uid, name: row.name, image: row.image,
			podUID: row.podUID, privileged: row.privileged, capabilities: row.capabilities
		})`
	return ex.batchWrite(ctx, session, cypher, items, func(item models.ContainerNode) map[string]any {
		return map[string]any{
			"uid": item.UID, "name": item.Name, "image": item.Image,
			"podUID": item.PodUID, "privileged": item.Privileged,
			"capabilities": strings.Join(item.Capabilities, ","),
		}
	}, "Container")
}

func (ex *Exporter) insertK8sNodes(ctx context.Context, session neo4j.SessionWithContext, items []models.NodeNode) error {
	cypher := `UNWIND $batch AS row
		CREATE (n:K8sNode {
			uid: row.uid, name: row.name, isControlPlane: row.isControlPlane,
			kubeletVersion: row.kubeletVersion, internalIP: row.internalIP,
			operatingSystem: row.operatingSystem, architecture: row.architecture,
			partial: row.partial
		})`
	return ex.batchWrite(ctx, session, cypher, items, func(item models.NodeNode) map[string]any {
		return map[string]any{
			"uid": item.UID, "name": item.Name, "isControlPlane": item.IsControlPlane,
			"kubeletVersion": item.KubeletVersion, "internalIP": item.InternalIP,
			"operatingSystem": item.OperatingSystem, "architecture": item.Architecture,
			"partial": item.Partial,
		}
	}, "K8sNode")
}

func (ex *Exporter) insertVolumes(ctx context.Context, session neo4j.SessionWithContext, items []models.VolumeNode) error {
	cypher := `UNWIND $batch AS row
		CREATE (n:Volume {
			uid: row.uid, name: row.name, podUID: row.podUID,
			sourceType: row.sourceType, hostPath: row.hostPath
		})`
	return ex.batchWrite(ctx, session, cypher, items, func(item models.VolumeNode) map[string]any {
		return map[string]any{
			"uid": item.UID, "name": item.Name, "podUID": item.PodUID,
			"sourceType": item.Source.Type, "hostPath": item.Source.HostPath,
		}
	}, "Volume")
}

func (ex *Exporter) insertEdges(ctx context.Context, session neo4j.SessionWithContext, edges []models.Edge) error {

	grouped := make(map[models.EdgeType][]models.Edge)
	for _, e := range edges {
		if !models.ValidEdgeType(e.Type) {
			return fmt.Errorf("unsupported relationship type %q", e.Type)
		}
		grouped[e.Type] = append(grouped[e.Type], e)
	}

	for edgeType, batch := range grouped {
		cypher := fmt.Sprintf(`UNWIND $batch AS row
			MATCH (src {uid: row.src})
			MATCH (dst {uid: row.dst})
			CREATE (src)-[r:%s]->(dst)
			SET r += row.props`, string(edgeType))

		err := ex.batchWrite(ctx, session, cypher, batch, func(item models.Edge) map[string]any {
			props := make(map[string]any, len(item.Properties))
			for k, v := range item.Properties {
				props[k] = v
			}
			return map[string]any{
				"src":   item.SourceUID,
				"dst":   item.TargetUID,
				"props": props,
			}
		}, string(edgeType)+" edges")
		if err != nil {
			return err
		}
	}

	return nil
}

func batchWrite[T any](ctx context.Context, session neo4j.SessionWithContext, cypher string, items []T, toMap func(T) map[string]any, label string) error {
	total := len(items)
	for start := 0; start < total; start += batchSize {
		end := start + batchSize
		if end > total {
			end = total
		}
		batch := make([]map[string]any, 0, end-start)
		for _, item := range items[start:end] {
			batch = append(batch, toMap(item))
		}
		if err := consumeWrite(ctx, session, cypher, map[string]any{"batch": batch}); err != nil {
			return fmt.Errorf("batch insert %s [%d-%d]: %w", label, start, end, err)
		}
	}
	if total > 0 {
		log.Printf("[graph] Inserted %d %s", total, label)
	}
	return nil
}

func consumeWrite(ctx context.Context, session neo4j.SessionWithContext, cypher string, params map[string]any) error {
	result, err := session.Run(ctx, cypher, params)
	if err != nil {
		return err
	}
	_, err = result.Consume(ctx)
	return err
}

func (ex *Exporter) batchWrite(ctx context.Context, session neo4j.SessionWithContext, cypher string, items any, toMap any, label string) error {

	switch typedItems := items.(type) {
	case []models.IdentityNode:
		return batchWrite(ctx, session, cypher, typedItems, toMap.(func(models.IdentityNode) map[string]any), label)
	case []models.PermissionSetNode:
		return batchWrite(ctx, session, cypher, typedItems, toMap.(func(models.PermissionSetNode) map[string]any), label)
	case []models.PodNode:
		return batchWrite(ctx, session, cypher, typedItems, toMap.(func(models.PodNode) map[string]any), label)
	case []models.ContainerNode:
		return batchWrite(ctx, session, cypher, typedItems, toMap.(func(models.ContainerNode) map[string]any), label)
	case []models.NodeNode:
		return batchWrite(ctx, session, cypher, typedItems, toMap.(func(models.NodeNode) map[string]any), label)
	case []models.VolumeNode:
		return batchWrite(ctx, session, cypher, typedItems, toMap.(func(models.VolumeNode) map[string]any), label)
	case []models.Edge:
		return batchWrite(ctx, session, cypher, typedItems, toMap.(func(models.Edge) map[string]any), label)
	default:
		return fmt.Errorf("unsupported batch type for %s", label)
	}
}

func serializeRules(rules []models.PolicyRule) string {
	var parts []string
	for _, r := range rules {
		part := fmt.Sprintf("apiGroups=[%s] resources=[%s] verbs=[%s]",
			strings.Join(r.APIGroups, ","),
			strings.Join(r.Resources, ","),
			strings.Join(r.Verbs, ","),
		)
		parts = append(parts, part)
	}
	return strings.Join(parts, "; ")
}
