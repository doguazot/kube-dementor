package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/kube-dementor/kube-dementor/pkg/models"
	"github.com/kube-dementor/kube-dementor/pkg/scanstore"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type RunScanFunc func(namespace, kubeconfig string)

type Server struct {
	driver      neo4j.DriverWithContext
	database    string
	addr        string
	webDir      string
	scans       *scanstore.Store
	runScan     RunScanFunc
	scanning    atomic.Bool
	queryDriver neo4j.DriverWithContext
}

func NewServer(neo4jURI, user, password, database, listenAddr, webDir string, scans *scanstore.Store, runScan RunScanFunc) (*Server, error) {
	driver, err := neo4j.NewDriverWithContext(neo4jURI, neo4j.BasicAuth(user, password, ""))
	if err != nil {
		return nil, fmt.Errorf("neo4j driver: %w", err)
	}
	return &Server{
		driver:   driver,
		database: database,
		addr:     listenAddr,
		webDir:   webDir,
		scans:    scans,
		runScan:  runScan,
	}, nil
}

func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	mux.HandleFunc("GET /api/v1/stats", s.handleStats)
	mux.HandleFunc("GET /api/v1/shortest-path", s.handleShortestPath)
	mux.HandleFunc("GET /api/v1/attack-paths", s.handleAttackPaths)
	mux.HandleFunc("GET /api/v1/critical-assets", s.handleCriticalAssets)
	mux.HandleFunc("GET /api/v1/container-escapes", s.handleContainerEscapes)
	mux.HandleFunc("POST /api/v1/query", s.handleCustomQuery)
	mux.HandleFunc("GET /api/v1/exploitability", s.handleExploitability)
	mux.HandleFunc("GET /api/v1/nodes", s.handleNodes)
	mux.HandleFunc("GET /api/v1/graph", s.handleGraph)
	mux.HandleFunc("GET /api/v1/exploitability-details", s.handleExploitabilityDetails)
	mux.HandleFunc("GET /api/v1/attack-chain", s.handleAttackChain)
	mux.HandleFunc("GET /api/v1/scans", s.handleListScans)
	mux.HandleFunc("GET /api/v1/scans/", s.handleScanDetail)
	mux.HandleFunc("POST /api/v1/scans", s.handleNewScan)

	if s.webDir != "" {
		fs := http.FileServer(http.Dir(s.webDir))
		mux.Handle("/", fs)
		log.Printf("[api] Serving dashboard from %s", s.webDir)
	}

	srv := &http.Server{
		Addr:         s.addr,
		Handler:      withLogging(mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()

	log.Printf("[api] Listening on %s", s.addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *Server) Close(ctx context.Context) {
	s.driver.Close(ctx)
	if s.queryDriver != nil {
		s.queryDriver.Close(ctx)
	}
}

func (s *Server) ConfigureReadOnlyQueries(uri, user, password string) error {
	driver, err := neo4j.NewDriverWithContext(uri, neo4j.BasicAuth(user, password, ""))
	if err != nil {
		return err
	}
	s.queryDriver = driver
	return nil
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	err := s.driver.VerifyConnectivity(r.Context())
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"status": "unhealthy",
			"error":  err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "healthy"})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	session := s.driver.NewSession(r.Context(), neo4j.SessionConfig{DatabaseName: s.database})
	defer session.Close(r.Context())

	cypher := `
		MATCH (n) 
		WITH labels(n) AS lbls, count(*) AS cnt
		UNWIND lbls AS label
		RETURN label, sum(cnt) AS count
		ORDER BY count DESC`

	result, err := session.Run(r.Context(), cypher, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	stats := make(map[string]int64)
	for result.Next(r.Context()) {
		record := result.Record()
		label, _ := record.Get("label")
		count, _ := record.Get("count")
		stats[label.(string)] = count.(int64)
	}
	if err := result.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleShortestPath(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	source := r.URL.Query().Get("source")

	if target == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("missing 'target' query parameter"))
		return
	}

	session := s.driver.NewSession(r.Context(), neo4j.SessionConfig{DatabaseName: s.database})
	defer session.Close(r.Context())

	var cypher string
	params := map[string]any{}

	if source != "" {

		cypher = `
			MATCH (src {uid: $source}), (dst {uid: $target}),
			path = shortestPath((src)-[:ROLE_BIND|POD_EXEC|TOKEN_STEAL|IDENTITY_IMPERSONATE|MEMBER_OF|CONTAINS|POD_CREATE|POD_CREATE_ESCAPE|CE_PRIV_MOUNT|CE_NSENTER*..15]->(dst))
			RETURN path`
		params["source"] = source
		params["target"] = target
	} else {

		cypher = `
			MATCH (src:Identity), (dst)
			WHERE dst.uid = $target OR dst.name = $target
			MATCH path = shortestPath((src)-[:ROLE_BIND|POD_EXEC|TOKEN_STEAL|IDENTITY_IMPERSONATE|MEMBER_OF|CONTAINS|POD_CREATE|POD_CREATE_ESCAPE|CE_PRIV_MOUNT|CE_NSENTER*..15]->(dst))
			RETURN src.name AS sourceName, src.uid AS sourceUID,
			       length(path) AS hops,
			       [rel IN relationships(path) | type(rel)] AS edgeTypes
			ORDER BY hops ASC
			LIMIT 20`
		params["target"] = target
	}

	result, err := session.Run(r.Context(), cypher, params)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	var paths []map[string]any
	for result.Next(r.Context()) {
		paths = append(paths, recordToMap(result.Record()))
	}
	if err := result.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	if len(paths) == 0 {
		writeJSON(w, http.StatusOK, map[string]string{"message": "no paths found"})
		return
	}

	writeJSON(w, http.StatusOK, paths)
}

func (s *Server) handleAttackPaths(w http.ResponseWriter, r *http.Request) {
	edgeType := r.URL.Query().Get("type")
	if edgeType == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("missing 'type' query parameter (e.g. ROLE_BIND, POD_EXEC, TOKEN_STEAL, CE_NSENTER)"))
		return
	}
	if !models.ValidEdgeType(models.EdgeType(edgeType)) {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid relationship type"))
		return
	}

	session := s.driver.NewSession(r.Context(), neo4j.SessionConfig{DatabaseName: s.database})
	defer session.Close(r.Context())

	cypher := fmt.Sprintf(`
		MATCH (src)-[r:%s]->(dst)
		RETURN src.uid AS sourceUID, src.name AS sourceName,
		       dst.uid AS targetUID, dst.name AS targetName,
		       properties(r) AS properties
		LIMIT 100`, edgeType)

	result, err := session.Run(r.Context(), cypher, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	var rows []map[string]any
	for result.Next(r.Context()) {
		rows = append(rows, recordToMap(result.Record()))
	}
	if err := result.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, rows)
}

func (s *Server) handleCriticalAssets(w http.ResponseWriter, r *http.Request) {
	session := s.driver.NewSession(r.Context(), neo4j.SessionConfig{DatabaseName: s.database})
	defer session.Close(r.Context())

	cypher := `
		MATCH (id:Identity)-[:ROLE_BIND]->(ps:PermissionSet {name: "cluster-admin"})
		RETURN id.uid AS uid, id.name AS name, id.namespace AS namespace, id.kind AS kind
		UNION
		MATCH (id:Identity)-[:IDENTITY_IMPERSONATE]->(target:Identity)-[:ROLE_BIND]->(ps:PermissionSet {name: "cluster-admin"})
		RETURN id.uid AS uid, id.name AS name, id.namespace AS namespace, id.kind AS kind`

	result, err := session.Run(r.Context(), cypher, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	var rows []map[string]any
	for result.Next(r.Context()) {
		rows = append(rows, recordToMap(result.Record()))
	}
	if err := result.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, rows)
}

func (s *Server) handleContainerEscapes(w http.ResponseWriter, r *http.Request) {
	session := s.driver.NewSession(r.Context(), neo4j.SessionConfig{DatabaseName: s.database})
	defer session.Close(r.Context())

	cypher := `
		MATCH (c:Container)-[r:CE_PRIV_MOUNT|CE_NSENTER]->(n:K8sNode)
		RETURN c.uid AS containerUID, c.name AS containerName, c.image AS image,
		       type(r) AS escapeType, properties(r) AS details,
		       n.uid AS nodeUID, n.name AS nodeName
		ORDER BY n.name`

	result, err := session.Run(r.Context(), cypher, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	var rows []map[string]any
	for result.Next(r.Context()) {
		rows = append(rows, recordToMap(result.Record()))
	}
	if err := result.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, rows)
}

func (s *Server) handleCustomQuery(w http.ResponseWriter, r *http.Request) {
	if s.queryDriver == nil {
		writeError(w, http.StatusForbidden, fmt.Errorf("custom queries are disabled; configure a separate read-only Neo4j principal"))
		return
	}
	var body struct {
		Cypher string         `json:"cypher"`
		Params map[string]any `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return
	}
	if body.Cypher == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("missing 'cypher' field"))
		return
	}

	session := s.queryDriver.NewSession(r.Context(), neo4j.SessionConfig{
		DatabaseName: s.database,
		AccessMode:   neo4j.AccessModeRead,
	})
	defer session.Close(r.Context())

	result, err := session.Run(r.Context(), body.Cypher, body.Params)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	var rows []map[string]any
	for result.Next(r.Context()) {
		rows = append(rows, recordToMap(result.Record()))
	}
	if err := result.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, rows)
}

func (s *Server) handleExploitability(w http.ResponseWriter, r *http.Request) {
	session := s.driver.NewSession(r.Context(), neo4j.SessionConfig{DatabaseName: s.database})
	defer session.Close(r.Context())

	cypher := `
		MATCH ()-[r]->()
		WHERE r.exploitable IS NOT NULL
		RETURN r.exploitable AS status, count(*) AS count`

	result, err := session.Run(r.Context(), cypher, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	resp := map[string]int64{"YES": 0, "NO": 0, "UNCHECKED": 0}
	for result.Next(r.Context()) {
		rec := result.Record()
		status, _ := rec.Get("status")
		count, _ := rec.Get("count")
		if s, ok := status.(string); ok {
			resp[s] = count.(int64)
		}
	}
	if err := result.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request) {
	nodeType := r.URL.Query().Get("type")
	if nodeType == "" {
		nodeType = "Pod"
	}

	allowed := map[string]bool{"Pod": true, "Container": true, "Identity": true, "PermissionSet": true, "K8sNode": true, "Volume": true, "Action": true}
	if !allowed[nodeType] {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid node type: %s", nodeType))
		return
	}

	session := s.driver.NewSession(r.Context(), neo4j.SessionConfig{DatabaseName: s.database})
	defer session.Close(r.Context())

	cypher := fmt.Sprintf("MATCH (n:%s) RETURN n ORDER BY n.name LIMIT 500", nodeType)
	result, err := session.Run(r.Context(), cypher, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	var rows []map[string]any
	for result.Next(r.Context()) {
		node, ok := result.Record().Get("n")
		if !ok {
			continue
		}
		if n, ok := node.(neo4j.Node); ok {
			props := make(map[string]any, len(n.Props))
			for k, v := range n.Props {
				props[k] = v
			}
			props["_labels"] = n.Labels
			rows = append(rows, props)
		}
	}
	if err := result.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, rows)
}

func (s *Server) handleGraph(w http.ResponseWriter, r *http.Request) {
	s.readDashboardRows(w, r, `
		MATCH (a)-[rel]->(b)
		WHERE type(rel) IN $types
		RETURN a.uid AS source, a.name AS sname, labels(a)[0] AS slabel,
		       b.uid AS target, b.name AS tname, labels(b)[0] AS tlabel, type(rel) AS type
		ORDER BY CASE WHEN type(rel) IN ['CONTAINS', 'MEMBER_OF'] THEN 1 ELSE 0 END,
		         type(rel), a.uid, b.uid
		LIMIT 500`,
		map[string]any{"types": []string{"ROLE_BIND", "POD_EXEC", "TOKEN_STEAL", "IDENTITY_IMPERSONATE",
			"CE_PRIV_MOUNT", "CE_NSENTER", "MEMBER_OF", "CONTAINS", "POD_CREATE", "POD_CREATE_ESCAPE"}})
}

func (s *Server) handleExploitabilityDetails(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	if status != "YES" && status != "NO" && status != "UNCHECKED" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid exploitability status"))
		return
	}
	s.readDashboardRows(w, r, `
		MATCH (a)-[rel]->(b) WHERE rel.exploitable = $status
		RETURN a.name AS source, b.name AS target, type(rel) AS type,
		       rel.severity AS severity, rel.reason AS reason,
		       rel.exploit_cmd AS exploit_cmd, rel.exploitable_reason AS exp_reason
		LIMIT 200`, map[string]any{"status": status})
}

func (s *Server) readDashboardRows(w http.ResponseWriter, r *http.Request, query string, params map[string]any) {
	session := s.driver.NewSession(r.Context(), neo4j.SessionConfig{
		DatabaseName: s.database, AccessMode: neo4j.AccessModeRead,
	})
	defer session.Close(r.Context())
	result, err := session.Run(r.Context(), query, params)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	rows := make([]map[string]any, 0)
	for result.Next(r.Context()) {
		rows = append(rows, recordToMap(result.Record()))
	}
	if err := result.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

func (s *Server) handleAttackChain(w http.ResponseWriter, r *http.Request) {
	identity := r.URL.Query().Get("identity")
	if identity == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("missing 'identity' query parameter"))
		return
	}

	session := s.driver.NewSession(r.Context(), neo4j.SessionConfig{DatabaseName: s.database})
	defer session.Close(r.Context())

	cypher1 := `
		MATCH path=(src:Identity)-[:ROLE_BIND|POD_EXEC|TOKEN_STEAL|IDENTITY_IMPERSONATE|CE_PRIV_MOUNT|CE_NSENTER|MEMBER_OF|CONTAINS|POD_CREATE|POD_CREATE_ESCAPE*1..6]->(t1)
		WHERE src.name = $identity OR src.uid = $identity
		RETURN DISTINCT t1.name AS targetName, t1.uid AS targetUID, labels(t1)[0] AS targetType,
		       [rel IN relationships(path) | type(rel)] AS edgeType, length(path) AS hops
		ORDER BY hops
		LIMIT 200`

	result1, err := session.Run(r.Context(), cypher1, map[string]any{"identity": identity})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	var rows []map[string]any
	for result1.Next(r.Context()) {
		rows = append(rows, recordToMap(result1.Record()))
	}
	if err := result1.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	permCypher := `
		MATCH (src:Identity)-[grant:HAS_PERMISSION]->(ps:PermissionSet)
		WHERE src.name = $identity OR src.uid = $identity
		RETURN ps.name AS role, ps.uid AS roleUID, grant.namespace AS namespace, grant.clusterScope AS clusterScope
		LIMIT 20`

	permResult, err := session.Run(r.Context(), permCypher, map[string]any{"identity": identity})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	var perms []map[string]any
	for permResult.Next(r.Context()) {
		perms = append(perms, recordToMap(permResult.Record()))
	}
	if err := permResult.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"identity":    identity,
		"reachable":   rows,
		"directPerms": perms,
	})
}

func (s *Server) handleScanDetail(w http.ResponseWriter, r *http.Request) {

	prefix := "/api/v1/scans/"
	id := r.URL.Path[len(prefix):]
	if id == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("missing scan ID in path"))
		return
	}
	if s.scans == nil {
		writeError(w, http.StatusNotFound, fmt.Errorf("scan store not configured"))
		return
	}

	results, err := s.scans.GetResults(id)
	if err != nil {

		meta, metaErr := s.scans.Get(id)
		if metaErr != nil {
			writeError(w, http.StatusNotFound, fmt.Errorf("scan not found: %s", id))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"meta":  meta,
			"edges": []any{},
			"nodes": map[string]int{},
			"note":  "Full results not available for this scan (pre-upgrade scan)",
		})
		return
	}

	writeJSON(w, http.StatusOK, results)
}

func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	if s.scans == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	scans, err := s.scans.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, scans)
}

func (s *Server) handleNewScan(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Namespace  string `json:"namespace"`
		Kubeconfig string `json:"kubeconfig"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid JSON: %w", err))
		return
	}

	if s.runScan == nil {
		writeError(w, http.StatusNotImplemented, fmt.Errorf("scan trigger not configured"))
		return
	}

	if !s.scanning.CompareAndSwap(false, true) {
		writeError(w, http.StatusConflict, fmt.Errorf("a graph scan is already running"))
		return
	}
	go func() {
		defer s.scanning.Store(false)
		s.runScan(body.Namespace, body.Kubeconfig)
	}()

	writeJSON(w, http.StatusAccepted, map[string]string{
		"status":  "accepted",
		"message": "Scan started. Check /api/v1/scans for progress.",
	})
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func recordToMap(record *neo4j.Record) map[string]any {
	m := make(map[string]any, len(record.Keys))
	for _, key := range record.Keys {
		val, _ := record.Get(key)
		m[key] = val
	}
	return m
}

func withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("[api] %s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}
