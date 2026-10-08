# Kube-Dementor — Kubernetes Attack Graph Analyzer

Kubernetes security scanner with BloodHound-style attack graphs. It combines visible workload configuration, scoped RBAC, self-authorization checks, and non-persistent pod admission checks. Use the built-in web UI or the optional Neo4j API.

## Scanning an Empty Namespace

Workload-create authority matters even when no pods currently exist. A namespace-admin can potentially create a privileged workload without first finding a privileged pod.

The scanner now reports these stages separately:

1. **Authorization:** can the current identity create pods in the checked namespace?
2. **Admission:** does the API server accept privileged host-root or hostPID specifications with `dryRun=All`?
3. **Placement:** if visible control-plane nodes exist, does admission accept the same specifications targeting those nodes?
4. **Runtime:** scheduling, container startup, host escape, and compromise remain **unverified**.

Admission checks use a pause image, no exploit command, and no persisted pod. Acceptance is a potential attack path, not proof of compromise. Admission rejection blocks that tested specification, not every possible escape technique. Discover mode performs no pod-create admission request.

If namespace listing is forbidden, discovery uses `--namespace`, the kubeconfig context namespace, or `default`. Supply `--namespace` when the context does not identify your accessible namespace. Resource lists are paginated; failed collections and authorization checks produce **incomplete coverage** warnings rather than a clean bill of health.

## Quick Start

```bash
# Build without replacing an existing binary
go build -o bin/kube-dementor ./cmd/kube-dementor

# Passive discovery, with no pod-create requests
./bin/kube-dementor discover --namespace my-namespace --refresh-threat-intel=false

# Authorization and safe dry-run admission assessment
./bin/kube-dementor scan --namespace my-namespace --refresh-threat-intel=false

# Built-in UI, default http://127.0.0.1:8080
./bin/kube-dementor web
```

`--namespace` limits namespaced inventory. Visible cluster-scoped objects still inform the assessment. A RoleBinding to `cluster-admin` grants namespace authority, not a cluster-wide `ClusterAdmin` path.

Attack findings carry structured `attackPath` evidence. The UI matches canonical user/service-account identities and uses explicit high-value endpoints, rather than guessing from display text. Service-account usage and ordinary secret mounting are not treated as attacker access on their own.

## Ephemeral Container Assessment

Discover, scan and chain runs include a read-only ephemeral-container check. Named SelfSubjectAccessReviews assess `update`/`patch` on `pods/ephemeralcontainers`, preserving pod-name restrictions even when role listing is forbidden. For relevant targets, `pods/exec` and `pods/attach` permissions are checked separately. Existing ephemeral containers retain their running, waiting, terminated or unknown status and pod-level security inheritance.

`KH-EPHEMERAL-ASSESSMENT` reports what was checked, including denials and unknown authorization. `KH-RBAC-EPHEMERAL` identifies authorized running targets; `KH-WRK-EPHEMERAL` identifies existing debug-container host-access prerequisites. No ephemeral container is injected, patched, attached or exec'd by this check. No ephemeral admission request is made, so admission and runtime behavior remain unverified.

Yellow graph branches represent potential injection or interaction, not successful exec. Host access additionally requires an observed prerequisite such as existing hostPID/hostPath and an appropriate admitted profile or a running escape-capable debug container. The check cannot change the pod's host namespaces, placement, or volumes, and does not invent a target in an empty/inaccessible namespace. Node roles are shown only when visible labels establish them. Worker access is not control-plane access.

## Active Ephemeral Injection (chain mode only)

Chain runs do not stop at authorization. Phase 2b tries the real injection on every running pod the read-only assessment marked as injectable (engine-created `kd-chain-*` pods first):

1. A **privileged root** debug container (`kd-chain-debug-*`, `sh -c "sleep 3600"`, targeting the pod's first container) is added through the `pods/ephemeralcontainers` subresource.
2. If admission rejects it, a **plain root** fallback is tried with the pod's existing hostPath volume re-mounted at `/host`.
3. Once the debug container reaches Running, exec is verified, then the actual escape is attempted from inside it: `nsenter -t 1` (hostPID pods) and `chroot /host` (hostPath pods). Success records a verified node shell and raises the chain to WORKER_NODE; later phases (escape ladder, credential harvest, recon) run in the injected container instead of assuming a `chain` container exists.

Every apiserver verdict is recorded as a step (success, failed with the denial text, or skipped with the reason). The safety guard permits PUT/PATCH **only** on the exact `pods/<name>/ephemeralcontainers` subresource; pod spec PATCHes, other PUTs, and all DELETEs stay blocked, and no existing container is ever edited, restarted, or removed.

**Persistence warning:** Kubernetes has no API to remove an ephemeral container. Debug containers injected into chain-created pods disappear with normal pod cleanup, but one injected into a pre-existing pod stays until that pod is deleted or redeployed (the step evidence includes this note). Discover/Scan runs never inject anything; only chain mode performs this test.

## Chain Results and Interactive Shells

The built-in UI now has a visual node/edge graph with pan, zoom, node dragging, and click-through details. Scan/discover graphs show **potential paths**; chain graphs show an **execution trace** with successful, failed, and skipped steps, plus explicitly yellow **potential/unverified** ephemeral-container branches. A successful read-only assessment step does not establish exec or host access. A completed run does not mean that every attack or the control-plane stage was attempted.

Shell targets are advertised only after exec was verified for that specific pod and scope. Pod names, privileged flags, successful creation, or another pod's host access do not prove a working shell. Missing prerequisites appear as skipped stages. Control-plane access requires verified placement, not merely accepting a pod with tolerations.

Interactive shell attachment is disabled by default. `web --live-exploit` is an explicit opt-in for an authorized test environment; it enables more than just terminal display. Do not enable it solely to hide an error. The UI checks a read-only `/shell-status` endpoint first and shows the real rejection reason. Opening a terminal never deletes, recreates, or reschedules a stopped pod, and a failed host-shell attempt does not silently fall back to a container shell.

## Exec and the rexec fallback

Every exec path in the tool works the same way: the standard `pods/exec` subresource is tried **first**, and when that fails for any reason, the same command is retried through the audited `kubectl-rexec` plugin (looked up in `PATH`, then `/usr/local/bin/kubectl-rexec`). This covers the autonomous chain engine, exploit-mode escape/chain probes, one-shot live-exploit capabilities, and the interactive web terminal, so clusters whose admission webhook mandates rexec keep working without configuration. A command that runs inside the container and exits non-zero (for example a binary missing from a minimal image) is not treated as an exec failure: the captured output stays valid evidence, verification is marker-based, and the exit code is reported separately.

Completed reports persist to disk under `~/.kube-dementor/reports/` and are reloaded when the server restarts. Live cluster sessions (interactive shells, one-shot exploit runs) are the only thing a restart does not restore; the UI states this when you open such a report.

## Architecture

| Module | Description |
|---|---|
| **Ingestor** | Reads K8s API resources (Pods, Nodes, Roles, Bindings, ServiceAccounts) via `client-go` with pagination |
| **Converter** | Normalizes raw K8s objects into lightweight graph-friendly structs |
| **Engine** | Evaluates attack rules (RBAC escalation, container escape) and produces edges |
| **Graph Exporter** | Batch-writes nodes and edges to Neo4j using parameterized Cypher |
| **API** | REST API for querying attack paths (e.g. shortest path to cluster-admin) |

## Graph Schema

### Nodes
- **Identity** — User, Group, ServiceAccount
- **PermissionSet** — Role, ClusterRole (with policy rules)
- **Pod** — Running workloads
- **Container** — Individual containers (privileged status, capabilities, mounts)
- **Node** — Worker / control-plane nodes
- **Volume** — Attached volumes (especially hostPath)
- **Action** — Prospective workload creation / node-access capability

### Edges (Attack Paths)
- `CONTAINS` — Node→Pod→Container structural hierarchy
- `HAS_PERMISSION` — Identity→PermissionSet
- `MEMBER_OF` — Authenticated user / ServiceAccount→Group
- `POD_CREATE` — Identity→prospective pod-creation Action, independent of existing pods
- `POD_CREATE` also connects an operator's creation Action to its admitted security specification
- `POD_CREATE_ESCAPE` — Conditional admitted specification→Node / unplaced node-access Action, not runtime proof
- `ROLE_BIND` — Identity bound to a cluster-wide critical role via ClusterRoleBinding
- `POD_EXEC` — Identity with pods/exec permission on a Pod
- `TOKEN_STEAL` — Pod mounting a high-privilege SA token
- `IDENTITY_IMPERSONATE` — Identity with impersonate verb
- `CE_PRIV_MOUNT` — Container with hostPath `/` read-write → Node escape
- `CE_NSENTER` — Root privileged / SYS_ADMIN container with hostPID → potential Node namespace escape

## Optional Neo4j Server

```bash
# Start Neo4j
docker compose up -d

# Build
go build -o bin/kube-dementor ./cmd/kube-dementor

# Run (uses current kubeconfig)
./bin/kube-dementor server
```

## REST API Endpoints

After ingestion and graph export, the optional server listens on `127.0.0.1:8888` (configurable via `KUBE_DEMENTOR_LISTEN`). Keep it on loopback unless you provide an authenticated reverse proxy. Concurrent rescans are rejected to avoid mixing graph snapshots. Scan metadata and saved results include incomplete-coverage warnings.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/health` | Neo4j connectivity check |
| `GET` | `/api/v1/stats` | Node counts by label |
| `GET` | `/api/v1/shortest-path?target=cluster-admin` | Shortest paths from any identity to target |
| `GET` | `/api/v1/shortest-path?source=<uid>&target=<uid>` | Shortest path between two specific nodes |
| `GET` | `/api/v1/attack-paths?type=ROLE_BIND` | List attack paths by edge type |
| `GET` | `/api/v1/critical-assets` | Identities with direct/indirect cluster-admin access |
| `GET` | `/api/v1/container-escapes` | All container escape paths (CE_PRIV_MOUNT, CE_NSENTER) |
| `GET` | `/api/v1/graph` | Bounded graph snapshot for the dashboard, including prospective actions |
| `GET` | `/api/v1/exploitability-details?status=UNCHECKED` | Bounded findings for a validated status |
| `POST` | `/api/v1/query` | Disabled by default; requires a separate read-only Neo4j principal |

To enable custom queries, set `NEO4J_QUERY_USER` and `NEO4J_QUERY_PASS` to a **separate, database-enforced read-only principal**. Do not give this account write access. Neo4j read access mode alone does not enforce read-only Cypher.

### Example API Calls

```bash
# Health check
curl http://localhost:8888/api/v1/health

# Who can reach cluster-admin?
curl "http://localhost:8888/api/v1/shortest-path?target=cluster-admin"

# List all container escape vectors
curl http://localhost:8888/api/v1/container-escapes

# Custom query, only when a separate read-only principal is configured
curl -X POST http://localhost:8888/api/v1/query \
  -H "Content-Type: application/json" \
  -d '{"cypher":"MATCH (n:Identity)-[r:ROLE_BIND]->(p:PermissionSet) RETURN n.name, p.name LIMIT 10"}'
```

## Example Neo4j Cypher Queries

```cypher
-- All identities that can escalate to cluster-admin
MATCH path=(id:Identity)-[:MEMBER_OF|ROLE_BIND|POD_EXEC|TOKEN_STEAL|IDENTITY_IMPERSONATE*1..6]->(ps:PermissionSet {name:"cluster-admin"})
RETURN path

-- Container escape paths
MATCH (c:Container)-[r:CE_PRIV_MOUNT|CE_NSENTER]->(n:K8sNode) RETURN c, r, n

-- Pods running with hostPID
MATCH (p:Pod {hostPID: true}) RETURN p.name, p.namespace

-- Full attack chain: Identity → Pod Exec → Token Steal → Cluster Admin
MATCH path=(id:Identity)-[:POD_EXEC]->(pod:Pod)-[:TOKEN_STEAL]->(sa:Identity)-[:ROLE_BIND]->(ps:PermissionSet)
WHERE ps.name = "cluster-admin"
RETURN path
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `KUBECONFIG` | `~/.kube/config` | Path to kubeconfig file |
| `NEO4J_URI` | `bolt://localhost:7687` | Neo4j connection URI |
| `NEO4J_USER` | `neo4j` | Neo4j username |
| `NEO4J_PASS` | `password` | Neo4j password |
| `NEO4J_DATABASE` | `neo4j` | Neo4j database name |
| `NEO4J_QUERY_USER` | _(unset)_ | Optional separate read-only principal for custom queries |
| `NEO4J_QUERY_PASS` | _(unset)_ | Password for the custom-query principal |
| `KUBE_DEMENTOR_LISTEN` | `127.0.0.1:8888` | Optional Neo4j REST API listen address |

## Web Console Operational Notes

- **Reports persist to disk.** Completed scans are saved under `~/.kube-dementor/reports/` (override with `KUBE_DEMENTOR_REPORTS_DIR`) and reloaded on server restart, including acceptances and uploaded exclusion files. Live cluster sessions do not survive a restart; shell/exploit actions on a restored report explain this instead of failing silently.
- **One scan at a time.** A second scan started while another is running is rejected with HTTP 409 and the running scan's id. Failed scans stay visible in the list with their error message.
- **Input validation.** Scan requests reject unknown modes (`discover|scan|exploit|chain`), levels (`safe|read-only|intrusive`), profiles (`external|internal`), invalid namespace names, and malformed exclusion YAML with a 400 and the exact reason. Bodies are size-limited (scan JSON and exclusion uploads 10 MB, accept requests 1 MB) and answered with 413.
- **Exclusions.** A non-empty exclusion file must contain at least one rule and every rule needs `ruleId` or `ruleIdPattern`; `severityMin` accepts `CRITICAL|HIGH|MEDIUM|LOW|INFO`. Invalid files fail the scan request instead of being ignored. Chain mode validates but does not apply exclusions.
- **CSV export** includes accepted findings and neutralizes spreadsheet-formula cells (`=`, `+`, `-`, `@` prefixes) against CSV injection.

## Validation

```bash
go test ./...
go test -race ./...
go vet ./...
node --check pkg/webui/assets/app.js
node --test pkg/webui/assets_test.js
node --test pkg/webui/scan_config_test.js
node --test pkg/webui/shell_graph_test.js
node --check web/static/app.js
node --test web/app.test.js
```

The regression suite uses local HTTP fixtures and synthetic inventory. It does not connect to a live cluster or execute a container escape. Coverage includes empty-namespace admin paths, restricted admission, unknown authorization, namespace scope, pagination, real resource edges, token inheritance, deferred Neo4j errors, and UI identity filters.
