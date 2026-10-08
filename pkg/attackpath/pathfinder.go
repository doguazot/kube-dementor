package attackpath

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kube-dementor/kube-dementor/pkg/scanner"
)

type Path struct {
	Nodes []*Node
	Edges []Edge
}

func (p Path) Score() int {

	score := len(p.Nodes) * 2
	for _, n := range p.Nodes {
		if n.HighValue {
			score -= 5
		}
	}
	return score
}

func FindFrom(g *Graph, startSubjects []string, maxHops int) []Path {
	if maxHops <= 0 {
		maxHops = 6
	}
	visited := map[string]Path{}
	for _, start := range startSubjects {
		if _, ok := g.Nodes[start]; !ok {
			continue
		}
		type frame struct {
			id   string
			path Path
		}
		q := []frame{{id: start, path: Path{Nodes: []*Node{g.Nodes[start]}}}}
		depth := map[string]int{start: 0}
		for len(q) > 0 {
			cur := q[0]
			q = q[1:]
			if len(cur.path.Nodes) > maxHops {
				continue
			}
			edges := append([]Edge(nil), g.Out[cur.id]...)
			sort.Slice(edges, func(i, j int) bool {
				return string(edges[i].Kind)+"|"+edges[i].To+"|"+edges[i].Note <
					string(edges[j].Kind)+"|"+edges[j].To+"|"+edges[j].Note
			})
			for _, e := range edges {

				if e.Kind == EdgeUsedBy || e.Kind == EdgeMountedBy {
					continue
				}
				next, ok := g.Nodes[e.To]
				if !ok {
					continue
				}

				onPath := false
				for _, n := range cur.path.Nodes {
					if n.ID == next.ID {
						onPath = true
						break
					}
				}
				if onPath {
					continue
				}
				nextDepth := len(cur.path.Edges) + 1
				if old, ok := depth[next.ID]; ok && old <= nextDepth {
					continue
				}
				depth[next.ID] = nextDepth
				np := Path{
					Nodes: append(append([]*Node{}, cur.path.Nodes...), next),
					Edges: append(append([]Edge{}, cur.path.Edges...), e),
				}
				q = append(q, frame{id: next.ID, path: np})
				if next.HighValue {

					key := start + "→" + next.ID
					if prev, ok := visited[key]; !ok || len(np.Nodes) < len(prev.Nodes) {
						visited[key] = np
					}
				}
			}
		}
	}

	out := make([]Path, 0, len(visited))
	for _, p := range visited {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score() != out[j].Score() {
			return out[i].Score() < out[j].Score()
		}
		return explain(out[i]) < explain(out[j])
	})
	return out
}

func ToFindings(paths []Path, edrAggressive bool) []scanner.Finding {
	out := make([]scanner.Finding, 0, len(paths))
	for i, p := range paths {
		if len(p.Nodes) < 2 {
			continue
		}
		start := p.Nodes[0]
		end := p.Nodes[len(p.Nodes)-1]
		sev := scanner.SevHigh
		if end.Kind == KindClusterAdmin {
			sev = scanner.SevCritical
		}

		score := ScorePath(p, edrAggressive)
		human := explain(p)
		tags := []string{"attack-path", "rbac", "lateral-movement"}
		tags = append(tags, ScoreTags(score)...)

		f := scanner.Finding{
			ID:       fmt.Sprintf("KH-PATH-%04d", i+1),
			RuleID:   "KH-PATH-001",
			Category: scanner.CatAttackPath,
			Severity: sev,
			Title:    fmt.Sprintf("Attack path: %s → %s (%d hops)", start.Name, end.Name, len(p.Nodes)-1),
			Description: fmt.Sprintf(`BloodHound-style walk from %s/%s reaches the high-value target %s/%s via %d edges. This is a potential attack path, not a demonstrated exploit. Check each edge's authorization scope, admission, token audience, placement and runtime preconditions before claiming endpoint compromise.

Score:
  length       : %d hops
  stealth      : %d/10 (higher = noisier for Falco/Tetragon)
  reliability  : %d/10
  MITRE chain  : %s`,
				start.Kind, start.Name, end.Kind, end.Name, len(p.Edges),
				score.Length, score.Stealth, score.Reliable, score.MITREChain),
			Resource: scanner.Resource{
				Kind:      string(end.Kind),
				Namespace: end.Namespace,
				Name:      end.Name,
			},
			Evidence:       human,
			Impact:         "Potential lateral movement or privilege escalation if the recorded edge prerequisites hold. No host execution or cluster compromise was performed by graph analysis.",
			Recommendation: "Break the chain at the weakest edge: remove the binding, scope the role, rotate the token, or apply PSA to block hostPath/privileged pods.",
			Tags:           tags,
			MitreATTACK:    pathMITRE(score.MITREChain),
			DetectedAt:     time.Now(),
			AttackPath:     pathSnapshot(p),
		}
		out = append(out, f)
	}
	return out
}

func Snapshot(g *Graph, paths []Path, me string) *scanner.GraphSnapshot {
	used := map[string]bool{}
	if me != "" {
		used[me] = true
	}
	edges := make([]scanner.GraphEdge, 0)
	for _, p := range paths {
		for _, n := range p.Nodes {
			used[n.ID] = true
		}
		for i, e := range p.Edges {

			if i+1 >= len(p.Nodes) {
				continue
			}
			from := p.Nodes[i].ID
			edges = append(edges, scanner.GraphEdge{
				From:   from,
				To:     e.To,
				Kind:   string(e.Kind),
				Note:   e.Note,
				Status: p.Nodes[i+1].Status,
			})
		}
	}

	seen := map[string]bool{}
	deduped := edges[:0]
	for _, e := range edges {
		key := e.From + "|" + e.To + "|" + e.Kind
		if seen[key] {
			continue
		}
		seen[key] = true
		deduped = append(deduped, e)
	}

	nodes := make([]scanner.GraphNode, 0, len(used))
	for id := range used {
		n, ok := g.Nodes[id]
		if !ok {

			nodes = append(nodes, scanner.GraphNode{
				ID:   id,
				Kind: "ServiceAccount",
				Name: id,
			})
			continue
		}
		nodes = append(nodes, scanner.GraphNode{
			ID:        n.ID,
			Kind:      string(n.Kind),
			Namespace: n.Namespace,
			Name:      n.Name,
			HighValue: n.HighValue,
			Status:    n.Status, Detail: n.Detail,
		})
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	sort.Slice(deduped, func(i, j int) bool {
		return deduped[i].From+"|"+deduped[i].To+"|"+deduped[i].Kind <
			deduped[j].From+"|"+deduped[j].To+"|"+deduped[j].Kind
	})
	return &scanner.GraphSnapshot{
		Me:    me,
		Nodes: nodes,
		Edges: deduped,
	}
}

func pathSnapshot(p Path) *scanner.GraphSnapshot {
	snapshot := &scanner.GraphSnapshot{
		Nodes: make([]scanner.GraphNode, 0, len(p.Nodes)),
		Edges: make([]scanner.GraphEdge, 0, len(p.Edges)),
	}
	for _, node := range p.Nodes {
		snapshot.Nodes = append(snapshot.Nodes, scanner.GraphNode{
			ID: node.ID, Kind: string(node.Kind), Namespace: node.Namespace,
			Name: node.Name, HighValue: node.HighValue,
			Status: node.Status, Detail: node.Detail,
		})
	}
	for i, edge := range p.Edges {
		snapshot.Edges = append(snapshot.Edges, scanner.GraphEdge{
			From: p.Nodes[i].ID, To: edge.To, Kind: string(edge.Kind), Note: edge.Note,
			Status: p.Nodes[i+1].Status,
		})
	}
	return snapshot
}

func pathMITRE(chain string) []string {
	seen := map[string]bool{}
	var techniques []string
	for _, technique := range strings.Split(chain, ",") {
		if technique != "" && !seen[technique] {
			seen[technique] = true
			techniques = append(techniques, technique)
		}
	}
	return techniques
}

func explain(p Path) string {
	var b strings.Builder
	for i, n := range p.Nodes {
		if i > 0 {
			e := p.Edges[i-1]
			fmt.Fprintf(&b, " ─[%s:%s]→ ", e.Kind, e.Note)
		}
		if n.Namespace != "" {
			fmt.Fprintf(&b, "%s/%s/%s", n.Kind, n.Namespace, n.Name)
		} else {
			fmt.Fprintf(&b, "%s/%s", n.Kind, n.Name)
		}
		if n.HighValue {
			b.WriteString(" 🎯")
		}
	}
	return b.String()
}
