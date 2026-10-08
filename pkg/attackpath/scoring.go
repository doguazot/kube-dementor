package attackpath

import (
	"fmt"
	"strings"
)

var edgeMitre = map[EdgeKind]string{
	EdgeBoundTo:             "T1078.001",
	EdgeGrantsRead:          "T1613",
	EdgeGrantsWrite:         "T1610",
	EdgeGrantsExec:          "T1609",
	EdgeCanInjectEphemeral:  "T1610",
	EdgeCanInteract:         "T1609",
	EdgeMountedBy:           "T1552.001",
	EdgeUsedBy:              "T1078.004",
	EdgeContainsToken:       "T1552.005",
	EdgeReadsMountedSecret:  "T1552.001",
	EdgeCanEscape:           "T1611",
	EdgeImpersonate:         "T1078",
	EdgeCanImpersonateIdent: "T1078",
	EdgeCanTokenRequest:     "T1528",
	EdgeCanDo:               "T1610",
}

var edgeStealth = map[EdgeKind]int{
	EdgeBoundTo:             1,
	EdgeGrantsRead:          1,
	EdgeGrantsWrite:         3,
	EdgeGrantsExec:          6,
	EdgeCanInjectEphemeral:  6,
	EdgeCanInteract:         6,
	EdgeMountedBy:           2,
	EdgeUsedBy:              0,
	EdgeContainsToken:       2,
	EdgeReadsMountedSecret:  2,
	EdgeCanEscape:           9,
	EdgeImpersonate:         4,
	EdgeCanImpersonateIdent: 4,
	EdgeCanTokenRequest:     2,
	EdgeCanDo:               3,
}

var edgeReliability = map[EdgeKind]int{
	EdgeBoundTo:             10,
	EdgeGrantsRead:          10,
	EdgeGrantsWrite:         9,
	EdgeGrantsExec:          9,
	EdgeCanInjectEphemeral:  5,
	EdgeCanInteract:         7,
	EdgeMountedBy:           8,
	EdgeUsedBy:              10,
	EdgeContainsToken:       6,
	EdgeReadsMountedSecret:  8,
	EdgeCanEscape:           8,
	EdgeImpersonate:         9,
	EdgeCanImpersonateIdent: 9,
	EdgeCanTokenRequest:     8,
	EdgeCanDo:               6,
}

type Score struct {
	Length     int
	Stealth    int
	Reliable   int
	MITREChain string
}

func ScorePath(p Path, edrAggressive bool) Score {
	s := Score{Length: len(p.Nodes) - 1}
	if len(p.Edges) == 0 {
		return s
	}
	var noise, relSum int
	var mitre []string
	relCount := 0
	for _, e := range p.Edges {
		w := edgeStealth[e.Kind]
		if edrAggressive {
			w++
		}
		if w > s.Stealth {
			s.Stealth = w
		}
		noise += w

		if r, ok := edgeReliability[e.Kind]; ok {
			relSum += r
			relCount++
		}
		if m, ok := edgeMitre[e.Kind]; ok {
			mitre = append(mitre, m)
		}
	}
	if relCount > 0 {
		s.Reliable = relSum / relCount
	}
	s.MITREChain = strings.Join(mitre, ",")
	_ = noise
	return s
}

func ScoreTags(s Score) []string {
	tags := []string{
		fmt.Sprintf("stealth:%d", s.Stealth),
		fmt.Sprintf("reliability:%d", s.Reliable),
	}
	if s.MITREChain != "" {
		for _, m := range strings.Split(s.MITREChain, ",") {
			tags = append(tags, "mitre:"+m)
		}
	}
	return tags
}
