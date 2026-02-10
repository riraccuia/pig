package ice

import (
	"fmt"

	"github.com/riraccuia/pig/pkg/ice/message"
)

func dedupCandidates(candidates []message.ICECandidate) []message.ICECandidate {
	seen := make(map[string]struct{}, len(candidates))
	out := make([]message.ICECandidate, 0, len(candidates))
	for _, c := range candidates {
		key := candidateKey(c)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, c)
	}
	return out
}

func dedupConnectPaths(paths []*ConnectPath) []*ConnectPath {
	seen := make(map[string]struct{}, len(paths))
	out := make([]*ConnectPath, 0, len(paths))
	for _, p := range paths {
		if p == nil || p.LocalAddr == nil || p.RemoteAddr == nil {
			continue
		}
		key := fmt.Sprintf("%s|%s|%s", p.Protocol.Network, p.LocalAddr.String(), p.RemoteAddr.String())
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, p)
	}
	return out
}

func candidateKey(c message.ICECandidate) string {
	return fmt.Sprintf("%s|%d|%s|%d|%s", c.Protocol, c.ComponentID, c.Address, c.Port, c.Type)
}
