// Copyright 2026 Riccardo Raccuia
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package route

import (
	"math/big"
	"net"
	"sync"
	"syscall"
)

// Table is a path-compressed binary prefix trie (PATRICIA) used as a route
// table. Nodes branch on a single bit position and prefixes are stored at the
// node whose branch position equals their prefix length, so a covering (shorter)
// prefix is always an ancestor of every more-specific prefix it contains. This
// guarantees correct longest-prefix-match lookups.
//
// It is safe for concurrent use.
type Table struct {
	root         *rtNode
	defaultRoute *Route
	ignore       map[string]bool
	family       int
	sync.RWMutex
}

// rtNode is a node in the prefix trie.
//
// A node represents the prefix formed by the first bitLen bits of prefix. If it
// carries one or more routes (value != nil) those routes have exactly that
// prefix length; otherwise it is a pure branch point introduced by path
// compression. Children are selected by the destination bit at index bitLen, so
// along any root-to-leaf path bitLen strictly increases.
type rtNode struct {
	children [2]*rtNode
	prefix   *big.Int // network key (host bits cleared beyond bitLen)
	value    []*Route // routes for exactly this prefix; nil for a pure branch
	bitLen   int      // prefix length of this node and the bit index its children branch on
}

// addRoute stores a route on a node that already represents the route's exact
// prefix. A route with the same interface replaces the existing one.
func (n *rtNode) addRoute(route *Route) {
	for i := range n.value {
		n.value[i] = route
	}
	n.value = append(n.value, route)
}

// NewTable creates a new routing table.
// Family must be one of FamilyInet or FamilyInet6.
// This determines the types of routes and addresses handled by the table.
// A table can only handle one family at a time.
func NewTable(family int) *Table {
	if family != syscall.AF_INET && family != syscall.AF_INET6 {
		return nil
	}
	return &Table{
		family: family,
		ignore: make(map[string]bool),
	}
}

// ExcludeAdapter excludes a given adapter from lookup results.
func (t *Table) ExcludeAdapter(adapterName ...string) {
	t.Lock()
	for _, adapter := range adapterName {
		t.ignore[adapter] = true
	}
	t.Unlock()
}

func (t *Table) DefaultRoute() *Route {
	return t.defaultRoute
}

// Lookup returns the best, most specific route in the table for a given destination IP address.
func (t *Table) Lookup(dst net.IP) *Route {
	t.RLock()
	route := t.lookup(dst)
	t.RUnlock()
	return route
}

// Walk walks the routing table and calls the given function for each route.
func (t *Table) Walk(fn func(route *Route)) {
	t.RLock()
	defer t.RUnlock()
	if t.defaultRoute != nil {
		fn(t.defaultRoute)
	}
	t.walk(t.root, fn)
}

func (t *Table) Insert(route *Route) {
	t.Lock()
	t.insert(route)
	t.Unlock()
}

func (t *Table) Remove(route *Route) bool {
	t.Lock()
	deleted := t.remove(route)
	t.Unlock()
	return deleted
}

func (t *Table) walk(node *rtNode, fn func(route *Route)) {
	if node == nil {
		return
	}
	for _, r := range node.value {
		fn(r)
	}
	t.walk(node.children[0], fn)
	t.walk(node.children[1], fn)
}

// destinationKey converts a destination IP to a big.Int key for the table's
// family, returning false if the address does not belong to that family.
func (t *Table) destinationKey(dst net.IP) (*big.Int, bool) {
	switch t.family {
	case syscall.AF_INET:
		ip4 := dst.To4()
		if ip4 == nil {
			return nil, false
		}
		return new(big.Int).SetBytes(ip4), true
	default:
		// To4 returns non-nil for IPv4-mapped addresses, so reject them here.
		if dst.To4() != nil {
			return nil, false
		}
		ip6 := dst.To16()
		if ip6 == nil {
			return nil, false
		}
		return new(big.Int).SetBytes(ip6), true
	}
}

func (t *Table) lookup(dst net.IP) *Route {
	dstKey, ok := t.destinationKey(dst)
	if !ok {
		return nil
	}

	var best *Route
	bestLen := -1
	if t.defaultRoute != nil {
		best = t.defaultRoute
		bestLen = 0
	}

	width := t.bitWidth()
	for cur := t.root; cur != nil; {
		// Stop descending once the destination leaves cur's prefix range.
		if t.commonBits(dstKey, cur.prefix) < cur.bitLen {
			break
		}
		// cur's prefix matches dst's first bitLen bits, so any route stored
		// here contains dst. Routes here all share cur.bitLen as their length.
		for _, r := range cur.value {
			if t.ignore[r.Interface] {
				continue
			}
			if cur.bitLen > bestLen {
				best = r
				bestLen = cur.bitLen
			}
		}
		if cur.bitLen >= width {
			break
		}
		cur = cur.children[t.getBit(dstKey, cur.bitLen)]
	}
	return best
}

func (t *Table) insert(value *Route) bool {
	if t.family != value.Family() {
		return false
	}
	prefixLen := int(routeToPrefixBits(value))
	if prefixLen == 0 {
		t.defaultRoute = value
		return true
	}

	key := routeToTablePrefix(value)
	if t.root == nil {
		t.root = &rtNode{prefix: key, value: []*Route{value}, bitLen: prefixLen}
		return true
	}

	var parent *rtNode
	cur := t.root
	for {
		shared := min(t.commonBits(key, cur.prefix), cur.bitLen)

		switch {
		case shared >= prefixLen && prefixLen < cur.bitLen:
			// The new prefix is an ancestor of cur: insert it above cur.
			node := &rtNode{prefix: key, value: []*Route{value}, bitLen: prefixLen}
			node.children[t.getBit(cur.prefix, prefixLen)] = cur
			t.relink(parent, cur, node)
			return true
		case shared >= prefixLen:
			// Same prefix as cur (prefixLen == cur.bitLen).
			cur.addRoute(value)
			return true
		case shared == cur.bitLen:
			// cur is an ancestor of the new prefix: descend.
			next := cur.children[t.getBit(key, cur.bitLen)]
			if next == nil {
				cur.children[t.getBit(key, cur.bitLen)] = &rtNode{
					prefix: key,
					value:  []*Route{value},
					bitLen: prefixLen,
				}
				return true
			}
			parent = cur
			cur = next
		default:
			// The keys diverge before either prefix ends: introduce a branch
			// node at the first differing bit with cur and the new prefix as
			// its two children.
			branch := &rtNode{prefix: t.maskPrefix(key, shared), bitLen: shared}
			curBit := t.getBit(cur.prefix, shared)
			branch.children[curBit] = cur
			branch.children[curBit^1] = &rtNode{
				prefix: key,
				value:  []*Route{value},
				bitLen: prefixLen,
			}
			t.relink(parent, cur, branch)
			return true
		}
	}
}

func (t *Table) remove(value *Route) bool {
	if t.family != value.Family() {
		return false
	}
	prefixLen := int(routeToPrefixBits(value))
	if prefixLen == 0 {
		existed := t.defaultRoute != nil
		t.defaultRoute = nil
		return existed
	}
	if t.root == nil {
		return false
	}

	key := routeToTablePrefix(value)

	var path []*rtNode
	cur := t.root
	for cur != nil {
		if t.commonBits(key, cur.prefix) < cur.bitLen {
			return false
		}
		if cur.bitLen == prefixLen {
			break
		}
		if cur.bitLen > prefixLen {
			return false
		}
		path = append(path, cur)
		cur = cur.children[t.getBit(key, cur.bitLen)]
	}
	if cur == nil || len(cur.value) == 0 {
		// No node holds this exact prefix.
		return false
	}

	cur.value = nil
	t.compress(path, cur)
	return true
}

// compress removes the now value-less node and collapses any ancestor that has
// become a pure branch with a single child, restoring path compression.
func (t *Table) compress(path []*rtNode, node *rtNode) {
	for {
		left, right := node.children[0], node.children[1]
		if len(node.value) > 0 || (left != nil && right != nil) {
			// Still a real prefix or a genuine branch point: keep it.
			return
		}

		var parent *rtNode
		if len(path) > 0 {
			parent = path[len(path)-1]
			path = path[:len(path)-1]
		}

		repl := left
		if repl == nil {
			repl = right
		}
		t.relink(parent, node, repl)

		if parent == nil {
			return
		}
		node = parent
	}
}

// relink replaces old with newNode in parent's children, or updates the root
// when parent is nil.
func (t *Table) relink(parent, old, newNode *rtNode) {
	if parent == nil {
		t.root = newNode
		return
	}
	if parent.children[0] == old {
		parent.children[0] = newNode
		return
	}
	parent.children[1] = newNode
}
