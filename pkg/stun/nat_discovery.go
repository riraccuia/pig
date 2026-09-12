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

// NAT behavior discovery implements RFC 5780 mapping (Section 4.3) and
// filtering (Section 4.4) tests using RFC 4787 terminology.
//
// The caller must use an RFC 5780-capable STUN server that honors
// CHANGE-REQUEST and returns OTHER-ADDRESS in binding responses.
package stun

import (
	"errors"
	"fmt"
	"net"
	"time"
)

var ErrOtherAddressMissing = errors.New("RFC 5780 OTHER-ADDRESS missing in STUN response")

// NATMappingBehavior describes how a NAT assigns external mappings.
// See RFC 4787 and RFC 5780 Sections 3.1, 4.3.
type NATMappingBehavior int

const (
	// MappingUnknown means mapping behavior was not determined.
	MappingUnknown NATMappingBehavior = iota
	// MappingEndpointIndependent means the same external mapping is reused for
	// all destinations (RFC 5780 mapping test II XOR-MAPPED matches test I).
	// Example req: local 192.168.1.2:4136 → 65.12.66.11:3478 (Ca:Dp, mapping test II).
	// Example res: mapped 67.105.12.10:49152, same as mapping test I.
	MappingEndpointIndependent
	// MappingAddressDependent means the mapping changes when the destination IP
	// changes but not when only the port on the same IP changes (mapping test III
	// XOR-MAPPED matches mapping test II).
	// Example req: local 192.168.1.2:4136 → 65.12.66.11:3478 then → 65.12.66.11:3479.
	// Example res: mapped 67.105.12.10:49154 for both mapping tests II and III.
	MappingAddressDependent
	// MappingAddressAndPortDependent means a new mapping is created for every
	// distinct destination IP:port (mapping test III XOR-MAPPED differs from II).
	// Example req: local 192.168.1.2:4136 → 65.12.66.11:3478 then → 65.12.66.11:3479.
	// Example res: mapped 67.105.12.10:49154 then 67.105.12.10:49155.
	MappingAddressAndPortDependent
)

func (m NATMappingBehavior) String() string {
	switch m {
	case MappingEndpointIndependent:
		return "endpoint-independent-mapping"
	case MappingAddressDependent:
		return "address-dependent-mapping"
	case MappingAddressAndPortDependent:
		return "address-and-port-dependent-mapping"
	default:
		return "unknown"
	}
}

// NATFilteringBehavior describes inbound UDP filter behavior.
// See RFC 4787 and RFC 5780 Sections 3.2, 4.4.
type NATFilteringBehavior int

const (
	// FilteringUnknown means filtering behavior was not determined.
	FilteringUnknown NATFilteringBehavior = iota
	// FilteringEndpointIndependent means inbound UDP is accepted from any remote
	// host once a mapping exists (filtering test II succeeds).
	// Example req: local 192.168.1.2:4136 → 65.12.66.10:3478 + CHANGE-REQUEST(change-IP+change-port, A|B).
	// Example res: binding response received from 65.12.66.11:3479 (Ca:Cp).
	FilteringEndpointIndependent
	// FilteringAddressDependent means inbound UDP is only accepted from IP
	// addresses previously sent to; filtering test II times out and test III
	// (change-port only) succeeds.
	// Example req: local 192.168.1.2:4136 → 65.12.66.10:3478 + CHANGE-REQUEST(change-port, B).
	// Example res: binding response received from 65.12.66.10:3479.
	FilteringAddressDependent
	// FilteringAddressAndPortDependent means inbound UDP is only accepted from
	// the exact remote IP:port previously sent to; both filtering tests II and III
	// time out.
	// Example req: local 192.168.1.2:4136 → 65.12.66.10:3478 + CHANGE-REQUEST(change-IP+change-port, A|B), then change-port only.
	// Example res: (timeout on both filtering tests).
	FilteringAddressAndPortDependent
)

func (f NATFilteringBehavior) String() string {
	switch f {
	case FilteringEndpointIndependent:
		return "endpoint-independent-filtering"
	case FilteringAddressDependent:
		return "address-dependent-filtering"
	case FilteringAddressAndPortDependent:
		return "address-and-port-dependent-filtering"
	default:
		return "unknown"
	}
}

// NATConnectivity describes UDP reachability and whether the host is behind a NAT.
type NATConnectivity int

const (
	ConnectivityUnknown NATConnectivity = iota
	// ConnectivityUDPBlocked means connectivity test I received no STUN response.
	// Example req: local 192.168.1.2:4136 → STUN 65.12.66.10:3478.
	// Example res: (timeout, no mapped address returned).
	ConnectivityUDPBlocked
	// ConnectivityOpenInternet means the host is not behind a NAT and filtering test II succeeded.
	// Example req: local 203.0.113.1:4000 → STUN 203.0.113.1:3478 + CHANGE-REQUEST(change-IP+change-port, A|B).
	// Example res: mapped 203.0.113.1:4000; response from alternate address received.
	ConnectivityOpenInternet
	// ConnectivitySymmetricUDPFirewall means the host is not behind a NAT but
	// filtering test II timed out.
	// Example req: local 203.0.113.1:4000 → STUN 203.0.113.1:3478 + CHANGE-REQUEST(change-IP+change-port, A|B).
	// Example res: mapped 203.0.113.1:4000; (timeout waiting for alternate source).
	ConnectivitySymmetricUDPFirewall
	// ConnectivityBehindNAT means the mapped address differs from the local socket.
	ConnectivityBehindNAT
)

func (c NATConnectivity) String() string {
	switch c {
	case ConnectivityUDPBlocked:
		return "udp-blocked"
	case ConnectivityOpenInternet:
		return "open-internet"
	case ConnectivitySymmetricUDPFirewall:
		return "symmetric-udp-firewall"
	case ConnectivityBehindNAT:
		return "behind-nat"
	default:
		return "unknown"
	}
}

// NATDiscoveryScope selects the scope of the discovery process.
type NATDiscoveryScope int

const (
	// DiscoveryFull runs filtering (Section 4.4) and mapping (Section 4.3) tests.
	DiscoveryFull NATDiscoveryScope = iota
	// DiscoveryMappingOnly runs mapping tests only and stops after mapping test II
	// when endpoint-independent mapping is detected (Section 4.5).
	DiscoveryMappingOnly
)

// NATDiscoveryOptions configures NAT behavior discovery.
type NATDiscoveryOptions struct {
	// Timeout for each individual STUN test. Zero uses the package default (1s).
	Timeout time.Duration
	// LocalAddr is the local UDP bind address. Nil lets the OS choose.
	LocalAddr *net.UDPAddr
	// Scope selects full or mapping-only discovery. Zero uses DiscoveryFull.
	Scope NATDiscoveryScope
}

// NATDiscoveryResult holds the outcome of a discovery run.
type NATDiscoveryResult struct {
	Connectivity       NATConnectivity
	Mapping            NATMappingBehavior
	Filtering          NATFilteringBehavior
	MappedAddress      net.IP
	MappedPort         int
	PrimaryServer      string
	AlternateServer    string
	MappingMappedPorts [3]int
}

func (r *NATDiscoveryResult) IsBehindNAT() bool {
	return r.Connectivity == ConnectivityBehindNAT
}

func (r *NATDiscoveryResult) String() string {
	// only include connectivity, mapping and filtering if they are not unknown
	var (
		connectivityStr = "unknown"
		mappingStr      = "unknown"
		filteringStr    = "unknown"
	)
	if r.Connectivity != ConnectivityUnknown {
		connectivityStr = r.Connectivity.String()
	}
	if r.Mapping != MappingUnknown {
		mappingStr = r.Mapping.String()
	}
	if r.Filtering != FilteringUnknown {
		filteringStr = r.Filtering.String()
	}
	return fmt.Sprintf("connectivity=%s, mapping=%s, filtering=%s", connectivityStr, mappingStr, filteringStr)
}

type bindingTestOutcome struct {
	received   bool
	mappedIP   net.IP
	mappedPort int
	msg        *Message
}

type natDiscoverer struct {
	stunServer  *net.UDPAddr
	timeout     time.Duration
	localAddr   *net.UDPAddr
	scope       NATDiscoveryScope
	bindingOpts *BindingOptions
}

// DiscoverNATBehavior runs binding tests described in RFC 5780 to classify
// the type of NAT in front of the local machine.
// stunServerAddr is the STUN server address specified as "host:port".
// Only UDP based STUN servers are supported at the moment.
// The options are optional and can be used to configure the discovery process.
func DiscoverNATBehavior(stunServerAddr string, opts *NATDiscoveryOptions) (*NATDiscoveryResult, error) {
	if stunServerAddr == "" {
		return nil, errors.New("STUN server address is required")
	}

	d, err := newNATDiscoverer(stunServerAddr, opts)
	if err != nil {
		return nil, err
	}
	return d.run()
}

func newNATDiscoverer(stunServerAddr string, opts *NATDiscoveryOptions) (*natDiscoverer, error) {
	stunServer, err := net.ResolveUDPAddr("udp", stunServerAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve primary STUN server %s: %w", stunServerAddr, err)
	}
	timeout := time.Second
	var localAddr *net.UDPAddr
	scope := DiscoveryFull
	if opts != nil {
		if opts.Timeout > 0 {
			timeout = opts.Timeout
		}
		localAddr = opts.LocalAddr
		scope = opts.Scope
	}
	return &natDiscoverer{
		stunServer:  stunServer,
		timeout:     timeout,
		localAddr:   localAddr,
		scope:       scope,
		bindingOpts: &BindingOptions{RequireFingerprint: false},
	}, nil
}

func (d *natDiscoverer) run() (*NATDiscoveryResult, error) {
	network := udpNetworkForAddr(d.stunServer)
	conn, err := net.ListenUDP(network, d.getListenAddr(d.stunServer))
	if err != nil {
		return nil, fmt.Errorf("listen UDP: %w", err)
	}
	defer conn.Close()

	result := &NATDiscoveryResult{
		PrimaryServer: d.stunServer.String(),
	}

	// Section 4.2, 4.3 test I, 4.4 test I — shared connectivity check.
	testI, err := d.runConnectivityTest(conn, d.stunServer)
	if err != nil {
		return nil, err
	}
	if !testI.received {
		result.Connectivity = ConnectivityUDPBlocked
		return result, nil
	}

	result.MappedAddress = testI.mappedIP
	result.MappedPort = testI.mappedPort
	result.MappingMappedPorts[0] = testI.mappedPort

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	if !isNatted(localAddr, testI.mappedIP, testI.mappedPort) {
		return d.getResultWhenNonNatted(conn, d.stunServer, result)
	}

	result.Connectivity = ConnectivityBehindNAT

	otherIP, otherPort, err := getOtherAddressFromMessage(testI.msg)
	if err != nil {
		return nil, fmt.Errorf("connectivity test I: %w", err)
	}

	alternateAddr := &net.UDPAddr{
		IP:   otherIP,
		Port: otherPort,
		Zone: d.stunServer.Zone,
	}
	result.AlternateServer = alternateAddr.String()

	alternatePrimaryPortAddr := &net.UDPAddr{
		IP:   otherIP,
		Port: d.stunServer.Port,
		Zone: d.stunServer.Zone,
	}

	if d.scope == DiscoveryFull {
		// Determine filtering behavior if full discovery is requested.
		// Precondition to these tests is that no binding be established to the
		// alternate address and port.
		// Because the NAT does not know that the alternate address and port belong to
		// the same server as the primary address and port, it treats these
		// responses the same as it would those from any other host on the
		// Internet. Therefore, the success of the binding responses sent from
		// the alternate address and port indicate whether the NAT is currently
		// performing Endpoint-Independent Filtering, Address-Dependent
		// Filtering, or Address and Port-Dependent Filtering. This test
		// applies only to UDP datagrams.
		var filterII, filterIII *bindingTestOutcome
		filterII, filterIII, err = d.runFilteringTests(conn, d.stunServer)
		if err != nil {
			return nil, err
		}
		result.Filtering = getNatFilteringBehavior(filterII, filterIII)
	}

	mappingII, mappingIII, err := d.runMappingTests(conn, testI, alternatePrimaryPortAddr, alternateAddr)
	if err != nil {
		return nil, err
	}
	result.MappingMappedPorts[1] = mappingII.mappedPort
	if mappingIII != nil && mappingIII.received {
		result.MappingMappedPorts[2] = mappingIII.mappedPort
	}
	result.Mapping = getNatMappingBehavior(testI, mappingII, mappingIII)

	return result, nil
}

func (d *natDiscoverer) getResultWhenNonNatted(conn *net.UDPConn, primaryAddr *net.UDPAddr, result *NATDiscoveryResult) (*NATDiscoveryResult, error) {
	result.Mapping = MappingEndpointIndependent

	filterII, err := d.sendBindingTest(conn, primaryAddr, changeIPFlag|changePortFlag)
	if err != nil {
		return nil, fmt.Errorf("filtering test II (no NAT): %w", err)
	}
	if filterII.received {
		result.Connectivity = ConnectivityOpenInternet
		result.Filtering = FilteringEndpointIndependent
		return result, nil
	}
	result.Connectivity = ConnectivitySymmetricUDPFirewall
	result.Filtering = FilteringAddressAndPortDependent
	return result, nil
}

// runConnectivityTest performs test I described in RFC 5780 Section 4.2.
func (d *natDiscoverer) runConnectivityTest(conn *net.UDPConn, primaryAddr *net.UDPAddr) (*bindingTestOutcome, error) {
	out, err := d.sendBindingTest(conn, primaryAddr, 0)
	if err != nil {
		return nil, fmt.Errorf("connectivity test I: %w", err)
	}
	return out, nil
}

// runMappingTests performs tests II and III described in RFC 5780 Section 4.3.
func (d *natDiscoverer) runMappingTests(conn *net.UDPConn, testI *bindingTestOutcome, alternatePrimaryPortAddr, alternateAddr *net.UDPAddr) (*bindingTestOutcome, *bindingTestOutcome, error) {
	testII, err := d.sendBindingTest(conn, alternatePrimaryPortAddr, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("mapping test II: %w", err)
	}
	if !testII.received {
		return nil, nil, errors.New("mapping test II: no STUN response")
	}

	if isMappedAddrEqual(testI, testII) {
		return testII, nil, nil
	}

	testIII, err := d.sendBindingTest(conn, alternateAddr, 0)
	if err != nil {
		return testII, nil, fmt.Errorf("mapping test III: %w", err)
	}
	if !testIII.received {
		return testII, nil, errors.New("mapping test III: no STUN response")
	}
	return testII, testIII, nil
}

// runFilteringTests performs tests II and III described in RFC 5780 Section 4.4.
// These tests must run before any binding request to the alternate address.
func (d *natDiscoverer) runFilteringTests(conn *net.UDPConn, primaryAddr *net.UDPAddr) (*bindingTestOutcome, *bindingTestOutcome, error) {
	testII, err := d.sendBindingTest(conn, primaryAddr, changeIPFlag|changePortFlag)
	if err != nil {
		return nil, nil, fmt.Errorf("filtering test II: %w", err)
	}
	if testII.received {
		return testII, nil, nil
	}

	testIII, err := d.sendBindingTest(conn, primaryAddr, changePortFlag)
	if err != nil {
		return testII, nil, fmt.Errorf("filtering test III: %w", err)
	}
	return testII, testIII, nil
}

func isMappedAddrEqual(a, b *bindingTestOutcome) bool {
	if a == nil || b == nil || !a.received || !b.received || a.mappedIP == nil || b.mappedIP == nil {
		return false
	}
	return a.mappedPort == b.mappedPort && a.mappedIP.Equal(b.mappedIP)
}

func getNatMappingBehavior(testI, testII, testIII *bindingTestOutcome) NATMappingBehavior {
	if testII == nil || !testII.received {
		return MappingUnknown
	}
	if isMappedAddrEqual(testI, testII) {
		return MappingEndpointIndependent
	}
	if testIII == nil || !testIII.received {
		return MappingUnknown
	}
	if isMappedAddrEqual(testII, testIII) {
		return MappingAddressDependent
	}
	return MappingAddressAndPortDependent
}

func getNatFilteringBehavior(testII, testIII *bindingTestOutcome) NATFilteringBehavior {
	if testII != nil && testII.received {
		return FilteringEndpointIndependent
	}
	if testIII != nil && testIII.received {
		return FilteringAddressDependent
	}
	return FilteringAddressAndPortDependent
}

func (d *natDiscoverer) sendBindingTest(conn *net.UDPConn, dest *net.UDPAddr, changeFlags uint32) (*bindingTestOutcome, error) {
	req, err := d.buildBindingRequest(changeFlags)
	if err != nil {
		return nil, err
	}

	if _, err := conn.WriteToUDP(req.Raw.Bytes(), dest); err != nil {
		return nil, fmt.Errorf("send binding request to %s: %w", dest, err)
	}

	buf := make([]byte, 1500)
	if err := conn.SetReadDeadline(time.Now().Add(d.timeout)); err != nil {
		return nil, err
	}
	n, _, err := conn.ReadFromUDP(buf)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return &bindingTestOutcome{received: false}, nil
		}
		return nil, fmt.Errorf("read STUN response: %w", err)
	}

	msg, err := DecodeMessage(buf[:n])
	if err != nil {
		return nil, fmt.Errorf("decode STUN response: %w", err)
	}

	bindingResult, err := ProcessBindingResponse(msg, req.Header.TransactionID, d.bindingOpts)
	if err != nil {
		return nil, err
	}

	return &bindingTestOutcome{
		received:   true,
		mappedIP:   bindingResult.IP,
		mappedPort: bindingResult.Port,
		msg:        msg,
	}, nil
}

func (d *natDiscoverer) buildBindingRequest(changeFlags uint32) (*Message, error) {
	req, err := BuildBindingRequest(d.bindingOpts)
	if err != nil {
		return nil, err
	}
	if changeFlags != 0 {
		if err := req.AppendAttribute(NewChangeRequestAttr(changeFlags)); err != nil {
			return nil, err
		}
	}
	return req, nil
}

func (d *natDiscoverer) getListenAddr(primary *net.UDPAddr) *net.UDPAddr {
	if d.localAddr != nil {
		return d.localAddr
	}
	ip := net.IPv4zero
	if primary.IP != nil && primary.IP.To4() == nil {
		ip = net.IPv6zero
	}
	return &net.UDPAddr{IP: ip, Port: 0}
}

func udpNetworkForAddr(addr *net.UDPAddr) string {
	if addr.IP != nil && addr.IP.To4() == nil {
		return "udp6"
	}
	return "udp4"
}

func isNatted(local *net.UDPAddr, mappedIP net.IP, mappedPort int) bool {
	if mappedIP == nil {
		return false
	}
	localIP := local.IP
	if localIP == nil || localIP.IsUnspecified() {
		return !isPrivateIP(mappedIP)
	}
	if isPrivateIP(localIP) && !isPrivateIP(mappedIP) {
		return true
	}
	if !mappedIP.Equal(localIP) {
		return true
	}
	return mappedPort != local.Port
}

func isPrivateIP(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

// getOtherAddressFromMessage extracts the OTHER-ADDRESS attribute from a STUN message.
// An error is returned if the attribute is not found.
func getOtherAddressFromMessage(msg *Message) (net.IP, int, error) {
	if msg == nil {
		return nil, 0, ErrOtherAddressMissing
	}
	attr, ok := msg.FindAttribute(AttrOtherAddress)
	if !ok {
		return nil, 0, ErrOtherAddressMissing
	}
	other, ok := attr.(*OtherAddressAttr)
	if !ok {
		return nil, 0, ErrOtherAddressMissing
	}
	return other.DecodeOtherAddress()
}
