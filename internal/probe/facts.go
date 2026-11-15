// Package probe is `stackward probe`: a look at one host from another
// machine. It resolves the target over IPv4 and IPv6, makes plain TCP
// connects to a short fixed list of ports, reads the first line an SSH
// server sends, asks the raw IP for / over HTTP and HTTPS, and optionally
// checks one hostname over HTTPS. The results are Facts, and the PRB checks
// judge them into the same report.v1 document that audit produces.
//
// probe never scans: one host, a fixed port list (plus at most a few extra
// ports), no ranges, no CIDR blocks, and it needs the user's confirmation
// that they own the host.
package probe

import (
	"sort"
	"time"

	"github.com/Shironex/stackward/internal/facts"
)

// SchemaVersion identifies the JSON shape of Facts.
const SchemaVersion = "stackward.probe.v1"

// Address families.
const (
	IPv4 = "ipv4"
	IPv6 = "ipv6"
)

// Port states.
const (
	Open        = "open"        // connected
	Closed      = "closed"      // refused: the host answered, nothing listens
	Filtered    = "filtered"    // no answer before the timeout
	Unreachable = "unreachable" // this machine has no route to the address
	Error       = "error"       // anything else
)

// Family states.
const (
	FamilyProbed      = "probed"
	FamilyNoAddress   = "no-address"
	FamilyUnreachable = "unreachable"
)

// PortList is every port probe tries, by role. The checks read the roles
// from Facts, so a saved facts file describes itself.
type PortList struct {
	SSH       []int `json:"ssh"`
	HTTP      []int `json:"http"`
	HTTPS     []int `json:"https"`
	Docker    []int `json:"docker"`
	Panels    []int `json:"panels"`
	Databases []int `json:"databases"`
	// Extra are the --ports. Open ones get a banner read; one that answers
	// with an SSH banner counts as SSH.
	Extra []int `json:"extra,omitempty"`
}

// DefaultPorts is the fixed list from the design brief.
func DefaultPorts() PortList {
	return PortList{
		SSH:       []int{22},
		HTTP:      []int{80},
		HTTPS:     []int{443},
		Docker:    []int{2375, 2376},
		Panels:    []int{3000, 3100, 6001, 6002, 8000, 8080, 8081, 9000, 9090},
		Databases: []int{3306, 5432, 6379, 9200, 27017},
	}
}

// All returns every port once, sorted.
func (l PortList) All() []int {
	seen := map[int]bool{}
	var out []int
	for _, set := range [][]int{l.SSH, l.HTTP, l.HTTPS, l.Docker, l.Panels, l.Databases, l.Extra} {
		for _, p := range set {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	sort.Ints(out)
	return out
}

// bannerPorts are the ports whose first line is read: SSH and extra.
func (l PortList) bannerPorts() map[int]bool {
	m := map[int]bool{}
	for _, p := range l.SSH {
		m[p] = true
	}
	for _, p := range l.Extra {
		m[p] = true
	}
	return m
}

// Facts is everything one probe run observed.
type Facts struct {
	Schema      string    `json:"schema"`
	CollectedAt time.Time `json:"collected_at"`
	// Target is the host as given (normalized).
	Target string `json:"target"`
	// Hostname is --hostname, if given.
	Hostname string `json:"hostname,omitempty"`
	// ResolveError is set when the target name did not resolve at all.
	ResolveError string    `json:"resolve_error,omitempty"`
	Addresses    []Address `json:"addresses"`
	// Truncated is true when the name resolved to more addresses per family
	// than probe tries.
	Truncated bool       `json:"truncated,omitempty"`
	Families  []Family   `json:"families"`
	PortList  PortList   `json:"port_list"`
	Ports     []Port     `json:"ports"`
	RawHTTP   []RawHTTP  `json:"raw_http"`
	HTTPS     *HTTPSFact `json:"https,omitempty"`
	// Steps records how each stage ended, reported as collectors.
	Steps []facts.CollectorStatus `json:"steps"`
}

// Address is one resolved address.
type Address struct {
	Address string `json:"address"`
	Family  string `json:"family"`
}

// Family is how one address family went.
type Family struct {
	Family string `json:"family"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// Port is one TCP connect.
type Port struct {
	Address string `json:"address"`
	Family  string `json:"family"`
	Port    int    `json:"port"`
	State   string `json:"state"`
	// Banner is the first line the service sent (SSH and extra ports).
	Banner string `json:"banner,omitempty"`
	Error  string `json:"error,omitempty"`
}

// RawHTTP is one GET / to the raw IP on a web port that was open.
type RawHTTP struct {
	Address string `json:"address"`
	Family  string `json:"family"`
	Port    int    `json:"port"`
	Scheme  string `json:"scheme"`
	// Status is the HTTP status code, 0 when no response came back.
	Status   int    `json:"status,omitempty"`
	Location string `json:"location,omitempty"`
	// TLSVerifySkipped is true for every HTTPS request here: an IP has no
	// certificate name to verify against.
	TLSVerifySkipped bool   `json:"tls_verify_skipped,omitempty"`
	Error            string `json:"error,omitempty"`
}

// HTTPSFact is the --hostname check.
type HTTPSFact struct {
	Hostname string `json:"hostname"`
	Hops     []Hop  `json:"hops"`
	// FinalStatus is the status of the last response, 0 when none.
	FinalStatus int `json:"final_status,omitempty"`
	// Loop is true when a redirect came back to a URL already visited.
	Loop bool `json:"loop,omitempty"`
	// TooManyRedirects is true when the redirect limit was hit.
	TooManyRedirects bool `json:"too_many_redirects,omitempty"`
	// Downgrade is true when a redirect went from https to http.
	Downgrade bool `json:"downgrade,omitempty"`
	// OffHost is the first redirect target on another host (not followed).
	OffHost string `json:"off_host,omitempty"`
	// TLSError is a certificate or handshake failure.
	TLSError string `json:"tls_error,omitempty"`
	// CertNotAfter is the expiry of the leaf certificate, when one was seen.
	CertNotAfter *time.Time `json:"cert_not_after,omitempty"`
	// Error is any other failure (DNS, connect, timeout).
	Error string `json:"error,omitempty"`
}

// Hop is one request of the redirect chain.
type Hop struct {
	URL      string `json:"url"`
	Status   int    `json:"status"`
	Location string `json:"location,omitempty"`
}
