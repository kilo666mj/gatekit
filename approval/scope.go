// Package approval validates client-address restrictions on fingerprint approvals.
package approval

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
)

const Capability = "approval_ranges_v1"
const MaxRanges = 128

// Scope is an immutable set of client CIDRs. A nil *Scope means unrestricted.
// Its zero value is invalid, preventing an explicit empty scope from broadening trust.
type Scope struct{ prefixes []netip.Prefix }

func New(ranges []string) (*Scope, error) {
	if len(ranges) == 0 || len(ranges) > MaxRanges {
		return nil, fmt.Errorf("approval_ranges requires 1..%d CIDRs", MaxRanges)
	}
	seen := make(map[netip.Prefix]bool)
	for _, raw := range ranges {
		p, err := netip.ParsePrefix(raw)
		if err != nil || p.Addr().Is4In6() {
			return nil, fmt.Errorf("invalid approval CIDR %q", raw)
		}
		seen[p.Masked()] = true
	}
	s := &Scope{}
	for p := range seen {
		s.prefixes = append(s.prefixes, p)
	}
	sort.Slice(s.prefixes, func(i, j int) bool { return s.prefixes[i].String() < s.prefixes[j].String() })
	return s, nil
}

func (s *Scope) Validate() error {
	if s != nil && (len(s.prefixes) == 0 || len(s.prefixes) > MaxRanges) {
		return fmt.Errorf("invalid empty or oversized approval scope")
	}
	return nil
}

func (s *Scope) Ranges() []string {
	if s == nil {
		return nil
	}
	out := make([]string, len(s.prefixes))
	for i, p := range s.prefixes {
		out[i] = p.String()
	}
	return out
}

// Allows uses the transport peer's address, not a hostname or untrusted header.
func (s *Scope) Allows(addr netip.Addr) bool {
	if s == nil {
		return true
	}
	if !addr.IsValid() || addr.Zone() != "" {
		return false
	}
	addr = addr.Unmap()
	for _, p := range s.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func (s *Scope) MarshalJSON() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(s.Ranges())
}
func (s *Scope) UnmarshalJSON(data []byte) error {
	var ranges []string
	if err := json.Unmarshal(data, &ranges); err != nil {
		return err
	}
	parsed, err := New(ranges)
	if err != nil {
		return err
	}
	*s = *parsed
	return nil
}
