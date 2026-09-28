package approval

import (
	"encoding/json"
	"net/netip"
	"testing"
)

func TestScopeValidationAndMatching(t *testing.T) {
	for _, raw := range []string{`[]`, `["bad"]`, `["::ffff:192.0.2.0/120"]`, `["fe80::1%eth0/64"]`, `[123]`} {
		var s *Scope
		if err := json.Unmarshal([]byte(raw), &s); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	s, err := New([]string{"192.0.2.9/24", "2001:db8:1::1/64", "192.0.2.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Ranges()) != 2 {
		t.Fatal(s.Ranges())
	}
	for ip, want := range map[string]bool{"192.0.2.25": true, "::ffff:192.0.2.25": true, "192.0.3.25": false, "2001:db8:1::5": true, "2001:db8:2::5": false, "fe80::1%eth0": false} {
		if got := s.Allows(netip.MustParseAddr(ip)); got != want {
			t.Errorf("%s: %t", ip, got)
		}
	}
	if s.Allows(netip.Addr{}) {
		t.Fatal("invalid address allowed")
	}
	var unrestricted *Scope
	if !unrestricted.Allows(netip.MustParseAddr("198.51.100.1")) {
		t.Fatal("legacy scope changed")
	}
	if _, err := json.Marshal(&Scope{}); err == nil {
		t.Fatal("empty scope marshaled")
	}
}
