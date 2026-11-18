package server

// Tests for the Utumno fork's trusted-proxy single sign-on (auth_sso.go).

import (
	"encoding/json"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func ssoServer(t *testing.T, trusted string) *Server {
	t.Helper()
	var p []netip.Prefix
	if trusted != "" {
		var err error
		p, err = ParseTrustedProxies(trusted)
		if err != nil {
			t.Fatalf("ParseTrustedProxies(%q): %v", trusted, err)
		}
	}
	return &Server{
		jwtKey:         []byte("test-signing-key-32-bytes-long!!"),
		trustedProxies: p,
	}
}

func TestAuthSSO_TrustedPeerWithIdentity_MintsToken(t *testing.T) {
	s := ssoServer(t, "172.20.0.0/16")
	r := httptest.NewRequest("GET", "/api/auth/sso", nil)
	r.RemoteAddr = "172.20.0.5:40000"
	r.Header.Set("X-Authentik-Username", "chase")
	w := httptest.NewRecorder()

	s.authSSO(w, r)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200 (body %s)", w.Code, w.Body.String())
	}
	var resp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Token == "" {
		t.Fatal("empty token")
	}
	if !verifyJWT(resp.Token, s.jwtKey) {
		t.Fatal("minted token does not verify against the server key")
	}
	if sub := jwtSubject(resp.Token, s.jwtKey); sub != "ARTEX" {
		t.Fatalf("subject = %q, want ARTEX (single-admin invariant)", sub)
	}
}

func TestAuthSSO_EmailFallback(t *testing.T) {
	s := ssoServer(t, "172.20.0.0/16")
	r := httptest.NewRequest("GET", "/api/auth/sso", nil)
	r.RemoteAddr = "172.20.0.5:40000"
	r.Header.Set("X-Authentik-Email", "chase@example.com")
	w := httptest.NewRecorder()

	s.authSSO(w, r)
	if w.Code != 200 {
		t.Fatalf("status = %d, want 200 (email identity should be accepted)", w.Code)
	}
}

func TestAuthSSO_UntrustedPeer_Forbidden(t *testing.T) {
	s := ssoServer(t, "172.20.0.0/16")
	r := httptest.NewRequest("GET", "/api/auth/sso", nil)
	r.RemoteAddr = "203.0.113.7:50000" // not in the trusted range
	r.Header.Set("X-Authentik-Username", "attacker")
	w := httptest.NewRecorder()

	s.authSSO(w, r)
	if w.Code != 403 {
		t.Fatalf("status = %d, want 403 (untrusted peer must not mint a token)", w.Code)
	}
}

func TestAuthSSO_NoTrustedProxiesConfigured_FailsClosed(t *testing.T) {
	s := ssoServer(t, "") // SSO disabled
	r := httptest.NewRequest("GET", "/api/auth/sso", nil)
	r.RemoteAddr = "127.0.0.1:40000"
	r.Header.Set("X-Authentik-Username", "chase")
	w := httptest.NewRecorder()

	s.authSSO(w, r)
	if w.Code != 403 {
		t.Fatalf("status = %d, want 403 (no trusted proxy = SSO off)", w.Code)
	}
}

func TestAuthSSO_TrustedPeerNoHeader_Forbidden(t *testing.T) {
	s := ssoServer(t, "172.20.0.0/16")
	r := httptest.NewRequest("GET", "/api/auth/sso", nil)
	r.RemoteAddr = "172.20.0.5:40000" // trusted, but no identity header
	w := httptest.NewRecorder()

	s.authSSO(w, r)
	if w.Code != 403 {
		t.Fatalf("status = %d, want 403 (trusted peer but no identity forwarded)", w.Code)
	}
}

// Guards the fail-closed contract directly.
func TestPeerTrusted(t *testing.T) {
	s := ssoServer(t, "10.0.0.0/8")
	cases := []struct {
		peer string
		want bool
	}{
		{"10.1.2.3:1234", true},
		{"10.255.255.255:1", true},
		{"192.168.1.1:1234", false},
		{"not-an-addr", false},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/api/auth/sso", nil)
		r.RemoteAddr = c.peer
		if got := s.peerTrusted(r); got != c.want {
			t.Errorf("peerTrusted(%q) = %v, want %v", c.peer, got, c.want)
		}
	}
	// Empty trusted list is always false.
	sEmpty := ssoServer(t, "")
	r := httptest.NewRequest("GET", "/api/auth/sso", nil)
	r.RemoteAddr = "10.1.2.3:1234"
	if sEmpty.peerTrusted(r) {
		t.Error("peerTrusted with no trusted proxies should be false")
	}
}
