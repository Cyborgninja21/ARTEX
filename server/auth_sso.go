package server

// Single sign-on from a trusted reverse proxy (Utumno fork patch).
//
// ARTEX ships only a single-admin password login. In the Utumno homelab it sits
// behind Authentik forward-auth (Traefik chain-authentik): the proxy authenticates
// the user and forwards their identity in X-Authentik-* headers. This endpoint
// turns that already-authenticated identity into an ARTEX session so the operator
// signs in once at Authentik and never sees ARTEX's own password form.
//
// Trust model: the Authentik identity header is believed ONLY when the DIRECT TCP
// peer is one of ARTEX_TRUSTED_PROXIES. It fails closed — with no trusted proxy
// configured, or a request from any other peer, SSO returns 403 and the password
// path is unaffected. A client that could reach the port directly cannot forge the
// header, because its peer address is not trusted. The minted token is identical to
// the one /api/auth/login issues (subject "ARTEX"), so every existing invariant and
// the single-admin model are preserved.

import (
	"net/http"
	"net/netip"
	"strings"
)

// ssoIdentityHeaders are the Authentik forward-auth headers, in precedence order,
// that carry the authenticated user the trusted proxy asserts. Canonical (Go
// http.Header) casing.
var ssoIdentityHeaders = []string{"X-Authentik-Username", "X-Authentik-Email"}

// ssoIdentity returns the authenticated username the trusted proxy asserted, or ""
// when no identity header is present.
func ssoIdentity(r *http.Request) string {
	for _, h := range ssoIdentityHeaders {
		if v := strings.TrimSpace(r.Header.Get(h)); v != "" {
			return v
		}
	}
	return ""
}

// peerTrusted reports whether the request's DIRECT TCP peer is a configured
// trusted proxy. Unlike clientIP it never consults X-Forwarded-For: the forgeable
// header is exactly what SSO must not trust from an untrusted peer.
func (s *Server) peerTrusted(r *http.Request) bool {
	if len(s.trustedProxies) == 0 {
		return false
	}
	addr, err := netip.ParseAddr(peerIP(r))
	if err != nil {
		return false
	}
	return isTrusted(addr, s.trustedProxies)
}

// GET /api/auth/sso — mint an ARTEX session from a trusted reverse proxy that has
// already authenticated the user (Authentik forward-auth). Exempt from requireAuth
// because it is under /api/auth/*. Fails closed: 403 unless the direct peer is a
// trusted proxy, 401 when the peer is trusted but no identity header is present.
func (s *Server) authSSO(w http.ResponseWriter, r *http.Request) {
	if !s.peerTrusted(r) {
		// 403, not 401: the frontend treats 401 as an expired session. This is "SSO
		// is not available here", not "your session expired".
		writeErr(w, 403, "SSO is only available through the trusted reverse proxy")
		return
	}
	if ssoIdentity(r) == "" {
		writeErr(w, 403, "No authenticated identity was forwarded by the reverse proxy")
		return
	}
	tok, err := signJWT(s.jwtKey)
	if err != nil {
		writeErr(w, 500, "token generation failed")
		return
	}
	writeJSON(w, 200, map[string]any{"token": tok})
}
