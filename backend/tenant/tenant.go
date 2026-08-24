// Package tenant is the v1 multi-tenant auth boundary: it resolves an API
// bearer token to a Tenant identity. This is deliberately the smallest thing
// that makes real data isolation possible — one API key per tenant, no
// self-serve signup, no multi-user-per-tenant RBAC, no SSO. Those are
// legitimate, separate, lower-risk features for later (see
// docs/adr/0005-multi-tenancy.md); getting isolation wrong is the dangerous
// mistake to make early, so that's what this package exists to prevent.
package tenant

// Tenant is one customer/organization boundary. Every Event, Detection, and
// Investigation in the system carries a Tenant.ID, and every store query an
// analyst can reach is scoped by it.
type Tenant struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Token string `json:"token"`
}

// Store resolves bearer tokens to tenants. It is a simple in-memory lookup —
// tenants are configured at process start (env var or file), not created via
// a signup flow. Swapping in a real tenant database later is an
// implementation change behind this same interface, not an API change.
type Store struct {
	byToken map[string]Tenant
}

// NewStore builds a Store from a fixed list of tenants. A tenant with an empty
// Token is treated as "open" — any request authenticates as it — which
// preserves the single-tenant dev/demo behavior of the original
// SENTINELX_TOKEN="" convenience mode. Only sensible with exactly one tenant.
func NewStore(tenants []Tenant) *Store {
	m := make(map[string]Tenant, len(tenants))
	for _, t := range tenants {
		m[t.Token] = t
	}
	return &Store{byToken: m}
}

// Resolve returns the tenant owning token, or false if the token is unknown.
func (s *Store) Resolve(token string) (Tenant, bool) {
	if t, ok := s.byToken[token]; ok {
		return t, true
	}
	if def, ok := s.byToken[""]; ok { // an open/dev tenant accepts any token
		return def, true
	}
	return Tenant{}, false
}

// List returns every configured tenant (used for startup logging/diagnostics).
func (s *Store) List() []Tenant {
	out := make([]Tenant, 0, len(s.byToken))
	for _, t := range s.byToken {
		out = append(out, t)
	}
	return out
}
