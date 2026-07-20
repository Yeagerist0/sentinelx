// Package api exposes the backend over HTTP/JSON. In production this sits
// behind mTLS for agents (POST /v1/ingest) and OIDC/SSO for analysts (GET
// endpoints); here a per-tenant bearer token gates both, resolved via
// tenant.Store. This is real multi-tenant data isolation (one API key per
// customer org, every response scoped to the caller's tenant) but not the
// full SaaS story — no self-serve signup, no multi-user-per-tenant RBAC, no
// SSO. Those are separate, lower-risk features for later; see
// docs/adr/0005-multi-tenancy.md. See deploy/ for the TLS/OIDC wiring.
package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"sentinelx/backend/narrate"
	"sentinelx/backend/normalize"
	"sentinelx/backend/pipeline"
	"sentinelx/backend/tenant"
)

// Server wraps the pipeline engine with HTTP handlers.
type Server struct {
	eng     *pipeline.Engine
	tenants *tenant.Store
	UIDir   string // if set, static UI is served from this directory at /
}

// New builds a Server. tenants resolves the bearer token on every request.
func New(eng *pipeline.Engine, tenants *tenant.Store) *Server {
	return &Server{eng: eng, tenants: tenants}
}

// Routes returns the HTTP handler.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/ingest", s.authed(s.handleIngest))
	mux.HandleFunc("GET /v1/investigations", s.authed(s.handleList))
	mux.HandleFunc("GET /v1/investigations/{id}", s.authed(s.handleGet))
	mux.HandleFunc("GET /v1/investigations/{id}/narrative", s.authed(s.handleNarrative))
	mux.HandleFunc("POST /v1/investigations/{id}/status", s.authed(s.handleSetStatus))
	mux.HandleFunc("GET /v1/audit/verify", s.authed(s.handleVerify))
	mux.HandleFunc("GET /v1/stats", s.authed(s.handleStats))
	mux.HandleFunc("POST /v1/login", s.handleLogin)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	if s.UIDir != "" {
		// Specific /v1 and /healthz patterns win over "/" in http.ServeMux, so the
		// file server only handles UI assets.
		mux.Handle("/", http.FileServer(http.Dir(s.UIDir)))
	}
	return mux
}

// tenantHandler is an http handler that also receives the caller's resolved
// tenant id, so every handler is forced to be tenant-aware rather than
// accidentally reaching for an unscoped store method.
type tenantHandler func(w http.ResponseWriter, r *http.Request, tenantID string)

func (s *Server) authed(h tenantHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		t, ok := s.tenants.Resolve(token)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h(w, r, t.ID)
	}
}

func bearerToken(r *http.Request) string {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request, tenantID string) {
	// Accept either a single AgentEvent or an array (batch).
	body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	var batch []normalize.AgentEvent
	if err := json.Unmarshal(body, &batch); err != nil {
		var one normalize.AgentEvent
		if err2 := json.Unmarshal(body, &one); err2 != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		batch = []normalize.AgentEvent{one}
	}
	touched := map[int64]bool{}
	var dropped int
	for _, a := range batch {
		ids, err := s.eng.Ingest(tenantID, a)
		if err != nil {
			dropped++
			continue
		}
		for _, id := range ids {
			touched[id] = true
		}
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"ingested":       len(batch) - dropped,
		"dropped":        dropped,
		"investigations": keys(touched),
	})
}

func (s *Server) handleList(w http.ResponseWriter, _ *http.Request, tenantID string) {
	invs := s.eng.Invs.ListByTenant(tenantID)
	out := make([]invSummary, 0, len(invs))
	for _, inv := range invs {
		out = append(out, summarize(inv))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request, tenantID string) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	inv, ok := s.eng.Invs.GetForTenant(tenantID, id)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	dets := s.eng.Detections(tenantID, inv.Detections)
	writeJSON(w, http.StatusOK, detail(inv, s.eng.Events, dets))
}

// handleLogin validates the analyst token and echoes back the tenant name so
// the UI can distinguish "wrong token" from a network error and display which
// org the analyst is signed into. There is no session or cookie: the UI
// stores the token client-side and sends it as a bearer on every subsequent
// request, same as the agent does.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&body); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	t, ok := s.tenants.Resolve(body.Token)
	if !ok {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "tenant": t.Name})
}

// handleSetStatus applies an analyst action — resolve, dismiss as
// false-positive, or reopen — to an investigation. This is the one
// write action an analyst has on an investigation; everything else in the
// API is read-only evidence.
func (s *Server) handleSetStatus(w http.ResponseWriter, r *http.Request, tenantID string) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&body); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if err := s.eng.SetStatus(tenantID, id, body.Status); err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, pipeline.ErrInvestigationNotFound) {
			code = http.StatusNotFound
		}
		http.Error(w, err.Error(), code)
		return
	}
	inv, _ := s.eng.Invs.GetForTenant(tenantID, id)
	writeJSON(w, http.StatusOK, summarize(inv))
}

func (s *Server) handleNarrative(w http.ResponseWriter, r *http.Request, tenantID string) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	inv, ok := s.eng.Invs.GetForTenant(tenantID, id)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	view := narrate.ViewFrom(inv, s.eng.Events)
	n := narrate.New(nil).Render(view)
	writeJSON(w, http.StatusOK, map[string]any{
		"text":      n.Text(),
		"sentences": n.Sentences,
		"rejected":  n.Rejected,
	})
}

func (s *Server) handleVerify(w http.ResponseWriter, _ *http.Request, tenantID string) {
	al := s.eng.AuditLog(tenantID)
	ok, seq := al.Verify()
	writeJSON(w, http.StatusOK, map[string]any{"intact": ok, "first_bad_seq": seq, "entries": al.Len()})
}

func (s *Server) handleStats(w http.ResponseWriter, _ *http.Request, tenantID string) {
	writeJSON(w, http.StatusOK, s.eng.Stats(tenantID))
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func keys(m map[int64]bool) []int64 {
	out := make([]int64, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
