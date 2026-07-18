// Package api exposes the backend over HTTP/JSON. In production this sits behind
// mTLS for agents (POST /v1/ingest) and OIDC/SSO for analysts (GET endpoints);
// here a single shared bearer token gates BOTH, since v1 is a single-tenant
// self-hosted deploy with one analyst credential, not a multi-user SaaS. The UI
// presents this as a login screen (POST /v1/login just validates the token —
// there is no user database). Real multi-analyst accounts / SSO is a post-v1
// item, see docs/adr. See deploy/ for the TLS/OIDC wiring.
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
)

// Server wraps the pipeline engine with HTTP handlers.
type Server struct {
	eng   *pipeline.Engine
	token string // bearer token required for ingest; empty disables the check (dev only)
	UIDir string // if set, static UI is served from this directory at /
}

// New builds a Server. token gates POST /v1/ingest.
func New(eng *pipeline.Engine, token string) *Server {
	return &Server{eng: eng, token: token}
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

func (s *Server) authed(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.token != "" {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if got != s.token {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		h(w, r)
	}
}

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
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
		ids, err := s.eng.Ingest(a)
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

func (s *Server) handleList(w http.ResponseWriter, _ *http.Request) {
	invs := s.eng.Invs.List()
	out := make([]invSummary, 0, len(invs))
	for _, inv := range invs {
		out = append(out, summarize(inv))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	inv, ok := s.eng.Invs.Get(id)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	dets := s.eng.Detections(inv.Detections)
	writeJSON(w, http.StatusOK, detail(inv, s.eng.Events, dets))
}

// handleLogin validates the analyst token and echoes it back so the UI can
// distinguish "wrong token" from a network error. There is no session or
// cookie: the UI stores the token client-side and sends it as a bearer on
// every subsequent request, same as the agent does.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&body); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if s.token != "" && body.Token != s.token {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleSetStatus applies an analyst action — resolve, dismiss as
// false-positive, or reopen — to an investigation. This is the one
// write action an analyst has on an investigation; everything else in the
// API is read-only evidence.
func (s *Server) handleSetStatus(w http.ResponseWriter, r *http.Request) {
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
	if err := s.eng.SetStatus(id, body.Status); err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, pipeline.ErrInvestigationNotFound) {
			code = http.StatusNotFound
		}
		http.Error(w, err.Error(), code)
		return
	}
	inv, _ := s.eng.Invs.Get(id)
	writeJSON(w, http.StatusOK, summarize(inv))
}

func (s *Server) handleNarrative(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	inv, ok := s.eng.Invs.Get(id)
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

func (s *Server) handleVerify(w http.ResponseWriter, _ *http.Request) {
	ok, seq := s.eng.Audit.Verify()
	writeJSON(w, http.StatusOK, map[string]any{"intact": ok, "first_bad_seq": seq, "entries": s.eng.Audit.Len()})
}

func (s *Server) handleStats(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.eng.Stats())
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
