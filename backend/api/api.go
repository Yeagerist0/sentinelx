// Package api exposes the backend over HTTP/JSON. In production this sits behind
// mTLS for agents (POST /v1/ingest) and OIDC bearer auth for analysts (GET
// endpoints); here a shared bearer token gates writes so the demo runs without
// an IdP. See deploy/ for the TLS/OIDC wiring.
package api

import (
	"encoding/json"
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
	mux.HandleFunc("GET /v1/investigations", s.handleList)
	mux.HandleFunc("GET /v1/investigations/{id}", s.handleGet)
	mux.HandleFunc("GET /v1/investigations/{id}/narrative", s.handleNarrative)
	mux.HandleFunc("GET /v1/audit/verify", s.handleVerify)
	mux.HandleFunc("GET /v1/stats", s.handleStats)
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
	writeJSON(w, http.StatusOK, detail(inv, s.eng.Events))
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
