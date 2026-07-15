package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"sentinelx/backend/correlate"
	"sentinelx/backend/detect"
	"sentinelx/backend/pipeline"
)

func newServer(t *testing.T) *Server {
	t.Helper()
	rules, err := detect.NewEngine(detect.Default())
	if err != nil {
		t.Fatal(err)
	}
	sc := correlate.NewScorer()
	sc.CtxMult["T1204.002"] = 1.15
	return New(pipeline.New(rules, sc), "secret")
}

func scenario(t *testing.T) []byte {
	b, err := os.ReadFile("../../tests/scenarios/curl_lolbin.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAPI_IngestRequiresAuth(t *testing.T) {
	srv := newServer(t)
	h := srv.Routes()

	req := httptest.NewRequest("POST", "/v1/ingest", strings.NewReader("[]"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 without token, got %d", rr.Code)
	}
}

// Read endpoints are the analyst-facing "login" gate: unauthenticated requests
// must be rejected the same as the agent ingest path.
func TestAPI_ReadEndpointsRequireAuth(t *testing.T) {
	srv := newServer(t)
	h := srv.Routes()
	for _, path := range []string{"/v1/investigations", "/v1/investigations/1", "/v1/investigations/1/narrative", "/v1/audit/verify", "/v1/stats"} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest("GET", path, nil))
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("%s: want 401 without token, got %d", path, rr.Code)
		}
	}
}

func TestAPI_Login(t *testing.T) {
	srv := newServer(t)
	h := srv.Routes()

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("POST", "/v1/login", strings.NewReader(`{"token":"wrong"}`)))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: want 401, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("POST", "/v1/login", strings.NewReader(`{"token":"secret"}`)))
	if rr.Code != http.StatusOK {
		t.Fatalf("correct token: want 200, got %d", rr.Code)
	}
}

func TestAPI_FullFlow(t *testing.T) {
	srv := newServer(t)
	h := srv.Routes()

	// ingest (authed)
	req := httptest.NewRequest("POST", "/v1/ingest", strings.NewReader(string(scenario(t))))
	req.Header.Set("Authorization", "Bearer secret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("ingest status %d", rr.Code)
	}

	authedGet := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("Authorization", "Bearer secret")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}

	// list -> exactly one investigation
	rr = authedGet("/v1/investigations")
	var list []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &list); err != nil {
		t.Fatalf("list decode: %v (%s)", err, rr.Body.String())
	}
	if len(list) != 1 {
		t.Fatalf("want 1 investigation, got %d", len(list))
	}

	// detail -> nodes/edges/timeline/detections present and JSON-serializable
	// (nodes/edges/timeline is also a regression check for the graph-cycle bug)
	rr = authedGet("/v1/investigations/1")
	var det map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &det); err != nil {
		t.Fatalf("detail decode: %v", err)
	}
	for _, k := range []string{"nodes", "edges", "timeline", "score_factors", "detections"} {
		if _, ok := det[k]; !ok {
			t.Fatalf("detail missing %q", k)
		}
	}
	// each detection drill-down must carry the rule, its events, and remediation
	// guidance — the "what fired and how do I fix it" click-through. 4, not 3:
	// the scenario's C2 callback (port 4444) is itself now caught by the
	// broadened ruleset's suspicious_c2_port rule.
	dets, _ := det["detections"].([]any)
	if len(dets) != 4 {
		t.Fatalf("want 4 detections in drill-down, got %d", len(dets))
	}
	for _, raw := range dets {
		d, _ := raw.(map[string]any)
		if d["rule_id"] == "" || d["rule_id"] == nil {
			t.Fatalf("detection missing rule_id: %v", d)
		}
		if rem, _ := d["remediation"].(string); rem == "" {
			t.Fatalf("detection %v missing remediation guidance", d["rule_id"])
		}
		if ids, _ := d["event_ids"].([]any); len(ids) == 0 {
			t.Fatalf("detection %v missing event_ids", d["rule_id"])
		}
	}

	// narrative -> grounded, non-empty
	rr = authedGet("/v1/investigations/1/narrative")
	var nar map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &nar); err != nil {
		t.Fatalf("narrative decode: %v", err)
	}
	if txt, _ := nar["text"].(string); !strings.Contains(txt, "risk") {
		t.Fatalf("narrative missing risk verdict: %v", nar["text"])
	}

	// audit chain intact
	rr = authedGet("/v1/audit/verify")
	var v map[string]any
	json.Unmarshal(rr.Body.Bytes(), &v)
	if intact, _ := v["intact"].(bool); !intact {
		t.Fatalf("audit chain not intact: %v", v)
	}

	authedPost := func(path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer secret")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}

	// resolving an investigation is the one write action an analyst has.
	rr = authedPost("/v1/investigations/1/status", `{"status":"resolved"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("resolve status %d: %s", rr.Code, rr.Body.String())
	}
	var sum map[string]any
	json.Unmarshal(rr.Body.Bytes(), &sum)
	if sum["status"] != "resolved" {
		t.Fatalf("resolve response status = %v, want resolved", sum["status"])
	}
	// and it must be reflected back on a fresh GET, not just the write response.
	rr = authedGet("/v1/investigations/1")
	json.Unmarshal(rr.Body.Bytes(), &det)
	if det["status"] != "resolved" {
		t.Fatalf("GET after resolve: status = %v, want resolved", det["status"])
	}

	rr = authedPost("/v1/investigations/1/status", `{"status":"bogus"}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid status: want 400, got %d", rr.Code)
	}
	rr = authedPost("/v1/investigations/99999/status", `{"status":"resolved"}`)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("unknown investigation: want 404, got %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("POST", "/v1/investigations/1/status", strings.NewReader(`{"status":"resolved"}`)))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauthed status change: want 401, got %d", rr.Code)
	}
}
