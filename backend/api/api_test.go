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

	// list -> exactly one investigation
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/v1/investigations", nil))
	var list []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &list); err != nil {
		t.Fatalf("list decode: %v (%s)", err, rr.Body.String())
	}
	if len(list) != 1 {
		t.Fatalf("want 1 investigation, got %d", len(list))
	}

	// detail -> nodes/edges/timeline present and JSON-serializable (the cycle bug regression)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/v1/investigations/1", nil))
	var det map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &det); err != nil {
		t.Fatalf("detail decode: %v", err)
	}
	for _, k := range []string{"nodes", "edges", "timeline", "score_factors"} {
		if _, ok := det[k]; !ok {
			t.Fatalf("detail missing %q", k)
		}
	}

	// narrative -> grounded, non-empty
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/v1/investigations/1/narrative", nil))
	var nar map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &nar); err != nil {
		t.Fatalf("narrative decode: %v", err)
	}
	if txt, _ := nar["text"].(string); !strings.Contains(txt, "risk") {
		t.Fatalf("narrative missing risk verdict: %v", nar["text"])
	}

	// audit chain intact
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/v1/audit/verify", nil))
	var v map[string]any
	json.Unmarshal(rr.Body.Bytes(), &v)
	if intact, _ := v["intact"].(bool); !intact {
		t.Fatalf("audit chain not intact: %v", v)
	}
}
