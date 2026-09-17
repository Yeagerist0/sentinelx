.PHONY: build agent test test-pg vet demo rules coverage bench triage-eval ui docker clean

build:
	go build -o ./bin/sentinelx ./cmd/sentinelx

# Real eBPF agent (separate module). Needs clang + a strip tool to regenerate the
# BPF object; the generated object is committed so a plain build needs neither.
agent:
	cd agent && go build -o ../bin/sentinelx-agent .

agent-gen:
	cd agent && go generate ./...

test:
	go test ./...

# Postgres integration + durability tests. Point SENTINELX_TEST_PG at a DSN.
# Runs -p 1 because the tests share one database.
test-pg:
	SENTINELX_TEST_PG="$${SENTINELX_TEST_PG:?set SENTINELX_TEST_PG}" go test -p 1 -run PG -v ./backend/store/ ./tests/

vet:
	gofmt -l . && go vet ./...

# Serve API + UI at http://localhost:8080 (set SENTINELX_PG for durability).
ui: build
	SENTINELX_TOKEN=demo ./bin/sentinelx serve --ui ./frontend

# Alert-reduction ratio + precision/recall over labeled scenarios.
bench:
	go run ./cmd/sentinelx bench --dir ./tests/scenarios/bench --rules ./rules

# Triage Agent held-out evaluation set harness (accuracy, FPR, failure taxonomy, confound resilience).
triage-eval:
	go run ./cmd/sentinelx eval --rules ./rules

# End-to-end demo: replay the attack chain and show one investigation.
demo:
	./demo.sh

# Print the MITRE ATT&CK coverage derived from the ruleset (CI artifact).
coverage:
	go run ./cmd/sentinelx rules --rules ./rules

docker:
	docker build -f deploy/Dockerfile -t sentinelx:dev .

clean:
	rm -rf ./bin
