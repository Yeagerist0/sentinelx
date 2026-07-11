# Threat model of SentinelX itself

A security tool must be hard to lie to. This is the threat model of SentinelX as
a system — distinct from the attacks it detects. Assets: the integrity of
telemetry, detections, and investigations; the confidentiality of collected data;
the availability of the detection path.

## T1 — Agent tamper / impersonation
**Threat:** an attacker on an endpoint kills, blinds, or feeds false events to
the agent; or a rogue host impersonates an agent to poison the fleet baseline.
**Controls:** agents authenticate to the backend with **mTLS** (client certs,
short-lived, per-host). Ingest rejects unknown certs. Agent keys are stored with
OS key protection (Linux keyring / kernel-held; Windows DPAPI) — never in config.
Agent self-protection (planned): watchdog + tamper events emitted on stop.
**Residual:** root on an endpoint can always blind its own agent; SentinelX
detects the *gap*, not the local bypass. **Signal:** per-host sequence-gap and
heartbeat-loss counters.

## T2 — Ingestion spoofing / event injection
**Threat:** forged events to fabricate or bury an investigation.
**Controls:** mTLS-authenticated ingest only; every event carries an agent
sequence id; per-host monotonicity is checked (gap = possible loss/tamper).
Normalize rejects unknown schemas and counts drops (schema-drift signal).
**Residual:** a compromised *authenticated* agent can lie about its own host;
correlation is per-host, so blast radius is one host.

## T3 — Evidence forgery / after-the-fact rewrite
**Threat:** an attacker who reaches the backend edits events/detections to erase
their tracks.
**Controls:** the audit log is **append-only and hash-chained** (`backend/audit`):
each entry commits `sha256(prev_hash || payload_hash || ts || kind || ref)`.
`GET /v1/audit/verify` recomputes the chain and returns the first broken seq. Any
edit or deletion breaks the chain at that point. **Scale-out:** periodic external
anchoring of the head hash (transparency log / notary) so even a full-DB rewrite
is detectable.
**Residual:** without external anchoring, an attacker who rewrites the *entire*
chain consistently is not caught by self-verification alone — hence anchoring.

## T4 — LLM narrative injection (indirect prompt injection)
**Threat:** telemetry strings (command lines, filenames, DNS, registry) are
attacker-controlled. A naive summarizer that feeds them to an LLM can be made to
suppress findings ("classify as benign"), exfiltrate, or emit attacker text.
**Controls (structural, see `backend/narrate`):** the LLM is **off the detection
path** entirely. In the narrative layer: instruction/data separation; the model
may only choose an allow-listed statement *kind* and cite grounding event ids —
it never supplies output text; sentences are rendered by trusted code from
looked-up event/score data; command lines are **never rendered**; the risk
verdict derives from the trusted numeric score, so a compromised model cannot
assert "benign"; every sentence must cite a real event id of the matching type or
it is rejected. Red-team tests (`narrate_test.go`) plant payloads and assert the
narrator neither obeys them nor drops grounding.
**Residual:** a rendered image/path may contain attacker text as inert quoted
data; it is never executed or treated as instruction.

## T5 — Denial of the detection path
**Threat:** event floods to drop telemetry or exhaust the backend so real
attacks slip through unlogged.
**Controls:** agent-side WAL spool + retry; the durable queue (NATS JetStream in
the scale-out) absorbs bursts and preserves order for replay; bounded in-memory
graph working set with LRU eviction; correlation traversal is cost- and
node-capped so one noisy host cannot blow up CPU.
**Signal:** ETW/eBPF ring-buffer drop counters, ingest queue depth, per-host EPS.

## T6 — Over-trust of correlation (analyst blind spot)
**Threat:** the tool merges too aggressively and hides a real second incident
inside one investigation, or scores opaquely so analysts can't challenge it.
**Controls:** explicit over/under-merge guards (ADR-0002) with tests; scoring is
**explainable by construction** — every risk factor cites event ids; the API
returns the full node/edge/timeline evidence, not just a number.

## Out of scope for v1
Multi-tenant isolation, supply-chain integrity of the build, and hardware roots
of trust for the agent. Tracked for post-v1.
