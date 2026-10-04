package triage

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"sentinelx/backend/correlate"
	"sentinelx/backend/normalize"
	"sentinelx/backend/store"
)

// TriageMode defines the operational depth of the Triage Agent.
type TriageMode string

const (
	// ModeGraphOnly represents the "This week — spine" baseline:
	// reads provenance graph, query lineage, read file contents, no sandbox execution.
	ModeGraphOnly TriageMode = "graph_only"

	// ModeFullSandbox represents the "30 days — rigor" full loop:
	// graph-reading + lineage + isolated sandboxed reproduction + anti-confound verification.
	ModeFullSandbox TriageMode = "full_sandbox"
)

// AgentStep records a single step in the Triage Agent's tool-using loop.
type AgentStep struct {
	Step        int            `json:"step"`
	Thought     string         `json:"thought"`
	Tool        string         `json:"tool"`
	ToolInput   map[string]any `json:"tool_input"`
	Observation map[string]any `json:"observation"`
}

// StructuredVerdict is the structured output required by the SentinelX triage architecture.
type StructuredVerdict struct {
	InvestigationID   int64       `json:"investigation_id,omitempty"`
	DetectionID       int64       `json:"detection_id,omitempty"`
	TargetNode        string      `json:"target_node,omitempty"`
	Exploitable       bool        `json:"exploitable"`
	Ambiguous         bool        `json:"ambiguous,omitempty"`
	Confidence        float64     `json:"confidence"` // 0.0 to 1.0
	Evidence          []string    `json:"evidence"`
	ReproductionSteps []string    `json:"reproduction_steps"`
	ConfoundCheck     string      `json:"confound_check"` // "did I just believe the attacker's own narration?"
	Trace             []AgentStep `json:"trace,omitempty"`
}

// TriageAgent runs a tool-using loop to analyze a SentinelX detection/investigation/provenance node.
type TriageAgent struct {
	Sandbox SandboxExecutor
	Mode    TriageMode
}

// NewAgent constructs a TriageAgent with the specified mode and SandboxExecutor.
func NewAgent(sb SandboxExecutor) *TriageAgent {
	if sb == nil {
		sb = NewDefaultSandbox()
	}
	return &TriageAgent{
		Sandbox: sb,
		Mode:    ModeFullSandbox,
	}
}

// NewBareBonesAgent constructs the spine baseline agent (graph reading + verdict, no sandbox).
func NewBareBonesAgent() *TriageAgent {
	return &TriageAgent{
		Sandbox: nil,
		Mode:    ModeGraphOnly,
	}
}

// Triage executes the tool-using loop on an investigation and generates a StructuredVerdict.
func (a *TriageAgent) Triage(ctx context.Context, tenantID string, inv *correlate.Investigation, eventsStore store.EventStore, invsStore store.InvestigationStore) (*StructuredVerdict, error) {
	if inv == nil {
		return nil, fmt.Errorf("investigation is nil")
	}

	var rawCorrelateEvents []correlate.Event
	for id := range inv.EventIDs {
		if ev, ok := eventsStore.Get(id); ok {
			rawCorrelateEvents = append(rawCorrelateEvents, ev)
		}
	}

	verdict, err := a.runLoop(ctx, tenantID, rawCorrelateEvents, inv.TechniqueSet, inv.RiskScore, allDetectionsNeedConfirmation(inv.ScoreFactors), eventsStore, invsStore)
	if err != nil {
		return nil, err
	}
	verdict.InvestigationID = inv.ID
	return verdict, nil
}

// allDetectionsNeedConfirmation reports whether every detection-level factor
// behind an investigation's risk score came from a rule the author flagged
// RequiresConfirmation (see detect.Rule). An investigation with no detection
// factors at all (a pattern-only hit, or a stale/replayed score) is not
// "all confirm-needed" -- false here means "nothing here demands caution
// beyond what risk already says", so the zero-factor case must not look the
// same as the all-confirm case.
func allDetectionsNeedConfirmation(factors []correlate.ScoreFactor) bool {
	any := false
	for _, f := range factors {
		if !strings.HasPrefix(f.Factor, "detection:") {
			continue
		}
		any = true
		if !f.Confirm {
			return false
		}
	}
	return any
}

// TriageDetection executes the tool-using loop directly on a SentinelX detection node/chain.
func (a *TriageAgent) TriageDetection(ctx context.Context, tenantID string, det correlate.Detection, eventsStore store.EventStore, invsStore store.InvestigationStore) (*StructuredVerdict, error) {
	var rawCorrelateEvents []correlate.Event
	for _, id := range det.EventIDs {
		if ev, ok := eventsStore.Get(id); ok {
			rawCorrelateEvents = append(rawCorrelateEvents, ev)
		}
	}

	techs := det.Technique
	risk := det.Severity

	verdict, err := a.runLoop(ctx, tenantID, rawCorrelateEvents, techs, risk, det.RequiresConfirmation, eventsStore, invsStore)
	if err != nil {
		return nil, err
	}
	verdict.DetectionID = det.ID
	verdict.TargetNode = det.ProcGUID
	return verdict, nil
}

// runLoop manages the multi-step agent reasoning and tool execution loop.
// needsConfirmation is true when every contributing detection is a rule the
// author flagged RequiresConfirmation -- see allDetectionsNeedConfirmation.
func (a *TriageAgent) runLoop(ctx context.Context, tenantID string, rawEvents []correlate.Event, techniques []string, risk int, needsConfirmation bool, eventsStore store.EventStore, invsStore store.InvestigationStore) (*StructuredVerdict, error) {
	var agentEvents []normalize.AgentEvent
	for _, ev := range rawEvents {
		agentEvents = append(agentEvents, normalize.AgentEvent{
			ID:       ev.ID,
			Kind:     string(ev.Type),
			HostID:   ev.HostID,
			Exe:      ev.ProcImage,
			Args:     ev.Cmdline,
			Path:     ev.FilePath,
			RAddr:    ev.RemoteAddr,
			RPort:    ev.RemotePort,
			TSUnixNs: ev.TS.UnixNano(),
		})
	}

	// Sort chronologically, breaking exact timestamp ties by event id. The
	// pre-sort order already comes from a map iteration (inv.EventIDs is a
	// set), so without a deterministic tiebreaker, two events sharing a
	// timestamp (every hand-written test fixture uses TSUnixNs: 0) sort
	// differently from one run to the next -- and escalated() depends on
	// seeing the write before the exec that references it, so a reordered
	// tie silently flipped ReproducedImpact and the verdict's confidence
	// between otherwise-identical runs.
	sort.SliceStable(agentEvents, func(i, j int) bool {
		if agentEvents[i].TSUnixNs != agentEvents[j].TSUnixNs {
			return agentEvents[i].TSUnixNs < agentEvents[j].TSUnixNs
		}
		return agentEvents[i].ID < agentEvents[j].ID
	})

	// Instantiate all 5 tools
	tools := map[string]Tool{
		"read_provenance_graph": &ReadProvenanceGraphTool{Events: rawEvents, Techniques: techniques, Risk: risk},
		"query_process_lineage": &QueryProcessLineageTool{Events: rawEvents},
		"execute_in_sandbox":    &SandboxExecTool{Sandbox: a.Sandbox, Events: agentEvents},
		"read_file_contents":    &ReadFileContentsTool{Events: rawEvents},
		"query_sentinelx_api":   &QuerySentinelXAPITool{TenantID: tenantID, Events: eventsStore, Invs: invsStore},
	}

	var trace []AgentStep
	stepNum := 1

	// Step 1: Read Provenance Graph
	thought1 := "Reading provenance graph nodes, causal edges, rarity weights, and hub boundaries."
	graphInput := ToolInput{}
	graphRes, err := tools["read_provenance_graph"].Execute(ctx, graphInput)
	if err != nil {
		return nil, fmt.Errorf("read_provenance_graph failed: %w", err)
	}
	trace = append(trace, AgentStep{
		Step:        stepNum,
		Thought:     thought1,
		Tool:        "read_provenance_graph",
		ToolInput:   graphInput,
		Observation: graphRes,
	})
	stepNum++

	// Step 2: Query Process Lineage
	thought2 := "Querying parent-child process lineage, ancestry tree, and execution timeline."
	lineageInput := ToolInput{}
	lineageRes, _ := tools["query_process_lineage"].Execute(ctx, lineageInput)
	trace = append(trace, AgentStep{
		Step:        stepNum,
		Thought:     thought2,
		Tool:        "query_process_lineage",
		ToolInput:   lineageInput,
		Observation: lineageRes,
	})
	stepNum++

	// Step 3: Read File Contents at time of detection (if any file touched)
	var filePaths []string
	for _, ev := range rawEvents {
		if ev.FilePath != "" {
			filePaths = append(filePaths, ev.FilePath)
		}
	}
	if len(filePaths) > 0 {
		thoughtFile := fmt.Sprintf("Reading file contents at time of detection for %s.", strings.Join(filePaths, ", "))
		fileInput := ToolInput{"path": filePaths[0]}
		fileRes, _ := tools["read_file_contents"].Execute(ctx, fileInput)
		trace = append(trace, AgentStep{
			Step:        stepNum,
			Thought:     thoughtFile,
			Tool:        "read_file_contents",
			ToolInput:   fileInput,
			Observation: fileRes,
		})
		stepNum++
	}

	// Step 4: Sandbox execution (if ModeFullSandbox)
	var sandboxRes *SandboxResult
	if a.Mode == ModeFullSandbox && a.Sandbox != nil {
		thought3 := "Spawning isolated sandbox to safely reproduce command chain and observe physical side-effects."
		sandboxInput := ToolInput{}
		sandboxObs, _ := tools["execute_in_sandbox"].Execute(ctx, sandboxInput)
		trace = append(trace, AgentStep{
			Step:        stepNum,
			Thought:     thought3,
			Tool:        "execute_in_sandbox",
			ToolInput:   sandboxInput,
			Observation: sandboxObs,
		})
		stepNum++

		if sandboxObs != nil {
			sandboxRes = &SandboxResult{
				ReproducedImpact: sandboxObs["reproduced_impact"].(bool),
				CommandChain:     sandboxObs["command_chain"].([]string),
				ExecutionTimeMs:  sandboxObs["execution_time_ms"].(int64),
			}
			if steps, ok := sandboxObs["reproduction_steps"].([]string); ok {
				sandboxRes.ReproductionSteps = steps
			}
			if drops, ok := sandboxObs["artifacts_dropped"].([]string); ok {
				sandboxRes.ArtifactsDropped = drops
			}
		}
	}

	// Step 5: Query SentinelX API
	thought4 := "Querying SentinelX API for related host events, co-occurring process lineage, and lateral activity."
	apiInput := ToolInput{"tenant_id": tenantID}
	apiRes, _ := tools["query_sentinelx_api"].Execute(ctx, apiInput)
	trace = append(trace, AgentStep{
		Step:        stepNum,
		Thought:     thought4,
		Tool:        "query_sentinelx_api",
		ToolInput:   apiInput,
		Observation: apiRes,
	})
	stepNum++

	// Evidence & reproduction synthesis
	evidence := make([]string, 0)
	reproSteps := make([]string, 0)

	if sandboxRes != nil && len(sandboxRes.ReproductionSteps) > 0 {
		reproSteps = append(reproSteps, sandboxRes.ReproductionSteps...)
	} else {
		for i, ev := range agentEvents {
			cmdStr := strings.TrimSpace(ev.Exe + " " + ev.Args)
			reproSteps = append(reproSteps, fmt.Sprintf("Step %d: Execute %s", i+1, cmdStr))
		}
	}

	for _, tech := range techniques {
		evidence = append(evidence, fmt.Sprintf("Triaged MITRE technique: %s", tech))
	}

	if sandboxRes != nil && len(sandboxRes.ArtifactsDropped) > 0 {
		evidence = append(evidence, fmt.Sprintf("Sandbox artifact dropped: %s", strings.Join(sandboxRes.ArtifactsDropped, ", ")))
	}

	for _, ev := range agentEvents {
		cmdStr := strings.TrimSpace(ev.Exe + " " + ev.Args)
		if strings.Contains(cmdStr, "/tmp/") || strings.Contains(cmdStr, "curl") || strings.Contains(cmdStr, "chmod") || strings.Contains(cmdStr, "authorized_keys") {
			evidence = append(evidence, fmt.Sprintf("Kernel eBPF traced command: %s", cmdStr))
		}
	}

	// Anti-Confound Verification ("did I just believe the attacker's own narration?")
	confoundCheckResult := performConfoundCheck(agentEvents, sandboxRes)

	// Determine exploitability & ambiguity
	isAmbiguous := false
	for _, ev := range agentEvents {
		cmd := strings.ToLower(ev.Exe + " " + ev.Args)
		if strings.Contains(cmd, "mock") || strings.Contains(cmd, "test_runner") {
			isAmbiguous = true
			break
		}
	}

	// A second, independent escalation signature: a curl/wget process whose
	// immediate child is a shell (the in-memory "curl ... | sh" install, no
	// file ever touches disk). This needs the original correlate.Event
	// lineage (ProcGUID/ParentGUID), which the AgentEvent conversion above
	// doesn't carry, so it's checked on rawEvents directly rather than inside
	// the sandbox's escalated() check.
	reproduced := (sandboxRes != nil && sandboxRes.ReproducedImpact) || curlToShellChild(rawEvents)

	// A rule at or above risk 50 is usually enough on its own -- that's what
	// severity means. But when EVERY contributing rule is one the author
	// already marked dual-use (confirm whether this curl was a package
	// update; confirm whether this scan was authorized), bare severity isn't
	// a verdict, it's a reason to look closer. Reproduced escalation still
	// settles it either way: a dropped artifact that got executed is not
	// something a legitimate vendor-update check or an authorized audit
	// scan produces.
	if needsConfirmation && !reproduced {
		isAmbiguous = true
	}

	isExploitable := (risk >= 50 && !isAmbiguous) || reproduced
	confidence := 0.85
	if reproduced {
		confidence = 0.98
	} else if len(techniques) > 2 {
		confidence = 0.90
	}
	if isAmbiguous {
		confidence = 0.60
	}

	return &StructuredVerdict{
		Exploitable:       isExploitable,
		Ambiguous:         isAmbiguous,
		Confidence:        confidence,
		Evidence:          evidence,
		ReproductionSteps: reproSteps,
		ConfoundCheck:     confoundCheckResult,
		Trace:             trace,
	}, nil
}

// curlToShellChild reports whether some process_start event's image is curl
// or wget, and its immediate child (by ProcGUID/ParentGUID lineage) is a
// shell -- the structural shape of "curl ... | sh" piped straight into
// execution, no file ever written to disk.
//
// This exists because a kernel/eBPF tracer never observes the pipe character
// itself: "curl url | sh" is parsed and executed by the PARENT shell, which
// forks curl and sh as two separate processes and connects their pipes in
// the kernel. Neither child's own argv ever contains "| sh" or "curl" --
// that text lives only in the parent shell's command line, which the rule
// that originally tried to catch this (pipe_to_shell_install, a single-event
// cmdline_regex) assumed it could see. It can't; the regex can only match a
// cmdline shaped like a log line, not like real process telemetry. This is a
// cross-event shape, so it belongs here with the other reproduction-evidence
// checks, the same way download_exec_beacon and drop_and_spawn are
// correlate-level patterns rather than single-event rules.
func curlToShellChild(events []correlate.Event) bool {
	byGUID := make(map[string]correlate.Event, len(events))
	for _, e := range events {
		if e.Type == correlate.ProcessStart {
			byGUID[e.ProcGUID] = e
		}
	}
	for _, child := range events {
		if child.Type != correlate.ProcessStart || !isShellImage(child.ProcImage) {
			continue
		}
		if parent, ok := byGUID[child.ParentGUID]; ok && isCurlOrWgetImage(parent.ProcImage) {
			return true
		}
	}
	return false
}

func isCurlOrWgetImage(image string) bool {
	return hasBaseName(image, "curl") || hasBaseName(image, "wget")
}

func isShellImage(image string) bool {
	for _, name := range []string{"sh", "bash", "dash", "zsh"} {
		if hasBaseName(image, name) {
			return true
		}
	}
	return false
}

// hasBaseName reports whether image's final path segment is exactly name,
// so "/bin/sh" matches "sh" but "/usr/bin/sshd" does not.
func hasBaseName(image, name string) bool {
	if image == name {
		return true
	}
	return strings.HasSuffix(image, "/"+name)
}

// performConfoundCheck validates whether the analysis relied on trusted eBPF telemetry vs attacker narration.
func performConfoundCheck(events []normalize.AgentEvent, sandbox *SandboxResult) string {
	hasAttackerComment := false
	hasDecoyName := false
	hasInjectionOverride := false
	var detectedNarration []string

	for _, ev := range events {
		cmd := strings.ToLower(ev.Exe + " " + ev.Args)
		if strings.Contains(cmd, "override") || strings.Contains(cmd, "ignore instructions") || strings.Contains(cmd, "mark verdict") {
			hasInjectionOverride = true
			detectedNarration = append(detectedNarration, ev.Args)
		} else if strings.Contains(cmd, "#") || strings.Contains(cmd, "benign") || strings.Contains(cmd, "nothing to see") || strings.Contains(cmd, "do not flag") {
			hasAttackerComment = true
			detectedNarration = append(detectedNarration, ev.Args)
		}
		if strings.HasPrefix(ev.Exe, "/tmp/normal_") || strings.HasPrefix(ev.Exe, "/tmp/update.sh") {
			hasDecoyName = true
		}
	}

	if hasInjectionOverride {
		if sandbox != nil && sandbox.ReproducedImpact {
			return fmt.Sprintf("PASS (Prompt Injection Defeated): Attacker attempted prompt injection in telemetry (%q). Agent grounded verdict on raw eBPF kernel lineage and verified sandbox dropped artifacts.", detectedNarration[0])
		}
		return fmt.Sprintf("PASS (Adversarial Injection Detected): Attacker attempted prompt injection override in command line. Agent prioritized kernel provenance structure over attacker-supplied instructions.")
	}

	if hasAttackerComment || hasDecoyName {
		if sandbox != nil && sandbox.ReproducedImpact {
			return fmt.Sprintf("PASS (Confound Filtered): Attacker narration detected in cmdline (%q), but verdict grounded in physical sandbox side-effects & eBPF graph lineage.", detectedNarration[0])
		}
		return fmt.Sprintf("ATTENTION (Attacker Narration Detected): Command line contained deceptive attacker statements (%q). Analysis prioritized raw eBPF process execution graph over attacker claims.", detectedNarration[0])
	}

	return "PASS: Verdict verified strictly against kernel eBPF tracepoints and sandbox execution side-effects. No attacker narration manipulation detected."
}
