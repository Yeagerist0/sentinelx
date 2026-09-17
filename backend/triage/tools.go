package triage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"sentinelx/backend/correlate"
	"sentinelx/backend/normalize"
	"sentinelx/backend/store"
)

// ToolInput represents parameters passed to a tool execution.
type ToolInput map[string]any

// ToolResult represents the data returned by a tool execution.
type ToolResult map[string]any

// Tool interface defining capabilities available to the Triage Agent loop:
// 1. read_provenance_graph: Read graph nodes, rare causal edges, and hub boundaries
// 2. query_process_lineage: Query parent-child process ancestry and execution hierarchy
// 3. sandbox_exec: Execute/reproduce command chains in an isolated sandbox environment
// 4. read_file_contents: Read file contents / dropped artifacts at time of detection
type Tool interface {
	Name() string
	Description() string
	Execute(ctx context.Context, input ToolInput) (ToolResult, error)
}

// ----------------------------------------------------------------------
// Tool 1: ReadProvenanceGraphTool
// ----------------------------------------------------------------------

type ReadProvenanceGraphTool struct {
	Events     []correlate.Event
	Techniques []string
	Risk       int
}

func (t *ReadProvenanceGraphTool) Name() string { return "read_provenance_graph" }
func (t *ReadProvenanceGraphTool) Description() string {
	return "Read provenance graph nodes, causal edges, rarity weights, and hub boundaries"
}
func (t *ReadProvenanceGraphTool) Execute(ctx context.Context, input ToolInput) (ToolResult, error) {
	var nodes []map[string]any
	var edges []map[string]any

	evs := append([]correlate.Event(nil), t.Events...)
	sort.Slice(evs, func(i, j int) bool { return evs[i].TS.Before(evs[j].TS) })

	for _, ev := range evs {
		node := map[string]any{
			"id":        ev.ProcGUID,
			"proc_name": ev.ProcImage,
			"cmdline":   ev.Cmdline,
			"type":      string(ev.Type),
			"timestamp": ev.TS.Format(time.RFC3339),
		}
		nodes = append(nodes, node)

		if ev.ParentGUID != "" {
			edges = append(edges, map[string]any{
				"src":      ev.ParentGUID,
				"dst":      ev.ProcGUID,
				"rel":      "spawned",
				"event_id": ev.ID,
			})
		}
		if ev.FilePath != "" {
			edges = append(edges, map[string]any{
				"src":  ev.ProcGUID,
				"dst":  ev.FilePath,
				"rel":  string(ev.Type),
				"rare": strings.HasPrefix(ev.FilePath, "/tmp/") || strings.Contains(ev.FilePath, "authorized_keys"),
			})
		}
		if ev.RemoteAddr != "" {
			edges = append(edges, map[string]any{
				"src":  ev.ProcGUID,
				"dst":  fmt.Sprintf("%s:%d", ev.RemoteAddr, ev.RemotePort),
				"rel":  "net_connect",
				"rare": ev.RemotePort != 80 && ev.RemotePort != 443,
			})
		}
	}

	return ToolResult{
		"risk_score":  t.Risk,
		"techniques":  t.Techniques,
		"nodes_count": len(nodes),
		"nodes":       nodes,
		"edges":       edges,
	}, nil
}

// ----------------------------------------------------------------------
// Tool 2: QueryProcessLineageTool
// ----------------------------------------------------------------------

type QueryProcessLineageTool struct {
	Events []correlate.Event
}

func (t *QueryProcessLineageTool) Name() string { return "query_process_lineage" }
func (t *QueryProcessLineageTool) Description() string {
	return "Query parent-child process lineage, ancestry tree, and execution timeline"
}
func (t *QueryProcessLineageTool) Execute(ctx context.Context, input ToolInput) (ToolResult, error) {
	evs := append([]correlate.Event(nil), t.Events...)
	sort.Slice(evs, func(i, j int) bool { return evs[i].TS.Before(evs[j].TS) })

	var lineage []map[string]any
	for _, ev := range evs {
		lineage = append(lineage, map[string]any{
			"proc_guid":   ev.ProcGUID,
			"parent_guid": ev.ParentGUID,
			"proc_image":  ev.ProcImage,
			"cmdline":     ev.Cmdline,
			"host_id":     ev.HostID,
			"timestamp":   ev.TS.Format(time.RFC3339),
		})
	}

	return ToolResult{
		"lineage_depth": len(lineage),
		"process_chain": lineage,
	}, nil
}

// ----------------------------------------------------------------------
// Tool 3: SandboxExecTool
// ----------------------------------------------------------------------

type SandboxExecTool struct {
	Sandbox SandboxExecutor
	Events  []normalize.AgentEvent
}

func (t *SandboxExecTool) Name() string { return "execute_in_sandbox" }
func (t *SandboxExecTool) Description() string {
	return "Execute and reproduce command sequence in an isolated execution sandbox"
}
func (t *SandboxExecTool) Execute(ctx context.Context, input ToolInput) (ToolResult, error) {
	if t.Sandbox == nil {
		t.Sandbox = NewDefaultSandbox()
	}
	res, err := t.Sandbox.ExecuteChain(ctx, t.Events)
	if err != nil {
		return nil, fmt.Errorf("sandbox execution failed: %w", err)
	}
	return ToolResult{
		"command_chain":      res.CommandChain,
		"exit_code":          res.ExitCode,
		"stdout":             res.Stdout,
		"stderr":             res.Stderr,
		"artifacts_dropped":  res.ArtifactsDropped,
		"network_calls":      res.NetworkCalls,
		"reproduced_impact":  res.ReproducedImpact,
		"reproduction_steps": res.ReproductionSteps,
		"execution_time_ms":  res.ExecutionTimeMs,
	}, nil
}

// ----------------------------------------------------------------------
// Tool 4: ReadFileContentsTool
// ----------------------------------------------------------------------

type ReadFileContentsTool struct {
	Events []correlate.Event
}

func (t *ReadFileContentsTool) Name() string { return "read_file_contents" }
func (t *ReadFileContentsTool) Description() string {
	return "Read file contents or dropped artifact bytes at the time of detection"
}
func (t *ReadFileContentsTool) Execute(ctx context.Context, input ToolInput) (ToolResult, error) {
	targetPath, _ := input["path"].(string)

	filesFound := make(map[string]string)

	// Check if captured in event metadata
	for _, ev := range t.Events {
		if ev.FilePath != "" {
			if targetPath == "" || ev.FilePath == targetPath {
				content := "[binary/executable payload recorded in telemetry]"
				if ev.Raw != nil {
					if c, ok := ev.Raw["file_content"].(string); ok {
						content = c
					}
				}
				// If file exists locally on disk in a safe readable path, read prefix
				if strings.HasPrefix(ev.FilePath, "/tmp/") || strings.HasPrefix(ev.FilePath, "/etc/") {
					if b, err := os.ReadFile(ev.FilePath); err == nil {
						if len(b) > 1024 {
							b = b[:1024]
						}
						content = string(b)
					}
				}
				filesFound[ev.FilePath] = content
			}
		}
	}

	if len(filesFound) == 0 && targetPath != "" {
		// Clean and sanitize file path
		cleanPath := filepath.Clean(targetPath)
		if b, err := os.ReadFile(cleanPath); err == nil {
			if len(b) > 1024 {
				b = b[:1024]
			}
			filesFound[cleanPath] = string(b)
		} else {
			filesFound[targetPath] = fmt.Sprintf("[file not on disk: %v]", err)
		}
	}

	return ToolResult{
		"files_read": len(filesFound),
		"files":      filesFound,
	}, nil
}

// ----------------------------------------------------------------------
// Tool 5: QuerySentinelXAPITool (Related telemetry query)
// ----------------------------------------------------------------------

type QuerySentinelXAPITool struct {
	TenantID string
	Events   store.EventStore
	Invs     store.InvestigationStore
}

func (t *QuerySentinelXAPITool) Name() string { return "query_sentinelx_api" }
func (t *QuerySentinelXAPITool) Description() string {
	return "Query SentinelX API for related host events, co-occurring process lineage, and lateral events"
}
func (t *QuerySentinelXAPITool) Execute(ctx context.Context, input ToolInput) (ToolResult, error) {
	var matching []map[string]any

	invs := t.Invs.ListByTenant(t.TenantID)
	for _, inv := range invs {
		for id := range inv.EventIDs {
			if ev, ok := t.Events.Get(id); ok {
				matching = append(matching, map[string]any{
					"id":        ev.ID,
					"proc_name": ev.ProcImage,
					"cmdline":   ev.Cmdline,
					"proc_guid": ev.ProcGUID,
					"type":      string(ev.Type),
					"host_id":   ev.HostID,
					"timestamp": ev.TS.Format(time.RFC3339),
				})
				if len(matching) >= 20 {
					break
				}
			}
		}
		if len(matching) >= 20 {
			break
		}
	}

	return ToolResult{
		"related_events_count": len(matching),
		"related_events":       matching,
	}, nil
}
