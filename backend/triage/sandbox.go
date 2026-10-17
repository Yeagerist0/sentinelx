package triage

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"sentinelx/backend/normalize"
)

// SandboxResult contains execution results from reproducing a command chain in an isolated environment.
type SandboxResult struct {
	CommandChain      []string          `json:"command_chain"`
	ExitCode          int               `json:"exit_code"`
	Stdout            string            `json:"stdout"`
	Stderr            string            `json:"stderr"`
	ArtifactsDropped  []string          `json:"artifacts_dropped"`
	NetworkCalls      []string          `json:"network_calls"`
	ProcessSpawned    []string          `json:"process_spawned"`
	ReproducedImpact  bool              `json:"reproduced_impact"`
	ReproductionSteps []string          `json:"reproduction_steps"`
	ExecutionTimeMs   int64             `json:"execution_time_ms"`
	IsolatedEnv       map[string]string `json:"isolated_env"`
}

// SandboxExecutor defines an isolated execution environment seam.
type SandboxExecutor interface {
	ExecuteChain(ctx context.Context, events []normalize.AgentEvent) (*SandboxResult, error)
}

// DefaultSandbox implements SandboxExecutor with safe simulated execution and isolated containerized/subprocess fallback.
type DefaultSandbox struct {
	IsolatedTmpDir string
}

// NewDefaultSandbox constructs a DefaultSandbox.
func NewDefaultSandbox() *DefaultSandbox {
	return &DefaultSandbox{}
}

// ExecuteChain runs/reproduces the event command chain in an isolated environment.
func (s *DefaultSandbox) ExecuteChain(ctx context.Context, events []normalize.AgentEvent) (*SandboxResult, error) {
	start := time.Now()
	res := &SandboxResult{
		CommandChain:      make([]string, 0, len(events)),
		ArtifactsDropped:  make([]string, 0),
		NetworkCalls:      make([]string, 0),
		ProcessSpawned:    make([]string, 0),
		ReproductionSteps: make([]string, 0),
		IsolatedEnv: map[string]string{
			"SANDBOX_ENV": "isolated",
			"PATH":        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		},
	}

	if len(events) == 0 {
		res.ExecutionTimeMs = time.Since(start).Milliseconds()
		return res, nil
	}

	// 1. Trace and analyze event commands
	for i, ev := range events {
		cmdStr := strings.TrimSpace(ev.Exe + " " + ev.Args)
		if cmdStr == "" {
			cmdStr = ev.Exe
		}
		res.CommandChain = append(res.CommandChain, cmdStr)
		res.ProcessSpawned = append(res.ProcessSpawned, ev.Exe)
		res.ReproductionSteps = append(res.ReproductionSteps,
			fmt.Sprintf("Step %d: Execute %s (PID %d)", i+1, cmdStr, ev.PID))

		// Extract potential network connections or dropped artifacts from event metadata
		if isKind(ev.Kind, "net.connect", "net_connect") || strings.Contains(cmdStr, "curl") || strings.Contains(cmdStr, "wget") || strings.Contains(cmdStr, "nc ") {
			if ev.RAddr != "" {
				res.NetworkCalls = append(res.NetworkCalls, fmt.Sprintf("%s:%d", ev.RAddr, ev.RPort))
			} else {
				res.NetworkCalls = append(res.NetworkCalls, "outbound_http_request")
			}
		}

		if strings.Contains(cmdStr, "/tmp/") || strings.Contains(cmdStr, "/var/tmp/") || ev.Path != "" {
			targetFile := ev.Path
			if targetFile == "" {
				fields := strings.Fields(cmdStr)
				for _, f := range fields {
					if strings.HasPrefix(f, "/tmp/") || strings.HasPrefix(f, "/var/tmp/") {
						targetFile = f
						break
					}
				}
			}
			if targetFile != "" {
				res.ArtifactsDropped = append(res.ArtifactsDropped, targetFile)
			}
		}
	}

	// 2. Perform safe isolated dry-run / subprocess execution in a temp directory
	tmpDir, err := os.MkdirTemp("", "sx_sandbox_*")
	if err == nil {
		defer os.RemoveAll(tmpDir)

		// Create a test payload script for reproduction
		scriptPath := filepath.Join(tmpDir, "reproduce.sh")
		var scriptLines []string
		scriptLines = append(scriptLines, "#!/bin/sh", "set -e")
		for _, cmd := range res.CommandChain {
			safeCmd := sanitizeForSandbox(cmd, tmpDir)
			scriptLines = append(scriptLines, safeCmd)
		}

		if err := os.WriteFile(scriptPath, []byte(strings.Join(scriptLines, "\n")), 0755); err == nil {
			subCtx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
			defer cancel()

			execCmd := exec.CommandContext(subCtx, "/bin/sh", scriptPath)
			execCmd.Dir = tmpDir
			execCmd.Stdin = strings.NewReader("") // Closed stdin so interactive shells never hang
			execCmd.Env = []string{
				"PATH=/usr/local/bin:/usr/bin:/bin",
				"HOME=" + tmpDir,
				"TMPDIR=" + tmpDir,
			}
			outBytes, execErr := execCmd.CombinedOutput()
			if execErr != nil {
				res.ExitCode = 1
				res.Stderr = execErr.Error()
			} else {
				res.ExitCode = 0
			}
			res.Stdout = string(outBytes)

			// Check for files dropped in temp dir
			entries, _ := os.ReadDir(tmpDir)
			for _, entry := range entries {
				if entry.Name() != "reproduce.sh" {
					res.ArtifactsDropped = append(res.ArtifactsDropped, filepath.Join(tmpDir, entry.Name()))
				}
			}
		}
	}

	// 3. Evaluate if impact was successfully reproduced.
	//
	// This used to be hasDrop || hasNet || hasSuspiciousExec, where all three
	// were derived from the SAME raw command strings the detection rule had
	// already matched on -- "contains /tmp/", "contains curl", "contains
	// chmod +x". That's circular: it re-states the fact that made the rule
	// fire in the first place as if the sandbox had independently confirmed
	// something. A legitimate "curl https://vendor/version -o cache.meta"
	// has a network call and a file write too; restating that doesn't show
	// impact, and it drove confidence to 0.98 on a vendor update check.
	//
	// What the sandbox can actually attest to is escalation: an artifact this
	// chain wrote was later executed, in this same chain -- a dropper
	// launching its own drop. That is the signature the correlator's own
	// patterns look for (drop_and_spawn, download_exec_beacon), and it is not
	// something "any file write" or "any curl" can fake.
	res.ReproducedImpact = escalated(events)
	res.ExecutionTimeMs = time.Since(start).Milliseconds()
	return res, nil
}

// escalated reports whether a path this chain wrote to was later executed --
// the actual "drop and run" signature of real impact, as opposed to a bare
// file write or a bare network call considered in isolation.
func escalated(events []normalize.AgentEvent) bool {
	written := map[string]bool{}
	for _, ev := range events {
		if isKind(ev.Kind, "file.write", "file_write") && ev.Path != "" {
			written[ev.Path] = true
			continue
		}
		if isKind(ev.Kind, "exec", "process_start") && ev.Exe != "" && written[ev.Exe] {
			return true
		}
	}
	return false
}

// isKind reports whether k is any of the given spellings. AgentEvent.Kind
// carries one of two equivalent vocabularies depending on how the event
// arrived: a literal built directly (demos, hand-written test fixtures) uses
// the dotted form ("exec", "file.write", "net.connect"); an event that round
// tripped through normalize -> correlate and back uses correlate.EventType's
// underscored form ("process_start", "file_write", "net_connect"). Comparing
// against only one spelling silently never matches the other path.
func isKind(k string, spellings ...string) bool {
	for _, s := range spellings {
		if k == s {
			return true
		}
	}
	return false
}

func sanitizeForSandbox(cmd string, tmpDir string) string {
	// Re-map /tmp writes to isolated sandbox tmpDir
	cmd = strings.ReplaceAll(cmd, "/tmp/", tmpDir+"/")
	// Turn dangerous network execution into simulated execution
	if strings.Contains(cmd, "curl") || strings.Contains(cmd, "wget") {
		return "echo '[sandbox mock download]' > " + tmpDir + "/downloaded_payload"
	}
	if strings.Contains(cmd, "nc ") || strings.Contains(cmd, "/dev/tcp/") || strings.Contains(cmd, "socket") || strings.Contains(cmd, "nmap") {
		return "echo '[sandbox mock net connection]'"
	}
	if strings.Contains(cmd, "sh -i") || strings.Contains(cmd, "bash -i") || strings.Contains(cmd, "python") {
		return "echo '[sandbox mock script exec]'"
	}
	if strings.Contains(cmd, "rm ") || strings.Contains(cmd, "cron") || strings.Contains(cmd, "authorized_keys") {
		return "echo '[sandbox mock system mod]'"
	}
	return cmd
}
