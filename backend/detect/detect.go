// Package detect is the deterministic, LLM-free rule engine. Rules are
// detection-as-code (JSON under /rules), versioned and testable. A rule matches
// a single normalized event; multi-event behavior is the correlation engine's
// job, not the detector's.
package detect

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"

	"sentinelx/backend/correlate"
)

// Rule is one detection, loaded from a .json file in /rules. Fields group by
// which event types they're meaningful for: ImageRegex/CmdlineRegex/
// CmdlineContains/PathPrefix match the acting process (process_start and,
// where set, any event type); FilePathRegex matches the object path on
// file_write/file_read/module_load; DNSRegex matches the queried name on
// dns_query; RemotePorts matches the destination port on net_connect.
type Rule struct {
	ID              string   `json:"id"`
	Version         string   `json:"version"`
	Technique       []string `json:"technique"`
	Severity        int      `json:"severity"`
	EventType       string   `json:"event_type"`       // matches correlate.EventType
	ImageRegex      string   `json:"image_regex"`      // matches ProcImage
	CmdlineRegex    string   `json:"cmdline_regex"`    // matches Cmdline
	CmdlineContains []string `json:"cmdline_contains"` // all substrings must be present
	PathPrefix      string   `json:"path_prefix"`      // ProcImage prefix (e.g. /tmp/)
	FilePathRegex   string   `json:"file_path_regex"`  // matches the event's FilePath
	DNSRegex        string   `json:"dns_regex"`        // matches the event's DNSName
	RemotePorts     []int    `json:"remote_ports"`     // matches the event's RemotePort
	Remediation     string   `json:"remediation"`      // analyst-facing "how to fix this" guidance
}

type compiled struct {
	Rule
	imageRe    *regexp.Regexp
	cmdRe      *regexp.Regexp
	filePathRe *regexp.Regexp
	dnsRe      *regexp.Regexp
}

// Engine evaluates rules against events and assigns unique detection ids.
type Engine struct {
	mu     sync.Mutex
	rules  []compiled
	nextID int64
}

// NewEngine compiles a set of rules.
func NewEngine(rs []Rule) (*Engine, error) {
	e := &Engine{}
	for _, r := range rs {
		c := compiled{Rule: r}
		if r.ImageRegex != "" {
			re, err := regexp.Compile(r.ImageRegex)
			if err != nil {
				return nil, fmt.Errorf("rule %s image_regex: %w", r.ID, err)
			}
			c.imageRe = re
		}
		if r.CmdlineRegex != "" {
			re, err := regexp.Compile(r.CmdlineRegex)
			if err != nil {
				return nil, fmt.Errorf("rule %s cmdline_regex: %w", r.ID, err)
			}
			c.cmdRe = re
		}
		if r.FilePathRegex != "" {
			re, err := regexp.Compile(r.FilePathRegex)
			if err != nil {
				return nil, fmt.Errorf("rule %s file_path_regex: %w", r.ID, err)
			}
			c.filePathRe = re
		}
		if r.DNSRegex != "" {
			re, err := regexp.Compile(r.DNSRegex)
			if err != nil {
				return nil, fmt.Errorf("rule %s dns_regex: %w", r.ID, err)
			}
			c.dnsRe = re
		}
		e.rules = append(e.rules, c)
	}
	return e, nil
}

// Load reads every *.json rule file in dir and compiles them.
func Load(dir string) (*Engine, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	var rs []Rule
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var r Rule
		if err := json.Unmarshal(b, &r); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		rs = append(rs, r)
	}
	return NewEngine(rs)
}

// Eval returns every detection the event triggers.
func (e *Engine) Eval(ev correlate.Event) []correlate.Detection {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []correlate.Detection
	for _, r := range e.rules {
		if !r.match(ev) {
			continue
		}
		e.nextID++
		out = append(out, correlate.Detection{
			ID:          e.nextID,
			TenantID:    ev.TenantID,
			RuleID:      r.ID,
			RuleVer:     r.Version,
			HostID:      ev.HostID,
			ProcGUID:    ev.ProcGUID,
			EventIDs:    []string{ev.ID},
			Technique:   r.Technique,
			Severity:    r.Severity,
			TS:          ev.TS,
			DedupKey:    r.ID + "|" + ev.ProcGUID,
			Remediation: r.Remediation,
		})
	}
	return out
}

// Techniques returns the distinct MITRE techniques the ruleset covers (feeds the
// CI coverage report).
func (e *Engine) Techniques() []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range e.rules {
		for _, t := range r.Technique {
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	return out
}

func (r compiled) match(ev correlate.Event) bool {
	if r.EventType != "" && string(ev.Type) != r.EventType {
		return false
	}
	if r.imageRe != nil && !r.imageRe.MatchString(ev.ProcImage) {
		return false
	}
	if r.PathPrefix != "" && !strings.HasPrefix(ev.ProcImage, r.PathPrefix) {
		return false
	}
	for _, s := range r.CmdlineContains {
		if !strings.Contains(ev.Cmdline, s) {
			return false
		}
	}
	if r.cmdRe != nil && !r.cmdRe.MatchString(ev.Cmdline) {
		return false
	}
	if r.filePathRe != nil && !r.filePathRe.MatchString(ev.FilePath) {
		return false
	}
	if r.dnsRe != nil && !r.dnsRe.MatchString(ev.DNSName) {
		return false
	}
	if len(r.RemotePorts) > 0 && !slices.Contains(r.RemotePorts, ev.RemotePort) {
		return false
	}
	return true
}

// Default returns the built-in v1 ruleset in code — identical to /rules/*.json —
// so tests and the demo run without a rules directory on disk.
func Default() []Rule {
	return []Rule{
		{
			ID: "lolbin_curl_download", Version: "1", Technique: []string{"T1105"}, Severity: 65,
			EventType: "process_start", ImageRegex: `(curl|wget)$`, CmdlineContains: []string{"http"},
			Remediation: "Confirm whether this download was operator-initiated (e.g. a package update). If not: isolate the host, kill the process tree rooted at the reported process, and block the destination IP/domain at the firewall. Check the downloaded path (see the file_write event in this investigation) for a match against threat intel before executing or opening it.",
		},
		{
			ID: "chmod_then_exec", Version: "1", Technique: []string{"T1222.002"}, Severity: 55,
			EventType: "process_start", ImageRegex: `chmod$`, CmdlineContains: []string{"+x"},
			Remediation: "A file had its execute bit set right before running. Identify the target path from the command line, verify it against a known-good binary inventory, and quarantine it if unrecognized. Review the parent process for how the file arrived (download, extraction, write).",
		},
		{
			ID: "exec_from_tmp", Version: "1", Technique: []string{"T1204.002", "T1059.004"}, Severity: 70,
			EventType: "process_start", PathPrefix: "/tmp/",
			Remediation: "Executables should not normally run from /tmp. Kill the process, capture the binary for analysis before it's cleaned up, and check for a persistence mechanism (cron, systemd unit, shell profile) referencing this path. Mount /tmp with noexec where the workload allows it.",
		},
		{
			ID: "reverse_shell_pattern", Version: "1", Technique: []string{"T1059.004", "T1071.001"}, Severity: 90,
			EventType: "process_start", CmdlineRegex: `(bash\s+-i|nc\s+-e|/dev/tcp/|python[0-9.]*\s+-c\s+.*socket)`,
			Remediation: "This command line matches a classic reverse-shell one-liner. Kill the process immediately, isolate the host from the network, and identify the destination address it was connecting to (check the next net_connect event in this investigation). Treat the host as compromised until proven otherwise.",
		},
		{
			ID: "base64_decode_exec", Version: "1", Technique: []string{"T1027", "T1140"}, Severity: 65,
			EventType: "process_start", CmdlineRegex: `base64\s+(-d|--decode)`,
			Remediation: "Decoding base64 into a shell or interpreter is a common way to hide a payload from simple string-matching defenses. Recover the decoded content from the command line, inspect it, and check what process consumed the output.",
		},
		{
			ID: "history_clearing", Version: "1", Technique: []string{"T1070.003"}, Severity: 55,
			EventType: "process_start", CmdlineRegex: `(history\s+-c|unset\s+HISTFILE|rm\s+-f.*bash_history)`,
			Remediation: "Command-history clearing is an anti-forensics step, usually following other malicious activity. Review this session's full process lineage for what happened just before the clear, and check for other hosts touched by the same account.",
		},
		{
			ID: "suid_bit_set", Version: "1", Technique: []string{"T1548.001"}, Severity: 75,
			EventType: "process_start", ImageRegex: `chmod$`, CmdlineRegex: `(\+s|u\+s|4[0-7]{3})`,
			Remediation: "Setting the SUID bit on a binary is a common local-privilege-escalation technique. Identify the target file from the command line and check whether it's an expected system binary or something recently dropped. Remove the SUID bit if unauthorized.",
		},
		{
			ID: "network_scanner_exec", Version: "1", Technique: []string{"T1046"}, Severity: 50,
			EventType: "process_start", ImageRegex: `(nmap|masscan)$`,
			Remediation: "Network scanning tools indicate discovery activity, either legitimate (an authorized scan) or an attacker mapping the network. Confirm with the operator on record; if unauthorized, isolate the host and check what ranges/ports it scanned.",
		},
		{
			ID: "pipe_to_shell_install", Version: "1", Technique: []string{"T1195.001", "T1105"}, Severity: 70,
			EventType: "process_start", CmdlineRegex: `(curl|wget).*\|\s*(bash|sh)\b`,
			Remediation: "Piping a downloaded script directly into a shell executes untrusted, unreviewed code immediately on download. Recover the source URL from the command line and check it against threat intel. Prefer download-then-inspect-then-run for any real install workflow.",
		},
		{
			ID: "ssh_authorized_keys_write", Version: "1", Technique: []string{"T1098.004"}, Severity: 80,
			EventType: "file_write", FilePathRegex: `authorized_keys$`,
			Remediation: "A write to an authorized_keys file can grant persistent SSH access. Diff the file against its last known-good version, remove any unrecognized public keys, and identify the process that wrote it.",
		},
		{
			ID: "passwd_shadow_write", Version: "1", Technique: []string{"T1003.008", "T1098"}, Severity: 85,
			EventType: "file_write", FilePathRegex: `/etc/(passwd|shadow)$`,
			Remediation: "Direct writes to /etc/passwd or /etc/shadow outside of standard user-management tools (useradd, passwd, chpasswd) are a strong signal of account tampering. Diff against the last backup and check for newly added or modified accounts.",
		},
		{
			ID: "cron_persistence_write", Version: "1", Technique: []string{"T1053.003"}, Severity: 70,
			EventType: "file_write", FilePathRegex: `(/etc/cron\.(d|daily|hourly|weekly)/|/var/spool/cron/)`,
			Remediation: "A new or modified cron entry is a common persistence mechanism. Read the written file's contents (from the file_write event) and check what command it schedules; remove it if unauthorized and identify the writing process's origin.",
		},
		{
			ID: "webshell_drop", Version: "1", Technique: []string{"T1505.003"}, Severity: 85,
			EventType: "file_write", FilePathRegex: `/(www|htdocs|public_html)/.*\.(php|jsp|jspx|asp|aspx)$`,
			Remediation: "A script file was written into a web root — a common webshell drop pattern. Quarantine the file immediately, review it for command-execution code, and check the web server's access logs for the request that triggered the write.",
		},
		{
			ID: "credential_file_read", Version: "1", Technique: []string{"T1552.001"}, Severity: 70,
			EventType: "file_read", FilePathRegex: `(\.ssh/id_[rd]sa$|\.aws/credentials$|/etc/shadow$)`,
			Remediation: "A credential file was read by a process. Confirm the reading process is an expected tool (ssh-agent, aws-cli) run by the file's owner; if not, treat the credential as compromised and rotate it.",
		},
		{
			ID: "suspicious_c2_port", Version: "1", Technique: []string{"T1571"}, Severity: 60,
			EventType: "net_connect", RemotePorts: []int{4444, 1337, 31337, 6667, 4443, 8888},
			Remediation: "This destination port is commonly used by post-exploitation frameworks and IRC-based C2, and is unusual for normal application traffic. Confirm the destination is expected; if not, block it at the firewall and isolate the host.",
		},
		{
			ID: "dns_tunneling_provider", Version: "1", Technique: []string{"T1071.004"}, Severity: 55,
			EventType: "dns_query", DNSRegex: `\.(ngrok\.io|trycloudflare\.com|duckdns\.org|no-ip\.(org|com))$`,
			Remediation: "This DNS name belongs to a free dynamic-DNS or tunneling provider commonly abused for C2 callback and data exfiltration. Confirm the resolving process is an expected tool; if not, block the domain and inspect the connection it establishes next.",
		},
		{
			ID: "suspicious_kernel_module_load", Version: "1", Technique: []string{"T1547.006"}, Severity: 85,
			EventType: "module_load", FilePathRegex: `^/(tmp|dev/shm|home)/`,
			Remediation: "Kernel modules should load from /lib/modules, not a world-writable path. This is a strong rootkit/persistence indicator. Isolate the host immediately — a module loaded from here has full kernel privileges — and capture the module file for analysis before it can be deleted.",
		},
	}
}
