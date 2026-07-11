# ADR-0003: Linux-first eBPF agent (Windows second)

Status: accepted · Date: 2026-07-08 (supersedes the initial Windows-first lean)

## Context
The correlation core is OS-agnostic; only collection is platform-specific. The
team is strong in Go, develops on Linux, and has no Windows-kernel experience.
The original plan led with Windows because the flagship demo (encoded
PowerShell/LOLBin) is Windows-native.

## Decision
Lead with a **Linux eBPF (CO-RE) agent, user-mode, no kernel module**. Windows
(ETW + Sysmon) is the second collector behind the same `Collector` interface.

Rationale: eBPF develops natively on the team's box, needs no Windows VM, and
still avoids a shipped kernel driver (programs are verifier-checked and loaded at
runtime). The demo scenario becomes the Linux analog — ingress-tool-transfer +
exec-from-tmp (`curl`→`/tmp/payload`→`chmod +x`→exec→C2), Atomic Red Team
T1105/T1222.002/T1204.002/T1059.004.

## The one real Linux nuance
Linux has no Sysmon `ProcessGuid`. The agent synthesizes a stable process key:
`hash(boot_id, pid, start_time_ticks)` (`normalize.ProcGUID`). `[VERIFY: start
time source — task->start_time via BPF, or /proc/<pid>/stat field 22]`.

## Hook mapping `[VERIFY per target kernel]`
| event | hook |
|---|---|
| process_start/stop | `sched_process_exec` / `sched_process_exit` |
| file_write/read | BPF-LSM `file_open` (CONFIG_BPF_LSM) or VFS kprobe fallback |
| net_connect | `tcp_connect` kprobe / `cgroup/connect4` |
| dns_query | UDP :53 heuristic in v1; `getaddrinfo` uprobe later |
| module_load | `init_module` / `finit_module` |

Fallback collector: **auditd** for kernels without BPF-LSM, same interface.

## Consequences
- Fast native iteration; Windows parity is additive, not a rewrite.
- Risk: eBPF portability across kernels. Mitigated by CO-RE + auditd fallback.
