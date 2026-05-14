// Package correlate turns a stream of provenance detections into a small number
// of investigations by grouping causally-related events on a per-host
// provenance graph.
//
// The engine is deterministic and OS-agnostic: it consumes normalized Events
// (see types.go) that a Linux eBPF collector or a Windows ETW/Sysmon collector
// both produce. The v1 collector target is Linux eBPF (CO-RE); see
// docs/design/correlation.md for the platform mapping.
//
// It defends against dependency explosion — the failure mode where a
// long-lived, high-degree process (systemd, sshd) or a common object node
// (/usr/bin/curl executed by everything) bridges unrelated activity and every
// investigation collapses into one blob — with two boundary mechanisms:
//
//  1. Hub termination: a node whose out-degree (a high-fanout process like
//     systemd/sshd) or in-degree (a binary executed by many processes) exceeds
//     Params.HubDegree is a hub. Traversal settles it as a boundary but does
//     not expand through it, and boundary nodes never contribute membership.
//  2. Rarity boundary: an edge whose learned rarity weight is below
//     Params.CommonWeight is "common". A common edge is settled as a boundary
//     too — two investigations are never merged across a common edge.
//
// Merges are driven by rare causal edges (a write-then-exec of /tmp/payload)
// and by shared process lineage roots. See correlator.go.
package correlate
