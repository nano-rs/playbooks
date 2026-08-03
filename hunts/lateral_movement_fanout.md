---
kind: hunt
title: "A host reaching peers it has never spoken to, the way admins do"
subtitle: "New host-to-host edges over RDP/SMB/SSH/WinRM, remote execution markers, and tool transfer riding the new paths"
category: network
owner: "team · soc-leads"
authored: 2026-08-03
schedule: "0 5 * * *"
timezone: "UTC"
lookback_window: 24h
telemetry:
  all_of:
    - identity.authentication
    - endpoint.process
  optional:
    - network.connection
mitre_tactic: lateral-movement
mitre_technique: T1021
budget:
  max_turns: 40
  max_tool_calls: 120
  max_rows: 6000
  max_wall_seconds: 900
tags:
  - network
  - lateral-movement
  - remote-execution
---
# A host reaching peers it has never spoken to, the way admins do

**Hypothesis:** an estate's east–west graph is a habit. Workstations talk to servers, servers talk to their dependencies, and the edges barely change from month to month — so an intruder spreading from a foothold must draw new lines on that graph, using exactly the protocols administration uses. The individual connection is invisible; the new edge, the fan-out, and the account riding it are not.

## The graph and its new edges

/baseline: per-host set of east–west destinations by protocol
  window: 30d
  note:   "RDP, SMB, SSH, WinRM — the admin protocols, because that is what
           movement wears. Build the edge census per protocol: a host that
           has talked SMB to a file server for a year growing a first RDP
           edge is a new line even though the peers already knew each other."

/query: connections whose host→host edge is absent from the census
  window: 24h
  from:   windows_security
  note:   "New edges happen legitimately every day — one new edge is a weak
           lead at best. Shape matters: one source growing MANY new edges in
           a window is fan-out; a CHAIN of new edges (A→B, then B→C within
           hours) is traversal, and chains outrank stars."

## What rode the edges

/query: remote-execution markers on the destination hosts
  note:   "Service installs from remote sources, WinRM shells, task
           registrations, the psexec/wmiexec texture. A new edge that
           carries execution is a different object from a new edge that
           carried a file browse — the census finds candidates, this step
           ranks them."

/query: file writes to admin shares followed by execution on the destination
  note:   "Tool transfer is the tell that movement is staged: a binary landing
           on ADMIN$ or C$ and running within minutes was not delivered for
           storage. Hash the transferred file and check its estate
           prevalence while here."

/pivot: the account authenticating across the new edges
  note:   "One account on many new edges is the pivot that matters most —
           moving laterally means logging in laterally. Cross-check the
           account's own profile: a service account suddenly minting RDP
           edges belongs to this lead AND to the interactive-logon hunt's
           story."

## Rule out the boring explanation

/enrichment: is the source a scanner, jump host, or newly commissioned admin box
  note:   "Vulnerability scanners and patching infrastructure are the two
           great fan-out factories, and every estate has a jump-host
           population that legitimately reaches everywhere. These are
           knowable, small sets — check membership, and treat a NEW member
           of the fan-out club as its own question: new scanners get
           commissioned, but so do staging boxes."

## Emit

/lead: new east–west edges with execution or transfer riding them
  entity: host
  note:   "Evidence carries the edge list with first-seen facts, the timeline
           across hops, the executing account, and any transferred binaries
           with hashes. Draw the chain explicitly — A to B to C with times —
           because the chain is what the reader must either break or chase,
           and a flat list of edges hides it."
