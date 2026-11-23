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
hypothesis: "An estate's east-west graph is a habit, so an intruder spreading from a foothold draws new lines on it with the protocols administration uses: one account authenticating over the network to many hosts, one source reaching many internal peers on RDP / SMB / SSH / WinRM, and remote-execution parents (services.exe, wmiprvse.exe, wsmprovhost.exe) starting shells on the destinations. The benign twin is a scanner, patching server or jump host that legitimately reaches everywhere, every day."
risk_weight: 7
default_severity: high
pivots:
  - name: lateral_telemetry_census
    role: coverage
    query: 'class_uid IN (3002, 1007, 4001) | stats count by class_uid, source_type'
  - name: account_network_logon_fanout
    role: discovery
    query: 'class_uid=3002 activity_id=1 status_id=1 logon_type_id IN (3, 10) dst_endpoint.hostname=* | stats dc(dst_endpoint.hostname) AS target_hosts, count AS logons, values(dst_endpoint.hostname) AS targets, values(logon_type_id) AS logon_types, min(timestamp) AS first_seen, max(timestamp) AS last_seen by user.name, src_endpoint.ip | where target_hosts >= 3 | sort -target_hosts | head 200'
    scorer:
      method: zscore
      field: target_hosts
      threshold: 2
  - name: admin_protocol_peer_fanout
    role: discovery
    query: 'class_uid=4001 dst_endpoint.port IN (22, 135, 445, 3389, 5985, 5986) | where is_private_ip(dst_endpoint.ip) | stats dc(dst_endpoint.ip) AS peers, count AS connections, values(dst_endpoint.port) AS ports, min(timestamp) AS first_seen, max(timestamp) AS last_seen by src_endpoint.ip | where peers >= 5 | sort -peers | head 200'
    scorer:
      method: iqr
      field: peers
      threshold: 3
  - name: remote_execution_children
    role: discovery
    query: 'class_uid=1007 ((process.parent_process.name IN ("services.exe", "wmiprvse.exe", "wsmprovhost.exe") process.name IN ("cmd.exe", "powershell.exe", "pwsh.exe", "rundll32.exe", "mshta.exe", "regsvr32.exe")) OR process.name IN ("psexesvc.exe", "paexec.exe", "remcomsvc.exe")) | stats count, dc(process.cmd_line) AS distinct_cmds, values(process.cmd_line) AS cmds, values(actor.user.name) AS users, min(timestamp) AS first_seen, max(timestamp) AS last_seen by device.hostname, process.parent_process.name, process.name | sort -count | head 200'
budget:
  max_turns: 40
  max_tool_calls: 120
  max_rows: 6000
  max_wall_seconds: 2700
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
  note:   "Within the sweep window, account_network_logon_fanout (Authentication
           3002, network and RDP logons per user.name and src_endpoint.ip to
           distinct dst_endpoint.hostname) and admin_protocol_peer_fanout
           (Network Activity 4001 per src_endpoint.ip to distinct private
           dst_endpoint.ip on admin ports) already measure the fan-out; they
           do not know which edges are NEW against the 30d census, so check
           the candidates against it.

           New edges happen legitimately every day — one new edge is a weak
           lead at best. Shape matters: one source growing MANY new edges in
           a window is fan-out; a CHAIN of new edges (A→B, then B→C within
           hours) is traversal, and chains outrank stars."

## What rode the edges

/query: remote-execution markers on the destination hosts
  note:   "The remote_execution_children pivot already lists shells started
           by services.exe, wmiprvse.exe and wsmprovhost.exe, and PsExec-style
           service binaries, per device.hostname.

           Service installs from remote sources, WinRM shells, task
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
