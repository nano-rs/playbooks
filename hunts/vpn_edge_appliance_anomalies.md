---
kind: hunt
title: "The boxes at the edge that everyone trusts and nobody watches"
subtitle: "VPN sessions that don't fit their user, admin-plane changes on the appliances themselves, and the telemetry gaps that keep edge intrusions invisible"
category: network
owner: "team · soc-leads"
authored: 2026-08-03
schedule: "30 10 * * *"
timezone: "UTC"
lookback_window: 24h
telemetry:
  all_of:
    - network.vpn
  optional:
    - network.edge_admin
    - network.connection
mitre_tactic: initial-access
mitre_technique: T1133
budget:
  max_turns: 40
  max_tool_calls: 120
  max_rows: 6000
  max_wall_seconds: 900
tags:
  - network
  - vpn
  - edge
  - remote-access
---
# The boxes at the edge that everyone trusts and nobody watches

**Hypothesis:** the estate's edge appliances are its most attacked and least observed machines — a rolling parade of exploited CVEs, credentials replayed from infostealer logs, and admin planes reachable from places they should never be. Two hunts live in their logs: sessions that do not fit the user who owns them, and changes to the *appliance itself* — and a third finding hides underneath, because thin edge telemetry is precisely how these intrusions stay invisible, and thinness is measurable.

## Sessions that do not fit their owner

/query: VPN authentications deviating from each user's own profile
  window: 24h
  from:   vpn_logs
  note:   "The sign-in hunt's doctrine applied at the tunnel: new geo, new
           ASN, new client fingerprint, impossible-travel pairs, and
           always against the user's OWN history. Two edge-specific
           shapes deserve extra weight: concurrent sessions for one user
           from distant networks — tunnels persist, so overlap is
           legible — and successful logons WITHOUT the posture or MFA
           step the estate's clients normally produce, which is what
           replayed credentials and session hijacks look like from here."

/query: what the tunnel touched after connecting
  note:   "A legitimate user lands and goes to their usual few systems; a
           replayed credential lands and goes exploring. First-seen
           internal destinations per VPN user, scanning shapes from
           VPN-assigned addresses, and RDP/SMB fan-out from the VPN pool
           join this hunt to the lateral-movement hunt's census — an
           edge session whose interior behaviour is also new is one lead,
           not two."

## The appliance as the victim

/query: administrative logons and configuration changes on the appliances
  note:   "Config writes, new local accounts, auth-policy edits, cert and
           key changes, firmware operations — from whom and from WHERE.
           Admin reachable from the WAN side is a finding even with a
           legitimate actor; a new local account on an edge box is close
           to a tripwire, since real estates manage edge auth centrally
           and local accounts are exactly what appliance-CVE exploitation
           leaves behind."

/query: appliance behaviour consistent with exploitation
  note:   "Unexpected reboots or crashes followed shortly by config
           changes, logging settings modified, unfamiliar processes or
           debug modes where the platform exposes them. The
           crash-then-change sequence is the classic post-exploit
           footprint on edge gear — each half is dismissible, the
           sequence is not."

## The gap is also a finding

/baseline: what these appliances CAN log versus what they are sending
  note:   "Edge boxes routinely send auth logs and nothing else — no
           config-change audit, no local-account events — and that
           silence gets read as health. Compare received event types
           against the platform's capability, the environment-recon
           discipline applied to one source class. If the admin-plane
           sections above are running blind, the sweep narrative must
           say so explicitly: an unwatchable edge is a risk finding in
           its own right, not a clean sweep."

## Rule out the boring explanation

/enrichment: NOC maintenance windows, egress changes, and roaming context
  note:   "Network teams do config pushes in windows from jump hosts, and
           sales teams do authenticate from four countries in a week.
           The maintenance carve is actor-plus-window-plus-source; the
           roaming carve is the user's own travel cadence. A config
           change that is IN a window but from a first-seen source
           network fails the carve on the axis that matters."

## Emit

/lead: edge session or appliance change outside its owner's pattern
  entity: host
  note:   "Evidence carries the session or change events, the owner's
           baseline beside the deviation, the interior-behaviour trail
           for sessions, and the capability-versus-received telemetry
           statement when it limited the sweep. For appliance-side leads,
           recommend checking the vendor's current KEV/advisory state in
           the narrative — edge findings age in days, and the reader
           should know if this box's platform is this month's campaign."
