---
title: "Lateral movement — SMB / RDP / WinRM"
subtitle: "Authenticated movement between hosts beyond normal pattern"
category: network
authored: 2025-06-18
match_signals:
  - lateral.smb
  - lateral.rdp
danger_policy:
  "action:high": approval
  "action:medium": auto
  "action:low": auto
review_cadence: 90d
scope: tenant
tags:
  - network
  - lateral-movement
  - smb
  - rdp
---
# Lateral movement

/query: every authenticated session from this host in 8h
  window: 8h
  from:   edr-network
  where:  class_uid = 4001 AND device.hostname = {{entity.host}} AND dst_endpoint.port IN (445, 3389, 5985, 5986)

/pivot: each destination host — what's been touched
  from:   edr-filesystem
  where:  class_uid = 1001 AND device.hostname IN {{entity.dst_hosts}} AND timestamp > {{event.ts}}

/decision: are any of the destinations domain controllers or tier-0?
  options: [yes, no]

/action: isolate source + all touched destinations
  kind:   edr.isolate_many
  target: {{entity.host_set}}
  danger: high
  require_approval: true
