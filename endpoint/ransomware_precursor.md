---
title: "Ransomware precursor — shadow copy deletion, bulk file rename"
subtitle: "Early-stage ransomware indicators · act fast"
category: endpoint
owner: "team · soc-leads"
authored: 2025-07-11
match_signals:
  - vssadmin.delete
  - file.bulk_rename
  - ransomware.precursor
danger_policy:
  "action:high": auto
  "action:medium": auto
  "action:low": auto
review_cadence: 90d
scope: tenant
tags:
  - endpoint
  - ransomware
  - ir
---
# Ransomware precursor

**Treat as active IR until disproven.** Run these in parallel; isolate first, ask questions after.

/action: isolate host immediately
  kind:   edr.isolate
  target: {{entity.host}}
  danger: high
  reversible: true
  require_approval: false
  note: "standing authorization per playbook policy"

/query: every process spawned by this host in the last hour
  window: 1h
  from:   edr-telemetry
  where:  host = {{entity.host}}

/pivot: lateral — any SMB or RDP from this host in 4h?
  from:   edr-network
  where:  host = {{entity.host}} AND proto IN (smb, rdp)

/action: page on-call IR lead
  kind:   page.create
  target: ir-oncall
  danger: low
