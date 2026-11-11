---
title: "Persistence mechanism — scheduled task / service / startup"
subtitle: "Attacker footprint on the box — find it, document it, remove it"
category: endpoint
authored: 2025-06-04
match_signals:
  - persistence.scheduled
  - registry.run_key
  - service.create
danger_policy:
  "action:high": approval
  "action:medium": auto
  "action:low": auto
review_cadence: 90d
scope: tenant
tags:
  - endpoint
  - persistence
---
# Persistence mechanism

/query: new scheduled tasks, services, run-keys in 7d
  window: 7d
  from:   edr-telemetry
  where:  device.hostname = {{entity.host}} AND (class_uid IN (1006, 201004) OR (class_uid IN (201001, 201002) AND (reg_key.path = "*\\CurrentVersion\\Run*" OR reg_value.path = "*\\CurrentVersion\\Run*")))
  note:   "1006 is Scheduled Job Activity, 201004 Windows Service Activity (service installs), 201001/201002 registry key/value changes"

/review: compare against known-good baseline
/decision: is the persistence mechanism legitimate?
  options: [yes, no, unclear]

/action: remove artifact + document
  kind:   edr.remediate
  target: {{entity.artifact_id}}
  danger: medium
