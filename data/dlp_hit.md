---
title: "DLP hit — sensitive content in motion"
subtitle: "Classified or regulated data detected in outbound channel"
category: data
authored: 2025-05-30
match_signals:
  - dlp.pii
  - dlp.source_code
  - dlp.financial
danger_policy:
  "action:high": approval
  "action:medium": auto
  "action:low": auto
review_cadence: 90d
scope: tenant
tags:
  - data-exfil
  - dlp
  - compliance
---
# DLP hit

/review: what was the matched content
/enrichment: user context
  system: workday
  user:   {{entity.user}}
  fields: team, role, manager

/decision: is this a legitimate business process?
  options:
    - yes — routine (attach change-ticket)
    - no — policy violation
    - unclear — escalate to manager

/action: quarantine the message / upload
  kind:   dlp.quarantine
  target: {{entity.event_id}}
  danger: low
