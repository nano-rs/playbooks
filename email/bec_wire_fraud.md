---
title: "BEC — wire fraud / invoice redirect"
subtitle: "Executive impersonation or invoice tampering · notify finance · preserve evidence"
category: email
authored: 2025-09-28
match_signals:
  - bec.wire
  - ceo_impersonation
danger_policy:
  "action:high": approval
  "action:medium": auto
  "action:low": auto
review_cadence: 90d
scope: tenant
tags:
  - email
  - bec
  - fraud
---
# BEC · wire fraud

/review: preserve original message + headers (do not delete)

/enrichment: sender authentication details
  from:   mail-security
  message: {{entity.msg_id}}

/query: previous communication history between these parties
  window: 90d
  from:   mail-metadata
  where:  (sender = {{entity.sender}} AND recipient = {{entity.victim}}) OR (sender = {{entity.victim}} AND recipient = {{entity.sender}})

/action: notify finance — halt any in-flight wires
  kind:   page.create
  target: finance-oncall
  danger: low

/action: open case with legal + fraud
  kind:   ticket.create
  target: legal-fraud-queue

/decision: was money transferred?
  options: [yes, no, unknown]
  note_required_on: yes
