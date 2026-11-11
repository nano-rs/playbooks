---
title: "Login spray — multi-tenant / multi-user"
subtitle: "Low-and-slow distributed login attempts across many accounts from related infra"
category: identity
owner: "team · soc-leads"
authored: 2025-10-19
match_signals:
  - auth-burst-v2
  - password_spray
  - ASN.spray
danger_policy:
  "action:high": approval
  "action:medium": auto
  "action:low": auto
review_cadence: 90d
scope: tenant
tags:
  - identity
  - password-spray
  - firewall
---
# Login spray · multi-tenant

Coordinated auth failures across users and tenants, usually from a rented botnet. Goal: confirm pattern, flag any successes, and push firewall rules.

/query: spray shape — failures per /24 per user per minute
  window: 4h
  from:   auth-events
  where:  class_uid = 3002 AND status_id = 2
  group:  by src_endpoint.ip /24, user.name, minute
  limit:  200

/pivot: any successes from the same source block
  from:   auth-events
  where:  class_uid = 3002 AND status_id = 1 AND src_endpoint.ip IN {{entity.src_ip_24_set}}
  note:   "any row here is an immediate escalation; the set holds CIDR blocks such as 203.0.113.0/24, which src_endpoint.ip matches directly"

/enrichment: ASN + hosting reputation
  services: greynoise, asnlookup
  values: {{entity.src_ip_24_set}}

/decision: any successful login from the source block?
  options: [yes — successful auth, no — failures only]
  note_required_on: yes — successful auth

/action: propose firewall block for the implicated /24s
  kind:   firewall.block_proposal
  target: {{entity.src_ip_24_set}}
  danger: medium
  require_approval: true

/action: notify affected tenants if > 3 tenants impacted
  kind:   customer.comms_draft
  template: customer-update.password-spray
  danger: low
