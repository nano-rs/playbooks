---
title: "Unusual outbound data transfer"
subtitle: "Volume or destination deviates from baseline · possible exfiltration"
category: data
authored: 2025-07-25
match_signals:
  - egress.anomaly
  - dlp.high_volume
danger_policy:
  "action:high": approval
  "action:medium": auto
  "action:low": auto
review_cadence: 90d
scope: tenant
tags:
  - data-exfil
  - egress
  - network
---
# Unusual outbound transfer

/query: outbound bytes per destination in 24h
  window: 24h
  from:   network-flows
  where:  src = {{entity.host}}
  group:  by dst_domain
  show:   bytes_out

/enrichment: destination reputation
  services: passivedns, whois
  target: {{entity.dst_domain}}

/decision: is the destination a known corporate tool (SaaS, backup)?
  options: [yes, no, unclear]

/action: block destination at egress
  kind:   firewall.block_domain
  target: {{entity.dst_domain}}
  danger: medium
  require_approval: true
