---
title: "DNS tunneling — high entropy subdomains"
subtitle: "Covert channel via oversized or encoded DNS queries"
category: network
authored: 2025-04-22
match_signals:
  - dns.tunneling
  - dns.high_entropy
danger_policy:
  "action:high": approval
  "action:medium": auto
  "action:low": auto
review_cadence: 90d
scope: tenant
tags:
  - network
  - dns
  - tunneling
---
# DNS tunneling

/query: DNS queries to this domain by entropy + length
  window: 12h
  from:   dns-logs
  where:  qname ~ {{entity.domain}}
  show:   qname, qlen, entropy

/enrichment: domain metadata
  services: whois, passivedns
  target: {{entity.domain}}

/action: sinkhole resolver
  kind:   dns.sinkhole
  target: {{entity.domain}}
  danger: medium
