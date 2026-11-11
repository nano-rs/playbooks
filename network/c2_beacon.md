---
title: "C2 beacon — periodic outbound to suspicious host"
subtitle: "Low-volume, regular interval callouts matching beaconing signature"
category: network
authored: 2025-09-08
match_signals:
  - network.beacon
  - dns.dga
danger_policy:
  "action:high": approval
  "action:medium": auto
  "action:low": auto
review_cadence: 90d
scope: tenant
tags:
  - network
  - c2
  - beacon
---
# C2 beacon

/query: outbound connections by interval
  window: 24h
  from:   network-flows
  where:  class_uid = 4001 AND device.hostname = {{entity.host}}
  group:  by dst_endpoint.ip, interval
  note:   "looking for tight jitter around a fixed period"

/enrichment: TI on destination
  services: virustotal, otx
  target: {{entity.dst_ip}}

/action: sinkhole + isolate
  kind:   firewall.sinkhole
  target: {{entity.dst_ip}}
  danger: medium

/action: isolate host
  kind:   edr.isolate
  target: {{entity.host}}
  danger: high
  require_approval: true
