---
kind: hunt
title: "More data leaving than the job explains"
subtitle: "Mass downloads from SharePoint/Exchange, staging shapes, and egress volume anomalies cross-referenced with DLP"
category: data
owner: "team · soc-leads"
authored: 2026-08-03
schedule: "0 4 * * *"
timezone: "UTC"
lookback_window: 24h
telemetry:
  one_of:
    - saas.data_export
    - network.web
    - network.connection
  optional:
    - endpoint.file
mitre_tactic: exfiltration
mitre_technique: T1567
hypothesis: "Exfiltration is a volume anomaly wearing legitimate credentials: a host pushing far more bytes to external addresses than its peers, uploads to a destination few other hosts use, or a user downloading or syncing many more distinct files from SharePoint, OneDrive or Drive than anyone else. The benign twins are legitimate bulk movers (backups, update and telemetry CDNs, legal exports, quarter-end finance, a leaver's mailbox archive) whose role, timing and destination fit an established rhythm."
risk_weight: 7
default_severity: medium
pivots:
  - name: egress_telemetry_census
    role: coverage
    query: 'class_uid IN (4001, 4002, 6006) | stats count, sum(traffic.bytes_out) AS bytes_out, dc(src_endpoint.ip) AS sources by class_uid, metadata.product.name | sort -count | head 50'
  - name: host_external_egress
    role: discovery
    query: 'class_uid=4001 traffic.bytes_out>0 dst_endpoint.ip NOT IN (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8) | stats sum(traffic.bytes_out) AS bytes_out, sum(traffic.bytes_in) AS bytes_in, count AS connections, dc(dst_endpoint.ip) AS destinations, values(src_endpoint.hostname) AS hostnames by src_endpoint.ip | sort -bytes_out | head 200'
    scorer:
      method: iqr
      field: bytes_out
      threshold: 3
  - name: upload_destinations
    role: discovery
    query: 'class_uid=4002 http_request.http_method IN ("POST","PUT") traffic.bytes_out>0 | stats sum(traffic.bytes_out) AS bytes_out, count AS requests, dc(src_endpoint.ip) AS estate_sources, values(src_endpoint.ip) AS source_ips by http_request.url.hostname | where estate_sources <= 3 | sort -bytes_out | head 200'
    scorer:
      method: zscore
      field: bytes_out
      threshold: 3
  - name: saas_bulk_downloads
    role: discovery
    query: 'class_uid=6006 activity_name IN ("Download","Sync") | stats count AS downloads, dc(file.path) AS distinct_files, dc(src_endpoint.ip) AS source_ips, values(metadata.product.name) AS platforms by actor.user.name | sort -distinct_files | head 200'
    scorer:
      method: zscore
      field: distinct_files
      threshold: 3
budget:
  max_turns: 40
  max_tool_calls: 120
  max_rows: 6000
  max_wall_seconds: 2700
tags:
  - data
  - exfiltration
  - insider
---
# More data leaving than the job explains

**Hypothesis:** exfiltration is a volume anomaly wearing legitimate credentials. Whether the hands belong to an intruder or a departing employee, the data has to move — through the collaboration platform, the browser, or the wire — and moving it leaves a per-person, per-host volume signature that their own history contradicts.

Volume alone convicts nobody. The hunt's job is to find the deviation, then check whether role, timing, and destination make it boring — and to say explicitly which of those checks was performed.

## Find the volume deviations

/query: per-user download and sync volumes from SharePoint and Exchange
  window: 24h
  from:   m365_audit
  note:   "Compare each user to their own trailing volume, not to the estate.
           Shapes worth ranking up: breadth (many sites or mailboxes touched
           for the first time), depth (a whole document library in one
           session), and mechanism shifts (a user who has only ever browsed
           suddenly bulk-syncing). The saas_bulk_downloads pivot measures distinct files downloaded or synced per user (File Hosting Activity 6006: actor.user.name, file.path) and flags outliers; it sees only the sweep window, so the user's own trailing history is still yours to fetch."

/query: per-host outbound byte volumes to non-CDN destinations
  window: 24h
  from:   squid_proxy
  note:   "Strip the destinations everyone uploads to as a matter of course —
           backup endpoints, update CDNs, telemetry sinks. What remains is
           small. Rank by destination rarity for the estate: personal cloud
           storage, transfer services, and never-before-seen domains beat raw
           byte counts. The host_external_egress pivot sums Network Activity traffic.bytes_out per src_endpoint.ip to non-private destinations; upload_destinations sums proxy POST / PUT bytes per http_request.url.hostname used by three or fewer sources."

## Corroborate

/enrichment: recent DLP hits for the flagged users and hosts
  note:   "The cross-reference is the point: DLP events are individually noisy
           and volume anomalies are individually ambiguous, but a user who
           tripped DLP on Monday and moved 4 GB on Tuesday is a different
           conversation. Absence of DLP hits is NOT clearance — plenty of
           valuable data matches no pattern."

/pivot: staging behaviour on the user's endpoint
  note:   "Bulk collection usually stages before it ships: archive creation,
           an unusual pile-up in a temp or personal directory, compression
           tools running under a user who never runs them. Where endpoint
           telemetry exists, the staging step turns two weak signals into one
           strong story; where it does not, say so."

## Rule out the boring explanation

/baseline: does the user's role involve bulk access, and is this their season
  note:   "Legal exports, finance at quarter-end, engineers cloning datasets,
           IT archiving a leaver's mailbox — every estate has legitimate bulk
           movers. The question is whether THIS volume, at THIS time, to THIS
           destination fits the role's established rhythm. Offboarding dates
           are worth an explicit check: departing-employee collection is the
           most common true positive this hunt has."

## Emit

/lead: data movement inconsistent with the mover's own history
  entity: user
  note:   "Evidence carries the user's baseline volume beside the anomaly, the
           destination and its estate rarity, any DLP corroboration, and the
           staging trail if one exists. Name the boring explanations that were
           checked — role, season, offboarding, migration — and which of them
           failed to hold. A volume number with no context is not a lead, it
           is homework."
