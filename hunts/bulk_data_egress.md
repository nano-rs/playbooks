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
budget:
  max_turns: 40
  max_tool_calls: 120
  max_rows: 6000
  max_wall_seconds: 900
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
           suddenly bulk-syncing)."

/query: per-host outbound byte volumes to non-CDN destinations
  window: 24h
  from:   squid_proxy
  note:   "Strip the destinations everyone uploads to as a matter of course —
           backup endpoints, update CDNs, telemetry sinks. What remains is
           small. Rank by destination rarity for the estate: personal cloud
           storage, transfer services, and never-before-seen domains beat raw
           byte counts."

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
