---
kind: hunt
title: "Regular outbound to a destination almost nothing else talks to"
subtitle: "Beacon-shaped egress, weighted by how unusual the destination is for this estate"
category: network
owner: "team · soc-leads"
authored: 2026-07-30
schedule: "0 4 * * *"
timezone: "UTC"
lookback_window: 24h
required_source_types:
  - squid_proxy
mitre_tactic: command-and-control
mitre_technique: T1071.001
budget:
  max_turns: 40
  max_tool_calls: 120
  max_rows: 6000
  max_wall_seconds: 900
tags:
  - network
  - c2
  - beaconing
---
# Regular outbound to a destination almost nothing else talks to

**Hypothesis:** implant traffic is regular in a way human browsing is not, and goes somewhere the rest of the estate has no reason to go. Neither property alone is worth an analyst's time — the estate is full of regular machine traffic to popular destinations, and full of one-off visits to obscure ones. The intersection is small and interesting.

Rarity here means *rare for this organisation*, computed against the estate's own history. A domain nobody has heard of that half the fleet contacts is a vendor; a bland-looking domain that exactly one host contacts every nine minutes is not.

## Find the regular talkers

/query: per source:destination pair, the distribution of inter-request gaps
  window: 24h
  from:   squid_proxy
  note:   "Beaconing shows as low variance in the gap between requests. Jitter is
           common in modern implants, so do not look for a constant — look for a
           distribution far tighter than human browsing, which is bursty and
           clusters around working hours."

/query: strip the obviously periodic and obviously benign
  note:   "Software update checks, telemetry endpoints, NTP-over-HTTP and status
           pages are all beacon-shaped and all boring. They are also usually
           contacted by MANY hosts, which the rarity step below removes for free
           — resist the urge to hardcode a vendor allowlist here, because that
           list is exactly where an attacker would like to be."

## Weight by how unusual the destination is

/baseline: how many distinct assets in this estate have ever contacted the destination
  note:   "This is the load-bearing step. One host talking to a destination the
           other 2,000 have never touched is the signal; the periodicity only
           told us where to look."

/enrichment: registration age, ASN, and category for the destination
  note:   "A domain registered last week carries more weight than a decade-old
           one. Treat this as corroboration, not as a verdict — plenty of
           legitimate infrastructure is new, and plenty of compromised
           infrastructure is old."

## Follow it back to the host

/pivot: what process on the source host owns this traffic
  note:   "Where endpoint telemetry exists, tie the flow to a process. A beacon
           from a browser is usually a page doing something dull; the same
           pattern from a signed-but-unusual binary is a different lead
           entirely. If endpoint data is unavailable, say so in the narrative
           rather than leaving the reader to assume it was checked."

/baseline: is this destination new for this host specifically
  note:   "An estate-wide first-seen and a host-level first-seen answer different
           questions. Both belong in the evidence."

## Emit

/lead: periodic egress to an estate-rare destination
  entity: dest_domain
  note:   "Attach the timing evidence AND the rarity measurement — a lead that
           says 'beaconing detected' without showing the gap distribution and
           the asset count cannot be triaged without redoing the work, and an
           analyst who has to redo the work will dismiss it.

           If the process could not be identified, state that. An unstated gap
           reads as a checked-and-clear."
