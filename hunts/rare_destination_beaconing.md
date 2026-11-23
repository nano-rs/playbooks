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
telemetry:
  one_of:
    - network.web
    - network.connection
  optional:
    - network.dns
mitre_tactic: command-and-control
mitre_technique: T1071.001
hypothesis: "Implant traffic is regular in a way human browsing is not, and goes to a destination almost nothing else in the estate contacts: one source, many requests spread across the day, inter-request gaps far tighter than bursty human browsing, to a domain or public IP that at most a few hosts have ever reached. Update checks and telemetry endpoints are just as periodic but are contacted by many hosts; one-off visits to obscure sites are rare but not periodic."
risk_weight: 6
default_severity: medium
pivots:
  - name: egress_census
    role: coverage
    query: 'class_uid IN (4001, 4002) | stats count, dc(src_endpoint.ip) AS sources by class_uid, source_type'
  - name: http_rare_destination_beacons
    role: discovery
    query: 'class_uid=4002 http_request.url.hostname!="" src_endpoint.ip!="" prevalence_dest_domain<=3 | eval dest=lower(http_request.url.hostname) | sort src_endpoint.ip, dest, timestamp | streamstats current=false last(timestamp) AS prev_ts by src_endpoint.ip, dest | eval gap=timestamp - prev_ts, hour=strftime(timestamp, "%Y-%m-%d %H") | eval gap=if(gap>0, gap, null()) | stats count AS requests, min(prevalence_dest_domain) AS estate_hosts_seen, count(gap) AS gap_count, avg(gap) AS mean_gap_seconds, stdev(gap) AS sd_gap, dc(hour) AS active_hours, values(http_request.user_agent) AS user_agents, min(timestamp) AS first_seen, max(timestamp) AS last_seen by src_endpoint.ip, dest | where gap_count>=12 AND active_hours>=3 | eval gap_cv=round(sd_gap / mean_gap_seconds, 3), mean_gap_seconds=round(mean_gap_seconds, 1) | where gap_cv<=0.5 | sort gap_cv, -requests, src_endpoint.ip | head 200'
  - name: network_rare_destination_beacons
    role: discovery
    query: 'class_uid=4001 dst_endpoint.ip!="" src_endpoint.ip!="" prevalence_dest_ip<=3 | sort src_endpoint.ip, dst_endpoint.ip, dst_endpoint.port, timestamp | streamstats current=false last(timestamp) AS prev_ts by src_endpoint.ip, dst_endpoint.ip, dst_endpoint.port | eval gap=timestamp - prev_ts, hour=strftime(timestamp, "%Y-%m-%d %H") | eval gap=if(gap>0, gap, null()) | stats count AS connections, sum(traffic.bytes_out) AS bytes_out, min(prevalence_dest_ip) AS estate_hosts_seen, count(gap) AS gap_count, avg(gap) AS mean_gap_seconds, stdev(gap) AS sd_gap, dc(hour) AS active_hours, min(timestamp) AS first_seen, max(timestamp) AS last_seen by src_endpoint.ip, dst_endpoint.ip, dst_endpoint.port | where gap_count>=12 AND active_hours>=3 | eval gap_cv=round(sd_gap / mean_gap_seconds, 3), mean_gap_seconds=round(mean_gap_seconds, 1) | where gap_cv<=0.5 | sort gap_cv, -connections, src_endpoint.ip | head 200'
budget:
  max_turns: 40
  max_tool_calls: 120
  max_rows: 6000
  max_wall_seconds: 2700
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
  note:   "The http_rare_destination_beacons (proxy, class_uid 4002) and
           network_rare_destination_beacons (flows, class_uid 4001) pivots
           already measure this per source and destination: request count,
           active hours, mean gap and gap_cv (standard deviation over mean of
           the gaps), kept at 12+ gaps over 3+ hours with gap_cv <= 0.5.

           Beaconing shows as low variance in the gap between requests. Jitter is
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
  note:   "Both beacon pivots read only destinations whose estate prevalence
           (prevalence_dest_domain / prevalence_dest_ip, hosts that have
           contacted it) is 3 or less, and return it as estate_hosts_seen.

           This is the load-bearing step. One host talking to a destination the
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
  entity: domain
  note:   "Attach the timing evidence AND the rarity measurement — a lead that
           says 'beaconing detected' without showing the gap distribution and
           the asset count cannot be triaged without redoing the work, and an
           analyst who has to redo the work will dismiss it.

           If the process could not be identified, state that. An unstated gap
           reads as a checked-and-clear."
