---
kind: hunt
title: "The boxes at the edge that everyone trusts and nobody watches"
subtitle: "VPN sessions that don't fit their user, admin-plane changes on the appliances themselves, and the telemetry gaps that keep edge intrusions invisible"
category: network
owner: "team · soc-leads"
authored: 2026-08-03
schedule: "30 10 * * *"
timezone: "UTC"
lookback_window: 24h
telemetry:
  all_of:
    - network.vpn
  optional:
    - network.edge_admin
    - network.connection
mitre_tactic: initial-access
mitre_technique: T1133
hypothesis: "Edge appliances are the most attacked and least observed machines in the estate. Replayed credentials and hijacked sessions show as a user's successful external logons spreading across several networks or countries, or two distant networks inside one hour; appliance exploitation shows as new local accounts and admin changes on the box itself; and thin edge telemetry hides both. The benign twin is a travelling user on a known cadence and a network team pushing config from a jump host inside a maintenance window."
risk_weight: 7
default_severity: high
pivots:
  - name: edge_telemetry_census
    role: coverage
    query: 'class_uid IN (3001, 3002, 3005, 3006, 4001, 6003) | stats count, dc(user.name) AS users by metadata.product.name, class_uid | sort metadata.product.name | head 200'
  - name: external_logon_spread
    role: discovery
    query: 'class_uid=3002 status_id=1 | where is_public_ip(src_endpoint.ip) | stats dc(src_endpoint.autonomous_system.number) AS asns, dc(src_endpoint.location.country) AS countries, dc(src_endpoint.ip) AS source_ips, count AS logons, values(src_endpoint.location.country) AS country_list, values(metadata.product.name) AS products by user.name | where asns >= 2 | sort -countries, -asns | head 200'
    scorer:
      method: zscore
      field: asns
      threshold: 2
  - name: concurrent_external_sessions
    role: discovery
    dataset: signals
    query: "SELECT user_name AS `user.name`, hour, uniqIf(asn, asn != 0) AS asns_in_hour, uniqIf(country, country != '') AS countries_in_hour, uniq(ip) AS source_ip_count, groupUniqArray(10)(ip) AS source_ips, groupUniqArray(5)(country) AS countries, groupUniqArray(5)(product) AS products, count() AS logons, countIf(detected) AS already_detected FROM (SELECT `user.name` AS user_name, toStartOfHour(timestamp) AS hour, `src_endpoint.autonomous_system.number` AS asn, `src_endpoint.location.country` AS country, `src_endpoint.ip` AS ip, `metadata.product.name` AS product, id IN (SELECT matched_log_id FROM {signals} WHERE timestamp >= {earliest:DateTime64(6, 'UTC')} AND timestamp <= {latest:DateTime64(6, 'UTC')}) AS detected FROM {events} WHERE timestamp >= {earliest:DateTime64(6, 'UTC')} AND timestamp <= {latest:DateTime64(6, 'UTC')} AND class_uid = 3002 AND status_id = 1 AND `user.name` != '' AND isIPv4String(`src_endpoint.ip`) AND NOT (isIPAddressInRange(`src_endpoint.ip`, '10.0.0.0/8') OR isIPAddressInRange(`src_endpoint.ip`, '172.16.0.0/12') OR isIPAddressInRange(`src_endpoint.ip`, '192.168.0.0/16') OR isIPAddressInRange(`src_endpoint.ip`, '127.0.0.0/8') OR isIPAddressInRange(`src_endpoint.ip`, '100.64.0.0/10') OR isIPAddressInRange(`src_endpoint.ip`, '169.254.0.0/16'))) GROUP BY user_name, hour HAVING asns_in_hour >= 2 ORDER BY countries_in_hour DESC, asns_in_hour DESC, `user.name` ASC, hour ASC LIMIT 200"
  - name: account_and_group_changes_by_product
    role: discovery
    query: 'class_uid IN (3001, 3006) | stats count, values(activity_name) AS activities, values(user.name) AS target_accounts, values(actor.user.name) AS actors, values(src_endpoint.ip) AS source_ips, min(timestamp) AS first_seen, max(timestamp) AS last_seen by metadata.product.name, device.hostname | sort +count, metadata.product.name, device.hostname | head 200'
budget:
  max_turns: 40
  max_tool_calls: 120
  max_rows: 6000
  max_wall_seconds: 900
tags:
  - network
  - vpn
  - edge
  - remote-access
---
# The boxes at the edge that everyone trusts and nobody watches

**Hypothesis:** the estate's edge appliances are its most attacked and least observed machines — a rolling parade of exploited CVEs, credentials replayed from infostealer logs, and admin planes reachable from places they should never be. Two hunts live in their logs: sessions that do not fit the user who owns them, and changes to the *appliance itself* — and a third finding hides underneath, because thin edge telemetry is precisely how these intrusions stay invisible, and thinness is measurable.

## Sessions that do not fit their owner

/query: VPN authentications deviating from each user's own profile
  window: 24h
  from:   vpn_logs
  note:   "Two pivots already measure the spread, over successful Authentication
           (3002) logons from public src_endpoint.ip (VPN plus any other
           internet-facing auth, products named in metadata.product.name):
           external_logon_spread (distinct ASNs, countries and IPs per
           user.name) and concurrent_external_sessions (two or more ASNs for
           one user inside one hour). Neither compares against the user's own
           history, and missing MFA (is_mfa) is not measured: check both on
           the candidates.

           The sign-in hunt's doctrine applied at the tunnel: new geo, new
           ASN, new client fingerprint, impossible-travel pairs, and
           always against the user's OWN history. Two edge-specific
           shapes deserve extra weight: concurrent sessions for one user
           from distant networks — tunnels persist, so overlap is
           legible — and successful logons WITHOUT the posture or MFA
           step the estate's clients normally produce, which is what
           replayed credentials and session hijacks look like from here."

/query: what the tunnel touched after connecting
  note:   "A legitimate user lands and goes to their usual few systems; a
           replayed credential lands and goes exploring. First-seen
           internal destinations per VPN user, scanning shapes from
           VPN-assigned addresses, and RDP/SMB fan-out from the VPN pool
           join this hunt to the lateral-movement hunt's census — an
           edge session whose interior behaviour is also new is one lead,
           not two."

## The appliance as the victim

/query: administrative logons and configuration changes on the appliances
  note:   "The account_and_group_changes_by_product pivot already lists
           Account Change (3001) and Group Management (3006) events per
           metadata.product.name and device.hostname; read the rows for the
           edge products. Config, cert and firmware operations have no common
           OCSF class across vendors: query them per product.

           Config writes, new local accounts, auth-policy edits, cert and
           key changes, firmware operations — from whom and from WHERE.
           Admin reachable from the WAN side is a finding even with a
           legitimate actor; a new local account on an edge box is close
           to a tripwire, since real estates manage edge auth centrally
           and local accounts are exactly what appliance-CVE exploitation
           leaves behind."

/query: appliance behaviour consistent with exploitation
  note:   "Unexpected reboots or crashes followed shortly by config
           changes, logging settings modified, unfamiliar processes or
           debug modes where the platform exposes them. The
           crash-then-change sequence is the classic post-exploit
           footprint on edge gear — each half is dismissible, the
           sequence is not."

## The gap is also a finding

/baseline: what these appliances CAN log versus what they are sending
  note:   "The edge_telemetry_census pivot already lists event counts per
           metadata.product.name and class_uid: an edge product with 3002
           rows and no 3001 / 3006 / 6003 rows is the gap.

           Edge boxes routinely send auth logs and nothing else — no
           config-change audit, no local-account events — and that
           silence gets read as health. Compare received event types
           against the platform's capability, the environment-recon
           discipline applied to one source class. If the admin-plane
           sections above are running blind, the sweep narrative must
           say so explicitly: an unwatchable edge is a risk finding in
           its own right, not a clean sweep."

## Rule out the boring explanation

/enrichment: NOC maintenance windows, egress changes, and roaming context
  note:   "Network teams do config pushes in windows from jump hosts, and
           sales teams do authenticate from four countries in a week.
           The maintenance carve is actor-plus-window-plus-source; the
           roaming carve is the user's own travel cadence. A config
           change that is IN a window but from a first-seen source
           network fails the carve on the axis that matters."

## Emit

/lead: edge session or appliance change outside its owner's pattern
  entity: host
  note:   "Evidence carries the session or change events, the owner's
           baseline beside the deviation, the interior-behaviour trail
           for sessions, and the capability-versus-received telemetry
           statement when it limited the sweep. For appliance-side leads,
           recommend checking the vendor's current KEV/advisory state in
           the narrative — edge findings age in days, and the reader
           should know if this box's platform is this month's campaign."
