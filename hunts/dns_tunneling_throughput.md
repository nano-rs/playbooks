---
kind: hunt
title: "DNS moving data by volume rather than by rhythm"
subtitle: "Per-domain subdomain fan-out, label entropy and one-host attribution — the throughput sibling of the beaconing hunt"
category: network
owner: "team · soc-leads"
authored: 2026-08-03
schedule: "0 8 * * *"
timezone: "UTC"
lookback_window: 24h
telemetry:
  all_of:
    - network.dns
mitre_tactic: exfiltration
mitre_technique: T1048.003
hypothesis: "Data moved over DNS puts the payload in the query labels, so one parent domain collects hundreds or thousands of distinct, never-repeated, long, high-entropy subdomains, often TXT / NULL, and almost always from a single host. CDNs, AV cloud lookups, DNSBLs and telemetry SDKs also fan out under one domain, but their labels are short and templated and the whole estate queries them. The shape and the audience are measured deterministically here; the model only explains them."
risk_weight: 7
default_severity: high
pivots:
  - name: dns_census
    role: coverage
    query: 'class_uid=4003 activity_id=1 | stats count, dc(src_endpoint.ip) AS sources, dc(query.hostname) AS names by source_type'
  - name: dns_parent_domain_shape
    role: discovery
    dataset: signals
    query: "SELECT parent_domain AS parent_domain, uniq(name) AS distinct_names, count() AS queries, countIf(qtype IN ('TXT', 'NULL')) AS txt_null_queries, round(txt_null_queries / queries, 3) AS txt_null_share, round(avg(length(name)), 1) AS avg_name_length, quantileExact(0.5)(length(lbl)) AS median_label_length, max(length(lbl)) AS max_label_length, round(avg(entropy), 3) AS label_entropy_bits, uniq(host_ip) AS source_ips, groupUniqArray(5)(host_name) AS source_hosts, groupUniqArray(5)(host_ip) AS source_ip_sample, countIf(detected) AS already_detected, min(ts) AS first_seen, max(ts) AS last_seen FROM (SELECT timestamp AS ts, id, `query.hostname` AS name, upper(toString(event.query.type)) AS qtype, `src_endpoint.ip` AS host_ip, `src_endpoint.hostname` AS host_name, cutToFirstSignificantSubdomain(`query.hostname`) AS parent_domain, splitByChar('.', `query.hostname`)[1] AS lbl, splitByString('', lbl) AS chars, arraySum(arrayMap(c -> -(c / length(lbl)) * log2(c / length(lbl)), arrayMap(ch -> countEqual(chars, ch), arrayDistinct(chars)))) AS entropy, id IN (SELECT matched_log_id FROM {signals} WHERE timestamp >= {earliest:DateTime64(6, 'UTC')} AND timestamp <= {latest:DateTime64(6, 'UTC')}) AS detected FROM {events} WHERE timestamp >= {earliest:DateTime64(6, 'UTC')} AND timestamp <= {latest:DateTime64(6, 'UTC')} AND class_uid = 4003 AND activity_id = 1 AND `query.hostname` != '') WHERE parent_domain != '' AND parent_domain != name GROUP BY parent_domain HAVING distinct_names >= 20 AND ((median_label_length >= 25) + (label_entropy_bits >= 4.0) + (txt_null_share >= 0.5)) >= 2 ORDER BY distinct_names DESC, parent_domain ASC LIMIT 200"
    scorer:
      method: zscore
      field: label_entropy_bits
      threshold: 2
  - name: dns_tunnel_candidate_queries
    role: discovery
    dataset: signals
    query: "SELECT id, ts AS timestamp, host_name AS `src_endpoint.hostname`, host_ip AS `src_endpoint.ip`, name AS `query.hostname`, qtype AS `query.type`, parent_domain, length(lbl) AS label_length, detected AS already_detected FROM (SELECT timestamp AS ts, id, `query.hostname` AS name, upper(toString(event.query.type)) AS qtype, `src_endpoint.ip` AS host_ip, `src_endpoint.hostname` AS host_name, cutToFirstSignificantSubdomain(`query.hostname`) AS parent_domain, splitByChar('.', `query.hostname`)[1] AS lbl, splitByString('', lbl) AS chars, arraySum(arrayMap(c -> -(c / length(lbl)) * log2(c / length(lbl)), arrayMap(ch -> countEqual(chars, ch), arrayDistinct(chars)))) AS entropy, id IN (SELECT matched_log_id FROM {signals} WHERE timestamp >= {earliest:DateTime64(6, 'UTC')} AND timestamp <= {latest:DateTime64(6, 'UTC')}) AS detected FROM {events} WHERE timestamp >= {earliest:DateTime64(6, 'UTC')} AND timestamp <= {latest:DateTime64(6, 'UTC')} AND class_uid = 4003 AND activity_id = 1 AND `query.hostname` != '') WHERE parent_domain IN (SELECT parent_domain FROM (SELECT parent_domain AS parent_domain, uniq(name) AS distinct_names, count() AS queries, countIf(qtype IN ('TXT', 'NULL')) AS txt_null_queries, round(txt_null_queries / queries, 3) AS txt_null_share, round(avg(length(name)), 1) AS avg_name_length, quantileExact(0.5)(length(lbl)) AS median_label_length, max(length(lbl)) AS max_label_length, round(avg(entropy), 3) AS label_entropy_bits, uniq(host_ip) AS source_ips, groupUniqArray(5)(host_name) AS source_hosts, groupUniqArray(5)(host_ip) AS source_ip_sample, countIf(detected) AS already_detected, min(ts) AS first_seen, max(ts) AS last_seen FROM (SELECT timestamp AS ts, id, `query.hostname` AS name, upper(toString(event.query.type)) AS qtype, `src_endpoint.ip` AS host_ip, `src_endpoint.hostname` AS host_name, cutToFirstSignificantSubdomain(`query.hostname`) AS parent_domain, splitByChar('.', `query.hostname`)[1] AS lbl, splitByString('', lbl) AS chars, arraySum(arrayMap(c -> -(c / length(lbl)) * log2(c / length(lbl)), arrayMap(ch -> countEqual(chars, ch), arrayDistinct(chars)))) AS entropy, id IN (SELECT matched_log_id FROM {signals} WHERE timestamp >= {earliest:DateTime64(6, 'UTC')} AND timestamp <= {latest:DateTime64(6, 'UTC')}) AS detected FROM {events} WHERE timestamp >= {earliest:DateTime64(6, 'UTC')} AND timestamp <= {latest:DateTime64(6, 'UTC')} AND class_uid = 4003 AND activity_id = 1 AND `query.hostname` != '') WHERE parent_domain != '' AND parent_domain != name GROUP BY parent_domain HAVING distinct_names >= 20 AND ((median_label_length >= 25) + (label_entropy_bits >= 4.0) + (txt_null_share >= 0.5)) >= 2)) ORDER BY parent_domain ASC, `src_endpoint.hostname` ASC, timestamp DESC LIMIT 25 BY parent_domain, `src_endpoint.hostname`, `src_endpoint.ip` LIMIT 200"
  - name: dns_single_audience_throughput
    role: discovery
    dataset: signals
    query: "SELECT parent_domain, uniq(name) AS distinct_names, count() AS queries, round(distinct_names / queries, 3) AS unique_name_share, sum(greatest(length(name) - length(parent_domain) - 1, 0)) AS label_bytes, uniq(host_ip) AS source_ips, groupUniqArray(3)(host_ip) AS source_ip_sample, groupUniqArray(3)(host_name) AS source_hosts, countIf(detected) AS already_detected, min(ts) AS first_seen, max(ts) AS last_seen FROM (SELECT timestamp AS ts, id, lower(`query.hostname`) AS name, `src_endpoint.ip` AS host_ip, `src_endpoint.hostname` AS host_name, cutToFirstSignificantSubdomain(lower(`query.hostname`)) AS parent_domain, id IN (SELECT matched_log_id FROM {signals} WHERE timestamp >= {earliest:DateTime64(6, 'UTC')} AND timestamp <= {latest:DateTime64(6, 'UTC')}) AS detected FROM {events} WHERE timestamp >= {earliest:DateTime64(6, 'UTC')} AND timestamp <= {latest:DateTime64(6, 'UTC')} AND class_uid = 4003 AND activity_id = 1 AND `query.hostname` != '') WHERE parent_domain != '' AND parent_domain != name GROUP BY parent_domain HAVING distinct_names >= 100 AND source_ips <= 2 ORDER BY label_bytes DESC, parent_domain ASC LIMIT 200"
    scorer:
      method: iqr
      field: label_bytes
      threshold: 3
budget:
  max_turns: 40
  max_tool_calls: 120
  max_rows: 6000
  max_wall_seconds: 900
tags:
  - network
  - dns
  - tunneling
  - exfiltration
---
# DNS moving data by volume rather than by rhythm

**Hypothesis:** a tunnel cannot hide what it is for. C2-over-DNS keeps a rhythm and the beaconing hunt owns that shape; *data movement* over DNS needs throughput, and throughput forces three measurable properties onto one parent domain: many distinct subdomains (payload goes in the labels), high label entropy (encoded bytes do not look like words), and — the load-bearing one — a single host doing the talking. Popular domains have fan-out; tunnels have fan-out from an audience of one.

## Measure the three properties

/query: per parent domain — distinct-subdomain count, query volume, label lengths
  window: 24h
  from:   dns_logs
  note:   "The dns_single_audience_throughput pivot already measures this per
           parent domain (cutToFirstSignificantSubdomain of query.hostname):
           distinct names, queries, unique-name share, label bytes and source
           count, kept only at 100+ distinct names from at most two sources.

           Aggregate at the registered domain, not the FQDN, or the tunnel
           disperses into its own noise. The interesting extreme is
           thousands of distinct, never-repeated subdomains — every query a
           new label is data encoding, since caching makes repeats free and
           tunnels get no repeats."

/query: label entropy and encoding texture on the high-fan-out set
  note:   "The dns_parent_domain_shape pivot already measures this (median
           and max first-label length, label entropy in bits, TXT / NULL
           share), and dns_tunnel_candidate_queries lists the matching
           queries per source host.

           Encoded payloads run long, character-dense and dictionary-free;
           hex and base32 have recognizable alphabets. Score entropy
           per-label and look at the DISTRIBUTION per domain — legitimate
           high-fan-out services (CDNs, telemetry) have structured,
           templated labels; tunnels are uniformly dense. Response types
           are corroboration: TXT/NULL/CNAME-heavy answers carry the
           downstream leg of a bidirectional channel."

## The attribution test

/baseline: how many distinct hosts query each candidate domain
  note:   "Both shape pivots return source_ips for each domain; the
           throughput pivot keeps only domains with one or two sources.

           This is the discriminator that survives contact with reality.
           Antivirus cloud lookups, DNSBLs and telemetry domains max out
           every volume metric this hunt has — queried by the WHOLE estate.
           A domain with tunnel texture queried by exactly one host has an
           audience of one, and tunnels are always an audience of one.
           Estate-wide first-seen for the domain belongs in the same
           breath: infrastructure this loud is rarely old."

## Back to the host

/pivot: the process and user behind the querying host's traffic
  note:   "Where endpoint telemetry exists, name the process owning the
           resolver traffic. A tunnel from a security tool's update process
           has a very different reading than one from an unsigned binary in
           a profile directory — and 'the host also appears in another
           hunt's leads today' is exactly the join worth making. If process
           attribution is unavailable, state it plainly."

/query: what else the host was doing during the tunnel window
  note:   "Throughput tunnels exist to move something. Bulk reads from
           shares, staging archives, or a preceding credential-access shape
           on the same host tells the reader WHAT is likely leaving, which
           converts a protocol anomaly into a data-loss narrative."

## Rule out the boring explanation

/enrichment: is the domain a known security product, DNSBL, or SaaS telemetry endpoint
  note:   "The one-host test already removed most of these; the survivors
           are niche agents installed on a single machine — a developer's
           odd tool phoning home through DNS. Vendor attribution of the
           domain settles it, and when it does, record the domain in the
           narrative so next sweep's reader inherits the answer instead of
           the mystery."

## Emit

/lead: tunnel-textured DNS with single-host attribution
  entity: host
  note:   "Evidence carries the numbers that made the case — subdomain
           count, entropy distribution, byte estimate for labels moved,
           the one-host fact, domain age — plus the owning process if
           found. Estimate throughput honestly: 'roughly 40 MB of encoded
           labels in six hours' is a sentence that mobilizes a response;
           'high entropy DNS' is one that gets filed."
