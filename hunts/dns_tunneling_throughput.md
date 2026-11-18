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
    query: 'class_uid=4003 | stats count, dc(src_endpoint.ip) AS sources, dc(query.hostname) AS names by source_type'
  - name: dns_parent_domain_shape
    role: discovery
    query: 'class_uid=4003 query.hostname!="" | eval qtype=upper(tostring(query.type)), parent_domain=registered_domain(query.hostname), lbl=mvindex(split(query.hostname, "."), 0), lbl_len=len(lbl), name_len=len(query.hostname), ent=entropy(lbl), is_txt_null=if(qtype="TXT" OR qtype="NULL", 1, 0), is_apex=if(parent_domain==query.hostname, 1, 0) | where parent_domain!="" AND is_apex=0 | stats dc(query.hostname) AS distinct_names, count AS queries, sum(is_txt_null) AS txt_null_queries, avg(name_len) AS avg_name_length, median(lbl_len) AS median_label_length, max(lbl_len) AS max_label_length, avg(ent) AS label_entropy_bits, dc(src_endpoint.ip) AS source_ips, values(src_endpoint.hostname) AS source_hosts, values(src_endpoint.ip) AS source_ip_sample, min(timestamp) AS first_seen, max(timestamp) AS last_seen by parent_domain | eval txt_null_share=round(txt_null_queries / queries, 3), label_entropy_bits=round(label_entropy_bits, 3), avg_name_length=round(avg_name_length, 1) | where distinct_names>=20 AND (if(median_label_length>=25, 1, 0) + if(label_entropy_bits>=4.0, 1, 0) + if(txt_null_share>=0.5, 1, 0))>=2 | sort -distinct_names, parent_domain | head 200'
    scorer:
      method: zscore
      field: label_entropy_bits
      threshold: 2
  - name: dns_tunnel_candidate_queries
    role: discovery
    query: 'class_uid=4003 query.hostname!="" | eval qtype=upper(tostring(query.type)), parent_domain=registered_domain(query.hostname), lbl=mvindex(split(query.hostname, "."), 0), lbl_len=len(lbl), is_apex=if(parent_domain==query.hostname, 1, 0) | where parent_domain!="" | eval sub_name=if(is_apex=0, query.hostname, ""), sub=if(is_apex=0, 1, 0), sub_txt_null=if(is_apex=0 AND (qtype="TXT" OR qtype="NULL"), 1, 0), sub_lbl_len=if(is_apex=0, lbl_len, null()), sub_ent=if(is_apex=0, entropy(lbl), null()) | eventstats dc(sub_name) AS distinct_names, sum(sub) AS queries, sum(sub_txt_null) AS txt_null_queries, median(sub_lbl_len) AS median_label_length, avg(sub_ent) AS label_entropy_bits by parent_domain | eval txt_null_share=round(txt_null_queries / queries, 3), label_entropy_bits=round(label_entropy_bits, 3) | where distinct_names>=20 AND (if(median_label_length>=25, 1, 0) + if(label_entropy_bits>=4.0, 1, 0) + if(txt_null_share>=0.5, 1, 0))>=2 | eventstats count AS in_source by parent_domain, src_endpoint.hostname, src_endpoint.ip | streamstats count AS seq_in_source by parent_domain, src_endpoint.hostname, src_endpoint.ip | where seq_in_source>in_source - 25 | table id, timestamp, src_endpoint.hostname, src_endpoint.ip, query.hostname, qtype, parent_domain, lbl_len | sort parent_domain, src_endpoint.hostname, -timestamp | head 200'
  - name: dns_single_audience_throughput
    role: discovery
    query: 'class_uid=4003 query.hostname!="" | eval name=lower(query.hostname), parent_domain=registered_domain(lower(query.hostname)), lbl_bytes=max(len(name) - len(parent_domain) - 1, 0), is_apex=if(parent_domain==name, 1, 0) | where parent_domain!="" AND is_apex=0 | stats dc(name) AS distinct_names, count AS queries, sum(lbl_bytes) AS label_bytes, dc(src_endpoint.ip) AS source_ips, values(src_endpoint.ip) AS source_ip_sample, values(src_endpoint.hostname) AS source_hosts, min(timestamp) AS first_seen, max(timestamp) AS last_seen by parent_domain | where distinct_names>=100 AND source_ips<=2 | eval unique_name_share=round(distinct_names / queries, 3) | sort -label_bytes, parent_domain | head 200'
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
           queries per source host: the newest 25 per source host, at most
           200 rows in all. DNS queries and responses both count (some
           sources log only responses).

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
