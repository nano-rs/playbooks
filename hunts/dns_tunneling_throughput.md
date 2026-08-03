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
  note:   "Aggregate at the registered domain, not the FQDN, or the tunnel
           disperses into its own noise. The interesting extreme is
           thousands of distinct, never-repeated subdomains — every query a
           new label is data encoding, since caching makes repeats free and
           tunnels get no repeats."

/query: label entropy and encoding texture on the high-fan-out set
  note:   "Encoded payloads run long, character-dense and dictionary-free;
           hex and base32 have recognizable alphabets. Score entropy
           per-label and look at the DISTRIBUTION per domain — legitimate
           high-fan-out services (CDNs, telemetry) have structured,
           templated labels; tunnels are uniformly dense. Response types
           are corroboration: TXT/NULL/CNAME-heavy answers carry the
           downstream leg of a bidirectional channel."

## The attribution test

/baseline: how many distinct hosts query each candidate domain
  note:   "This is the discriminator that survives contact with reality.
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
