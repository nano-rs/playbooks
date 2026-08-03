---
kind: hunt
title: "Data-plane moves the identity hunts never see"
subtitle: "Snapshots shared to foreign accounts, storage flipped public, signed-URL bursts, and compute that pays someone else"
category: cloud
owner: "team · soc-leads"
authored: 2026-08-03
schedule: "30 7 * * *"
timezone: "UTC"
lookback_window: 24h
telemetry:
  all_of:
    - cloud.data_plane
mitre_tactic: exfiltration
mitre_technique: T1537
budget:
  max_turns: 40
  max_tool_calls: 120
  max_rows: 5000
  max_wall_seconds: 900
tags:
  - cloud
  - exfiltration
  - storage
  - cryptomining
---
# Data-plane moves the identity hunts never see

**Hypothesis:** the cloud credential and persistence hunts watch *who* is acting; this one watches what happens to the *stuff*. Cloud-native exfiltration never crosses the network perimeter at all — a disk snapshot shared to an attacker's own account, a bucket policy flipped open, a pile of signed URLs — and resource theft (mining) is the confession that a credential is fully owned. Every one of these is a single API call sitting in audit logs the identity-focused hunts have no reason to read.

## Data leaving by reference

/query: snapshots, images and disks shared to accounts outside the organization
  window: 24h
  note:   "The cleanest cloud exfil there is: snapshot the disk, grant a
           foreign project or subscription access, download on the other
           side — nothing 'left' the estate as far as any network sensor
           can tell. Cross-org sharing events are rare enough to read
           individually, and the receiving account identity is the most
           attributable artifact this whole category produces. Weight by
           what the disk WAS: a database volume's snapshot outranks a web
           server's."

/query: storage access policy changes toward open
  note:   "Buckets and containers flipped to public or all-authenticated,
           anonymous-access enablement, and org-policy exceptions created
           for specific resources. Two readings, both leads: an intruder
           staging a pickup, or an engineer about to cause the org's next
           disclosure. Rank by data sensitivity where tagging allows, and
           by whether the flip was followed by anonymous reads — a flip
           that was USED is a different lead than a flip that waits."

/query: signed-URL and SAS-token generation bursts
  note:   "Time-limited links are the polite way to move data to an
           unauthenticated pickup. Baseline per principal: applications
           mint them steadily by design; a human identity or an unusual
           service suddenly minting dozens against sensitive containers is
           packaging for delivery."

## Compute that pays someone else

/query: instance creation off the estate's pattern — regions, types, volume
  note:   "Mining shapes: GPU or large-CPU instance types the org never
           uses, unused regions lighting up, many instances in one burst,
           spot-heavy requests, or quota-increase attempts preceding all
           of it. This is less about the money than the implication — a
           miner means a credential is fully compromised and its owner
           does not know yet. The same burst WITHOUT mining texture might
           be worse; check what the instances actually do before labeling."

## Attribution back to hands

/pivot: the principal and session behind each flagged call
  note:   "Every event above joins back to the identity hunts' ground: was
           the calling credential already deviating (wrong network, wrong
           API appetite)? A snapshot share performed by a credential the
           misuse hunt flagged yesterday is one intrusion narrated in two
           logs, and the lead should say so rather than making the reader
           discover it."

## Rule out the boring explanation

/baseline: the estate's legitimate cross-account and public-publishing patterns
  note:   "Real estates share snapshots with vendor support cases, publish
           website assets from public buckets, and burst compute for
           batch jobs. The legitimate TARGETS are a small fixed set —
           partner account IDs, the known-public buckets, the batch
           projects. First-seen receiving account is the load-bearing
           question for shares, exactly as first-seen destination is for
           egress."

/enrichment: change context for infrastructure-shaped events
  note:   "Migrations genuinely move disks across accounts and terraform
           genuinely rewrites storage policy in bulk. Pipeline authorship
           with a change ticket clears most of this in one check — and
           bulk policy rewrites from a HUMAN credential outside a window
           is the inverse signal, sharpened by the same check."

## Emit

/lead: data-plane event moving data or compute outside the estate's pattern
  entity: resource
  note:   "Evidence carries the API call verbatim, the resource and its
           sensitivity, the receiving account or public scope, the acting
           principal with its session context, and the was-it-used answer
           for flips and links. Recommend the immediate reversal action in
           the narrative — unshare, re-close, revoke — since every hour a
           snapshot stays shared is pickup time; the analyst decides, but
           the hunt should have done the looking-up."
