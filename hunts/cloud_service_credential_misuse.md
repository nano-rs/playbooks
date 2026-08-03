---
kind: hunt
title: "Machine credentials used from the wrong place or asking the wrong questions"
subtitle: "GCP service-account keys and Azure service principals deviating from their own calling pattern"
category: cloud
owner: "team · soc-leads"
authored: 2026-08-03
schedule: "0 2 * * *"
timezone: "UTC"
lookback_window: 24h
telemetry:
  all_of:
    - cloud.control_plane
mitre_tactic: defense-evasion
mitre_technique: T1550.001
budget:
  max_turns: 40
  max_tool_calls: 120
  max_rows: 6000
  max_wall_seconds: 900
tags:
  - cloud
  - service-accounts
  - credential-abuse
---
# Machine credentials used from the wrong place or asking the wrong questions

**Hypothesis:** a service credential has the most predictable life of anything in the estate — same callers, same APIs, same rhythm — so a stolen key betrays itself on the first call: wrong network, wrong API surface, or wrong appetite. The account is legitimate; the hands are not.

This is the machine sibling of the human sign-in hunt. The difference is that machine baselines are *tighter*: a service account that has called three APIs from one IP range for six months has effectively zero legitimate reasons to enumerate IAM policy from a residential ASN tomorrow.

## Learn each credential's habits

/baseline: per-credential calling profile — source networks, API methods, rhythm
  window: 30d
  note:   "Three axes per service account and service principal: where calls
           come from, which methods are called, and how regularly. Most
           credentials collapse to a tiny tuple on all three. Record which
           credentials are TOO noisy to baseline (shared CI credentials, sadly
           common) rather than pretending they fit."

## Look for the wrong place

/query: credential calls from networks outside the credential's history
  window: 24h
  note:   "A key minted for a GKE workload calling from cloud-internal ranges
           that suddenly calls from a consumer ISP is the cleanest shape this
           hunt produces. Grade by ASN category — new-region cloud egress is a
           migration smell, residential or VPN-exit egress is not."

/query: dormant credentials waking up
  note:   "A key unused for 60 days that authenticates today deserves a look
           regardless of source. Stolen key material is often old — exfiltrated
           from a repo or laptop long before use — and revival is the first
           observable moment."

## Look for the wrong questions

/query: enumeration bursts — List*/Get*/Describe* across services in tight sequence
  note:   "Workloads ask the same narrow questions forever; a thief inventories
           what the key can do. A credential whose call mix shifts from its
           usual methods to a breadth-first sweep of IAM, storage and compute
           reads is doing reconnaissance, whoever holds it."

/query: privilege and persistence moves by machine credentials
  note:   "Key creation, role grants, policy writes by a credential that has
           never touched IAM before is the escalation leg. Cross-reference the
           cloud persistence hunt — a hit on both in one sweep is one story,
           not two leads."

## Rule out the boring explanation

/enrichment: recent infrastructure changes touching the credential's home project
  note:   "Migrations move calling IPs, and platform teams do re-home
           workloads. A change that explains the new network should explain
           it for EVERY credential in that project — one credential moving
           alone, or one moving somewhere the change does not cover, keeps
           the lead alive."

/pivot: the human trail near the credential's key material
  note:   "If the key was recently downloaded, exported, or its secret read by
           a human identity, that event and that human belong in the evidence.
           An engineer running a prod key from a laptop is a real finding too —
           a policy one, and the narrative should call it what it is."

## Emit

/lead: service credential deviating from its established calling pattern
  entity: service_account
  note:   "Show the baseline tuple next to the deviation — the reader must see
           'three APIs, one network, six months' beside 'IAM enumeration,
           residential ASN, today' to triage at a glance. If the API surface
           check was impossible because the credential was too noisy to
           baseline, say so; an unstated gap reads as checked-and-clear."
