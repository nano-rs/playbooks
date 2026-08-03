---
kind: hunt
title: "Admin-plane changes that make a foothold easier to keep"
subtitle: "Backdoor accounts, federation changes, conditional-access edits and log tampering across Entra, GCP and Azure"
category: cloud
owner: "team · soc-leads"
authored: 2026-08-03
schedule: "0 3 * * *"
timezone: "UTC"
lookback_window: 24h
telemetry:
  one_of:
    - identity.admin_audit
    - cloud.control_plane
mitre_tactic: persistence
mitre_technique: T1098
budget:
  max_turns: 40
  max_tool_calls: 120
  max_rows: 5000
  max_wall_seconds: 900
tags:
  - cloud
  - persistence
  - defense-evasion
---
# Admin-plane changes that make a foothold easier to keep

**Hypothesis:** an intruder who has landed in a tenant spends their first quiet hour making eviction harder — a spare account, a federation trust, a carve-out in conditional access, a diagnostic setting deleted. Every one of those events is also a thing a real administrator does on a normal Tuesday, which is why no rule fires. The tell is never the event; it is the actor, the clustering, and the missing context.

## Collect the hardening moves

/query: identity-plane writes that extend or entrench access
  window: 24h
  note:   "The census: new users granted privileged roles shortly after
           creation, credentials added to existing applications, federation
           and IdP trust changes, conditional-access edits — especially
           exclusions added to an existing policy, which is how you weaken CA
           without the diff looking like a weakening."

/query: visibility-plane writes
  note:   "Diagnostic settings deleted, audit sinks disabled or re-routed,
           retention shortened. Nobody hardens a foothold and leaves the
           cameras running. These are rarer and heavier than the identity
           moves — in a quiet estate this query alone is nearly a tripwire."

## Judge the actor, not the event

/baseline: which identities normally make admin-plane changes, and which kinds
  window: 30d
  note:   "The changing population is small and stable — a handful of admins
           and a handful of automation identities, each with its own subset of
           change types. The load-bearing question is not 'did a CA policy
           change' but 'has THIS identity ever changed one before'."

/query: clustering — multiple hardening moves in one actor-session
  note:   "Real admin work is single-purpose: one ticket, one change. A session
           that creates an account, grants it a role, AND touches CA or
           logging inside an hour is doing eviction-resistance, and the
           cluster is far stronger evidence than any member of it."

/pivot: how the acting identity's session began
  note:   "Walk back to the sign-in behind the change. If the actor's own
           authentication was out of character — new geo, new device, MFA
           registration minutes before — this lead and the sign-in hunt's lead
           are the same intrusion, and the narrative should join them."

## Rule out the boring explanation

/enrichment: change records or maintenance windows covering the change
  note:   "Most estates cannot join tickets to audit events cleanly; do what is
           possible and say what was not. A change with a matching ticket and a
           familiar actor dies here. A 2 a.m. federation edit by an account
           that has never made one, with no window in sight, does not."

## Emit

/lead: foothold-hardening change without matching context
  entity: actor
  note:   "Evidence carries the change events, the actor's change history (or
           its absence), the session cluster, and the sign-in behind it.
           Recommend the reader treat the artifacts as live until disproven —
           an account created in a move like this is not cleanup-safe just
           because it has not been used yet."
