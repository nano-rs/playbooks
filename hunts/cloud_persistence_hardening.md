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
hypothesis: "An intruder who lands in a tenant spends the first quiet hour making eviction harder: a spare account granted a role, credentials added to an application, a federation or IdP trust changed, an exclusion added to conditional access, a trail, sink or diagnostic setting deleted. Every one of those is also routine admin work, so the tell is the actor (one who has never made that kind of change), the clustering (several hardening moves from one identity in one window) and the missing change context."
risk_weight: 7
default_severity: high
pivots:
  - name: admin_plane_census
    role: coverage
    query: 'class_uid=6003 | stats count, dc(actor.user.name) AS actors, dc(api.operation) AS operations by cloud.provider, metadata.product.name | sort -count | head 50'
  - name: identity_plane_writes
    role: discovery
    query: 'class_uid=6003 (api.operation IN ("CreateUser","CreateLoginProfile","UpdateLoginProfile","CreateAccessKey","AttachUserPolicy","AttachRolePolicy","PutUserPolicy","PutRolePolicy","AddUserToGroup","UpdateAssumeRolePolicy","CreateSAMLProvider","UpdateSAMLProvider","CreateOpenIDConnectProvider","google.iam.admin.v1.CreateServiceAccount","google.iam.admin.v1.CreateServiceAccountKey","SetIamPolicy","Add user.","Add member to role.","Add service principal.","Add service principal credentials.","Set domain authentication.","Set federation settings on domain.") OR api.operation=*roleassignments/write* OR api.operation CONTAINS "conditional access" OR api.operation CONTAINS "federation" OR api.operation CONTAINS "certificates and secrets") | stats count, dc(api.operation) AS distinct_ops, values(api.operation) AS operations, values(resources.name) AS resources, min(timestamp) AS first_seen, max(timestamp) AS last_seen by actor.user.name, src_endpoint.ip, cloud.provider | sort -distinct_ops, -count | head 200'
    scorer:
      method: zscore
      field: distinct_ops
      threshold: 2
  - name: visibility_plane_writes
    role: discovery
    query: 'class_uid=6003 (api.operation IN ("DeleteTrail","StopLogging","UpdateTrail","PutEventSelectors","DeleteFlowLogs","DeleteDetector","UpdateDetector","DeleteConfigurationRecorder","StopConfigurationRecorder","DeleteDeliveryChannel","DisableSecurityHub","DeleteLogGroup","PutRetentionPolicy","DeleteSubscriptionFilter","google.logging.v2.ConfigServiceV2.DeleteSink","google.logging.v2.ConfigServiceV2.UpdateSink","google.logging.v2.ConfigServiceV2.UpdateBucket","google.logging.v2.ConfigServiceV2.CreateExclusion") OR api.operation=*diagnosticsettings/delete* OR api.operation=*diagnosticsettings/write*) | stats count, values(api.operation) AS operations, values(resources.name) AS resources, values(status) AS outcomes, min(timestamp) AS first_seen, max(timestamp) AS last_seen by actor.user.name, src_endpoint.ip, cloud.provider, cloud.account.uid | sort -count | head 200'
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
           without the diff looking like a weakening. The identity_plane_writes pivot lists these per actor (AWS IAM, GCP IAM, Azure role assignments, Entra role, credential, federation and conditional-access operations)."

/query: visibility-plane writes
  note:   "Diagnostic settings deleted, audit sinks disabled or re-routed,
           retention shortened. Nobody hardens a foothold and leaves the
           cameras running. These are rarer and heavier than the identity
           moves — in a quiet estate this query alone is nearly a tripwire. The visibility_plane_writes pivot lists trail, flow-log, detector, config-recorder, log-sink and diagnostic-setting changes per actor."

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
           cluster is far stronger evidence than any member of it. identity_plane_writes already counts distinct operations per actor in the window (distinct_ops, zscore scored); check visibility_plane_writes for the same actor."

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
