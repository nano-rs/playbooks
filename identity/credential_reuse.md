---
title: "Credential reuse — offboarded / dormant account"
subtitle: "Attacker using old credentials for a user who has since left or gone inactive"
category: identity
owner: "team · soc-leads"
authored: 2025-11-14
match_signals:
  - access_key.used
  - offboarded
  - dormant_account
  - iam.credential_reuse
danger_policy:
  "action:high": approval
  "action:medium": auto
  "action:low": auto
review_cadence: 90d
scope: tenant
tags:
  - identity
  - offboarding
  - iam
---
# Credential reuse · offboarded / dormant account

Agent-first identity investigation for the pattern **"account that shouldn't be active is active."** Runs the auth history, HR cross-check, and blast-radius queries automatically, then asks you two decisions.

## Phase 1 · establish state

/enrichment: HR system · is the user currently employed
  system: workday
  employee: {{entity.user}}
  fields: status, end_date, manager, team

/query: last 30d of auth events for this user
  window: 30d
  from:   auth-events
  where:  class_uid = 3002 AND (user.name = {{entity.user}} OR actor.user.name = {{entity.user}})
  group:  by day
  note:   "looking for the silhouette of a live account vs a resurrected one"

/pivot: every access-key this user has owned
  from:   iam-keys
  where:  owner = {{entity.user}}
  show:   key_id, created, last_used, status

## Phase 2 · decide what we're looking at

/decision: is this a live user account?
  options:
    - yes · user is employed and active
    - no · user is offboarded
    - partial · employed but on leave / role changed
  note_required_on: no, partial

/review: check the key-use timeline against the HR end_date
  hint: "any key use after end_date is the smoking gun"

## Phase 3 · scope the blast radius

/query: every action taken by this actor in the last 24h
  window: 24h
  from:   cloudtrail
  where:  class_uid = 6003 AND actor.user.name = {{entity.user}}
  show:   timestamp, api.operation, resources.name, src_endpoint.ip

/pivot: resources touched — did any succeed?
  from:   cloudtrail
  where:  class_uid = 6003 AND actor.user.name = {{entity.user}} AND status_id = 1
  group:  by api.operation

/enrichment: source IP reputation
  services: greynoise, spur, ipinfo
  ip: {{entity.ip}}

## Phase 4 · containment

/action: rotate or disable the compromised credential
  kind:   iam.key_rotate
  target: {{entity.key_id}}
  danger: medium
  reversible: true

/action: revoke active sessions for this user
  kind:   auth.session_revoke
  target: {{entity.user}}
  danger: medium
  reversible: false
  require_approval: false

/action: disable the IAM user
  kind:   iam.user_disable
  target: {{entity.user}}
  danger: high
  reversible: true
  require_approval: true
  note: "only after Phase 2 confirmed offboarded"

## Phase 5 · close out

/decision: root-cause category
  options:
    - offboarding gap · HR → IAM deprovisioning failed
    - credential theft · key leaked (paste, repo, laptop)
    - third-party compromise · upstream saas breach
    - other

/action: create a tuning ticket if this is a recurring pattern
  kind:   ticket.create
  target: soc-engineering
  body:   "consider auto-disable on HR offboarding webhook"
