---
title: "MFA bypass / push fatigue"
subtitle: "Repeated MFA challenges, accepted push from new geo, session token hijack"
category: identity
owner: "team · soc-leads"
authored: 2025-09-02
match_signals:
  - mfa.fatigue
  - push_accepted_new_device
  - session.hijack
danger_policy:
  "action:high": approval
  "action:medium": auto
  "action:low": auto
review_cadence: 90d
scope: tenant
tags:
  - identity
  - mfa
  - session
---
# MFA bypass · push fatigue

Suspected **MFA fatigue** (spam push until approve) or **token replay**. Run the challenge pattern + device trust check; flag to IR if the device is new.

/query: MFA events for this user in the last 4h
  window: 4h
  from:   idp-events
  where:  user = {{entity.user}} AND event ~ /mfa/
  show:   ts, event, device_id, ip, result

/enrichment: device trust posture
  system: okta
  user:   {{entity.user}}
  fields: device_id, trust, first_seen, os

/decision: was a push accepted from a new or untrusted device?
  options: [yes, no]

/action: revoke active sessions
  kind:   auth.session_revoke
  target: {{entity.user}}
  danger: medium

/action: require MFA re-enrollment
  kind:   idp.mfa_reset
  target: {{entity.user}}
  danger: low
