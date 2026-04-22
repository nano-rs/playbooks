---
title: "Suspicious OAuth app consent"
subtitle: "Third-party app granted broad mailbox permissions"
category: email
authored: 2025-08-05
match_signals:
  - oauth.consent_broad
  - app.mail_read
danger_policy:
  "action:high": approval
  "action:medium": auto
  "action:low": auto
review_cadence: 90d
scope: tenant
tags:
  - email
  - oauth
  - saas
---
# OAuth app consent

/enrichment: app publisher + reputation
  from:   idp-oauth-apps
  app_id: {{entity.app_id}}
  fields: publisher, verified, scopes, users_consented

/query: other users who granted this app consent
  window: 30d
  from:   idp-events
  where:  app_id = {{entity.app_id}} AND event = oauth.consent

/decision: is the app approved or known-good?
  options: [yes — approved, no — unknown, no — malicious]

/action: revoke app consent for all users
  kind:   oauth.revoke_app
  target: {{entity.app_id}}
  danger: medium
  require_approval: true
