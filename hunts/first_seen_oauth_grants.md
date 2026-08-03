---
kind: hunt
title: "OAuth grants and tokens this estate has never seen before"
subtitle: "Consent phishing, rogue integrations and freshly minted PATs — first-seen apps weighted by the scopes they asked for"
category: identity
owner: "team · soc-leads"
authored: 2026-08-03
schedule: "0 5 * * *"
timezone: "UTC"
lookback_window: 24h
telemetry:
  one_of:
    - identity.admin_audit
    - cicd.audit
  optional:
    - identity.authentication
mitre_tactic: credential-access
mitre_technique: T1528
budget:
  max_turns: 40
  max_tool_calls: 120
  max_rows: 5000
  max_wall_seconds: 900
tags:
  - identity
  - oauth
  - tokens
  - consent-phishing
---
# OAuth grants and tokens this estate has never seen before

**Hypothesis:** the modern credential theft does not touch a password — it convinces a user to consent, or mints a token, and walks in through an integration. Every grant and every token has a first-seen moment in the tenant, and the malicious ones cluster there: new app, few users, greedy scopes, and a consent that arrived minutes after a lure.

## The new arrivals

/query: first-seen OAuth applications and consent grants
  window: 24h
  from:   entra_audit
  note:   "First-seen for THIS tenant, not first-seen globally. Rank by scope
           appetite: offline_access, mail read, files read-all and
           full_access_as_app carry the hunt; a first-seen app asking for
           openid and profile is barely worth the row it arrived in."

/query: token and PAT minting in source-control
  window: 24h
  from:   github_audit
  note:   "New personal access tokens, new deploy keys, new OAuth app
           authorizations against the org. Weight by scope breadth and by the
           account's history — a PAT with repo and org scope from an account
           that has never minted one, or minting from a new network, is the
           source-control mirror of consent phishing."

## Judge the app and the moment

/enrichment: publisher, verification status, and registration age of the app
  note:   "An app registered last week, unverified, with a name one edit away
           from a product everyone uses ('Microsoft 0ffice Sync') is the
           classic. Treat publisher verification as corroboration only —
           attackers do buy and burn verified publishers."

/pivot: the consenting user's sign-in shape around the grant
  note:   "Consent phishing lands AFTER a lure: check whether the consent
           followed a suspicious sign-in, a link click, or arrived out of the
           user's working hours. A grant whose surrounding session is itself
           out of character joins this lead to the sign-in hunt's story."

/query: what the app or token did with its access
  note:   "Grants are intent; usage is action. Mail rules created via Graph,
           bulk file reads, or repo clones by a day-old token move the lead
           from 'revoke and shrug' to 'scope the theft'. No usage yet is
           still a lead — it is just an earlier one."

## Rule out the boring explanation

/baseline: how many users consented, over how long
  note:   "Legitimate SaaS adoption is many users consenting to a known
           publisher over weeks, usually trailing an announcement. One user
           consenting to a day-old app is the inverse on every axis. The
           middle case — a team lead consenting to a niche tool their team
           adopts — is why the publisher and scope checks exist."

## Emit

/lead: first-seen grant or token with greedy scope and thin provenance
  entity: app
  note:   "Evidence carries the scopes verbatim, the app's age and publisher
           status, the consenting user and their session context, and any
           usage observed. Scopes matter more than app names to the reader —
           an ugly name with read-profile is nothing; a pretty name with
           full_access_as_app is the finding."
