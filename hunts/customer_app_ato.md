---
kind: hunt
title: "Customer-facing logins that work but do not belong to the customer"
subtitle: "Credential stuffing that lands, account takeover, enumeration and scraping against the estate's own applications"
category: identity
owner: "team · soc-leads"
authored: 2026-08-03
schedule: "0 6 * * *"
timezone: "UTC"
lookback_window: 24h
telemetry:
  all_of:
    - application.authentication
  optional:
    - network.waf
mitre_tactic: credential-access
mitre_technique: T1110.004
budget:
  max_turns: 40
  max_tool_calls: 120
  max_rows: 6000
  max_wall_seconds: 900
tags:
  - identity
  - account-takeover
  - credential-stuffing
  - abuse
---
# Customer-facing logins that work but do not belong to the customer

**Hypothesis:** attacks on customer applications abuse *working* functionality — a login that succeeds, a lookup that answers, a page that renders — so nothing errors and nothing alerts. Stuffing, takeover, enumeration and scraping each leave a statistical silhouette that no single request shows: failure ratios, account-per-source spreads, and post-login behaviour the real customer never exhibits.

## Stuffing, and the part of it that landed

/query: per-source authentication outcomes — failures, successes, distinct accounts
  window: 24h
  from:   app_auth
  note:   "The stuffing fingerprint is many accounts × few attempts each —
           the inverse of brute force. High-failure sources are the easy
           half; the hunt's real product is the SUCCESSES inside those
           sources. A 2% hit rate on ten thousand attempts is two hundred
           compromised customers, and those two hundred are the lead."

/query: distributed variants of the same shape
  note:   "Serious stuffing spreads sources thin to stay under per-IP limits.
           Re-aggregate by ASN, user-agent family and interval texture —
           a thousand IPs each trying six accounts with identical pacing is
           one actor, and the per-IP view was designed to hide that."

## What the landed accounts did next

/pivot: post-login behaviour of accounts that succeeded from flagged sources
  note:   "Takeover has a rhythm the owner does not: immediate email or
           password change, payout or delivery detail edits, value
           extraction — orders, gift balances, stored cards — all in one
           short session from an infrastructure the account has never used.
           Compare against the account's own history; customers are
           creatures of habit and the contrast is usually stark."

## Enumeration and scraping

/query: response-differential probing on lookup and reset endpoints
  window: 24h
  from:   waf_logs
  note:   "Password-reset and login endpoints that answer differently for
           valid and invalid identifiers are oracles, and a source walking
           an identifier space through one is building the target list for
           next week's stuffing run. High volume, low variety, and an
           ordered identifier sequence is the shape."

/query: sessions consuming content at inhuman depth or rate
  note:   "Scraping is abuse of the working product too: catalogue walks,
           price harvesting, profile mass-reads. Judge per session against
           the endpoint's human baseline — depth-per-session and pages-per-
           minute separate a browser from a harvester better than any
           user-agent string, which is trivially forged."

## Rule out the boring explanation

/baseline: known aggregators, partners, and load-test windows for the app
  note:   "Legitimate partners hit APIs with inhuman rhythm by design, and
           marketing does run campaigns that spike logins from odd geos.
           The partner population is enumerable — check it, and check the
           campaign calendar, before promoting a source. A partner IP
           showing STUFFING texture is not cleared by being a partner."

## Emit

/lead: authentication or usage pattern inconsistent with genuine customers
  entity: account
  note:   "Two audiences read this lead: security wants the source
           infrastructure and its texture; the fraud side wants the list of
           landed accounts with the post-login evidence per account. Carry
           both, and mark clearly which accounts show takeover BEHAVIOUR
           versus merely a suspicious login — the response differs, and the
           lead should not force the reader to re-derive the split."
