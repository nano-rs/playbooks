---
kind: hunt
title: "Risky mail followed by execution on the recipient's endpoint"
subtitle: "The join no detection rule does — gateway-flagged deliveries correlated with what the recipient's machine did in the next four hours"
category: email
owner: "team · soc-leads"
authored: 2026-08-03
schedule: "0 */6 * * *"
timezone: "UTC"
lookback_window: 12h
telemetry:
  all_of:
    - email.gateway
    - endpoint.process
mitre_tactic: initial-access
mitre_technique: T1566.001
budget:
  max_turns: 40
  max_tool_calls: 120
  max_rows: 6000
  max_wall_seconds: 900
tags:
  - email
  - phishing
  - initial-access
---
# Risky mail followed by execution on the recipient's endpoint

**Hypothesis:** the gateway and the EDR each hold half of a finding neither can emit. Mail that was scored risky but delivered anyway is a daily flood the gateway cannot act on; process activity on an endpoint is ambiguous without a reason to look. Joined on recipient and time — delivery, then execution within four hours — the two halves become the earliest reliable picture of a phish that worked. No rule does this join; that is exactly why a hunt should.

## The risky-but-delivered set

/query: deliveries the gateway disliked but let through
  window: 12h
  from:   email_gateway
  note:   "High phish/spam scores under the block threshold, newly registered
           sender domains, first-contact senders with attachments or
           rewritten URLs, and anything released from quarantine by a user
           or an admin. Releases deserve their own respect — somebody
           overrode the machine's judgment, and attackers engineer exactly
           that override."

## The join

/pivot: each recipient to their endpoint, execution within four hours of delivery
  note:   "The window is the contract: wide enough for a coffee break between
           read and click, tight enough that a match still means something.
           Shapes that count as execution context: Office spawning script
           hosts or shells, archive extraction followed by a run,
           first-seen binaries appearing under user profile paths, LNK or
           container-file mounts — the same vocabulary as the drive-by hunt,
           arriving by mail instead of browser."

/query: for campaign bursts, the endpoint of EVERY recipient — not a sample
  note:   "When the same lure hit fifty inboxes, the yield is not fifty times
           one check; it is the ONE recipient out of fifty who ran it.
           Sampling is how that recipient is missed, and the burst is what
           makes exhaustive checking affordable — one lure analysis, N cheap
           endpoint probes. Report the denominator: '1 execution across 47
           recipients' is a sentence that triages itself."

## Corroborate and scope

/query: post-execution behaviour on matched endpoints
  note:   "Delivery→execution is a strong prior, not a verdict. Outbound
           connections to young domains, credential prompts, persistence
           writes, or a process tree deepening in the minutes after turn
           the match into a story. Their absence softens it — say which."

/enrichment: sender infrastructure and lure URL provenance
  note:   "Domain age, registrar, hosting, and whether the same
           infrastructure mailed other tenants of the estate. This dates and
           scopes the campaign; it does not decide the lead — the endpoint
           evidence already did."

## Rule out the boring explanation

/baseline: the recipient's normal relationship with this kind of execution
  note:   "Some users run macro-laden spreadsheets from external partners
           every single day, and their execution 'match' is Tuesday. The
           recipient's own history is the filter — a first-ever Office→shell
           chain on THIS machine is not softened by other machines doing it
           routinely."

## Emit

/lead: gateway-flagged delivery followed by recipient-endpoint execution
  entity: user
  note:   "Evidence is the join laid bare: message metadata and score, the
           delivery-to-execution interval, the process chain, and the
           post-execution timeline. For campaigns, include the full
           recipient roll with per-recipient outcome — the reader's next
           question is always 'who else got it', and the hunt already paid
           for that answer."
