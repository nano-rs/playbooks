---
kind: hunt
title: "Kerberos tickets requested the way crackers need them, not the way computers use them"
subtitle: "Roasting harvests, pre-auth-disabled accounts under request, and tickets whose properties no DC should have issued"
category: identity
owner: "team · soc-leads"
authored: 2026-08-03
schedule: "30 1 * * *"
timezone: "UTC"
lookback_window: 24h
telemetry:
  all_of:
    - identity.kerberos
mitre_tactic: credential-access
mitre_technique: T1558.003
budget:
  max_turns: 40
  max_tool_calls: 120
  max_rows: 6000
  max_wall_seconds: 900
tags:
  - identity
  - kerberos
  - active-directory
---
# Kerberos tickets requested the way crackers need them, not the way computers use them

**Hypothesis:** legitimate Kerberos is need-driven — a client requests a service ticket because it is about to talk to that service, so requests are sparse, repeated, and RC4-free on a modern domain. A roasting attack inverts every property: one principal requesting tickets for *many* services it never contacts, in one burst, preferring the encryption type that cracks fastest. The DC logs all of it; almost nobody reads it.

This hunt needs ticket events from the domain controllers (4768/4769) with encryption-type fields populated. That is precisely the kind of assumption that rots — run `environment_recon` against it before trusting a quiet first sweep, and let this hunt HOLD rather than sweep a half-fed source.

## The harvest shape

/query: per principal, distinct service tickets requested in the window
  window: 24h
  from:   windows_security
  note:   "Kerberoasting is a breadth event: one account pulling TGS tickets
           for ten, fifty, two hundred distinct SPNs in minutes — services
           it has never authenticated to and never will. Ordinary clients
           accumulate distinct SPNs slowly and re-request the same few.
           Keep the requesting host: a harvest from a workstation carries a
           different story than one from a domesticated automation box."

/query: RC4 service tickets on a domain that has moved past RC4
  note:   "Crackers request RC4 because it is orders of magnitude cheaper to
           brute. On most estates the residual RC4 population is a small,
           stable set of legacy services — learn it, then treat an RC4
           ticket OUTSIDE that set, especially paired with the breadth
           shape above, as the roast it almost certainly is. Etype
           downgrade for an account that normally issues AES is the same
           signal in one event."

## The accounts that skip the handshake

/query: authentication requests for accounts with pre-authentication disabled
  window: 24h
  note:   "AS-REP roasting needs no credentials at all — just the account
           list. Pre-auth-disabled accounts are rare and enumerable; a
           request burst against several of them from one source is
           somebody working through that list. The population itself
           belongs in the sweep narrative: every entry is standing attack
           surface someone chose to keep."

## Tickets that should not exist

/query: service-ticket activity with no plausible ticket-granting history behind it
  note:   "Forged-ticket tells are property anomalies: session activity for
           an account with no corresponding TGT issuance visible, ticket
           lifetimes far beyond domain policy, or logons whose account
           SIDs and group memberships do not match the directory. Any one
           of these is worth the pivot — golden and silver tickets do not
           announce themselves twice."

## Rule out the boring explanation

/enrichment: is the requesting host a scanner, an identity product, or a pentest in progress
  note:   "Vulnerability scanners kerberoast on schedule as a check, and so
           do some identity-posture products — their harvests are periodic,
           from fixed hosts, against the same SPN census every time. An
           authorized red team is the other repeat customer; check the
           engagement calendar before the narrative says intruder."

/pivot: what the harvesting principal did before and after
  note:   "A roast is a means. Walk back to how the requesting session came
           to exist, and forward to whether any harvested service account
           authenticated somewhere new in the following days — that
           forward join is the difference between 'attempted' and
           'cracked', and it is worth re-checking across sweeps, not just
           within one."

## Emit

/lead: ticket-request pattern consistent with roasting or forgery
  entity: user
  note:   "Evidence carries the request burst with timestamps and etypes,
           the requesting host, the SPN list harvested, and the forward
           check's result. Name the service accounts whose hashes left in
           ticket form — like the credential-harvesting hunt, that list is
           the reader's rotation scope, and cracking happens offline on
           the attacker's clock, not yours."
