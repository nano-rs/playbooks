---
kind: hunt
title: "Service account authenticating interactively"
subtitle: "Accounts provisioned for machine-to-machine use logging on the way a person would"
category: identity
owner: "team · soc-leads"
authored: 2026-07-30
schedule: "0 3 * * *"
timezone: "UTC"
lookback_window: 24h
telemetry:
  all_of:
    - identity.authentication
mitre_tactic: lateral-movement
mitre_technique: T1078.002
budget:
  max_turns: 30
  max_tool_calls: 90
  max_rows: 4000
  max_wall_seconds: 600
tags:
  - identity
  - service-accounts
  - valid-accounts
---
# Service account authenticating interactively

**Hypothesis:** an account that exists to let one machine talk to another should never produce the authentication silhouette of a human sitting at a keyboard. When it does, either someone has taken the credential, or an engineer is using it as a personal login — and both are worth knowing.

This is a good nightly hunt because the negative case is genuinely quiet. Most estates have a stable, small set of service accounts with a stable, boring logon pattern, so a deviation is legible rather than statistical.

## Establish the population

/query: candidate service accounts by naming convention and behaviour
  window: 30d
  from:   windows_security
  where:  event_id = 4624
  note:   "Do not rely on the naming convention alone — svc_* is a hint, not a
           definition, and the interesting account is often the one that was
           never named like one. Prefer the behavioural signature: authenticates
           from a small fixed set of hosts, at machine-regular intervals, and
           never with logon type 2 or 10."

/baseline: per-account logon-type distribution over the trailing 30 days
  note:   "The comparison that matters is against the account's OWN history, not
           against other accounts. A service account that has always logged on
           interactively is a policy problem, not an intrusion; one that started
           yesterday is the finding."

## Look for the deviation

/query: interactive and remote-interactive logons for the candidate population
  window: 24h
  from:   windows_security
  where:  event_id = 4624 and logon_type in (2, 10)
  note:   "Type 2 is at-the-console, type 10 is RDP. Either is out of character
           for an account that should only ever produce type 3."

/pivot: what the account did after the interactive session began
  note:   "An operator troubleshooting with a shared credential looks different
           from an intruder: the former stays on the host it logged into and
           touches the service it maintains, the latter reaches outward. Follow
           the session rather than stopping at the logon."

## Rule out the boring explanation

/enrichment: is the source host one this account normally authenticates from
  note:   "A service account used interactively ON ITS OWN SERVER during a
           maintenance window is sloppy practice, not an incident. The same
           credential used interactively from a workstation in another subnet
           is not the same thing at all."

/baseline: has this account:host pair been seen before
  note:   "First-seen matters more than volume here. One logon from a host that
           has never seen this account beats a hundred from one that has."

## Emit

/lead: interactive logon by a machine-to-machine account
  entity: user
  note:   "Evidence should carry the logon events themselves plus whatever the
           session went on to do — a lead with only the 4624 is hard to triage
           and will be dismissed on sight, which trains the suppression list
           against you.

           Say plainly in the narrative which benign explanation was checked and
           why it did not hold. A lead that has not ruled out the maintenance
           window is a question, not a finding."
