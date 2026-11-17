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
hypothesis: "An account that exists for machine-to-machine use authenticates from a small fixed set of hosts with network, batch or service logons, never interactively. An interactive (type 2) or remote-interactive (type 10) logon by such an account means the credential was taken or an engineer is using it as a personal login. The benign twin is maintenance on the account's own server, during a window, by someone who stays on that host."
risk_weight: 6
default_severity: medium
pivots:
  - name: logon_type_census
    role: coverage
    query: "class_uid=3002 activity_id=1 | stats count, dc(user.name) AS accounts by logon_type_id"
  - name: named_service_accounts_interactive
    role: discovery
    query: 'class_uid=3002 activity_id=1 status_id=1 logon_type_id IN (2, 10, 11, 12) (user.name CONTAINS "svc" OR user.name CONTAINS "service" OR user.name STARTSWITH "srv" OR user.name STARTSWITH "sa_" OR user.name STARTSWITH "sa-") NOT user.name ENDSWITH "$" | stats count AS interactive_logons, dc(dst_endpoint.hostname) AS target_hosts, values(dst_endpoint.hostname) AS target_host_list, values(src_endpoint.ip) AS source_ips, values(src_endpoint.hostname) AS source_hosts, values(logon_type_id) AS logon_types, min(timestamp) AS first_seen by user.name | sort -interactive_logons | head 200'
  - name: machine_shaped_accounts_interactive
    role: discovery
    query: 'class_uid=3002 activity_id=1 status_id=1 logon_type_id IN (2, 3, 4, 5, 10, 11, 12) NOT user.name ENDSWITH "$" | eval interactive=if(logon_type_id==2 || logon_type_id==10 || logon_type_id==11 || logon_type_id==12,1,0) | stats count AS logons, sum(interactive) AS interactive_logons, dc(src_endpoint.ip) AS sources, dc(dst_endpoint.hostname) AS target_hosts by user.name | eval machine_share=(logons-interactive_logons)/logons | where interactive_logons >= 1 AND logons >= 50 AND machine_share >= 0.95 | sort -logons | head 200'
budget:
  max_turns: 40
  max_tool_calls: 90
  max_rows: 5000
  max_wall_seconds: 900
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
  where:  metadata.event_code = "4624"
  note:   "Do not rely on the naming convention alone — svc_* is a hint, not a
           definition, and the interesting account is often the one that was
           never named like one. Prefer the behavioural signature: authenticates
           from a small fixed set of hosts, at machine-regular intervals, and
           never with logon type 2 or 10. The machine_shaped_accounts_interactive
           pivot measures that signature inside the sweep window."

/baseline: per-account logon-type distribution over the trailing 30 days
  note:   "The comparison that matters is against the account's OWN history, not
           against other accounts. A service account that has always logged on
           interactively is a policy problem, not an intrusion; one that started
           yesterday is the finding."

## Look for the deviation

/query: interactive and remote-interactive logons for the candidate population
  window: 24h
  from:   windows_security
  where:  metadata.event_code = "4624" and logon_type_id in (2, 10)
  note:   "Type 2 is at-the-console, type 10 is RDP. Either is out of character
           for an account that should only ever produce type 3. The
           named_service_accounts_interactive pivot lists these logons with
           their source and target hosts."

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
