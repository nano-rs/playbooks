---
kind: hunt
title: "Quiet edits to who is allowed to do anything on-prem"
subtitle: "Privileged group membership changes, add-use-remove cycles, and GPO modifications — the on-prem sibling of the cloud persistence hunt"
category: identity
owner: "team · soc-leads"
authored: 2026-08-03
schedule: "30 5 * * *"
timezone: "UTC"
lookback_window: 24h
telemetry:
  all_of:
    - identity.privilege_changes
mitre_tactic: privilege-escalation
mitre_technique: T1098
budget:
  max_turns: 40
  max_tool_calls: 120
  max_rows: 5000
  max_wall_seconds: 900
tags:
  - identity
  - active-directory
  - privilege
  - gpo
---
# Quiet edits to who is allowed to do anything on-prem

**Hypothesis:** the cloud persistence hunt watches the tenant's admin plane; this is its on-prem twin. Domain privilege moves through a handful of writable objects — group memberships, GPOs, trusts — and the estate changes them rarely, through known hands, with tickets. An intruder changes them from wherever they landed, and often changes them *back*: the add-use-remove cycle is the single most diagnostic shape on-prem hunting has, because legitimate administration has no reason to hide.

## Membership changes that matter

/query: additions to privileged groups, domain and local
  window: 24h
  from:   windows_security
  note:   "The obvious tier — Domain, Enterprise and Schema Admins — plus
           the quietly-equivalent tier attackers prefer BECAUSE it is
           quieter: Backup Operators, DNSAdmins, Server Operators, Account
           Operators, and additions to local Administrators on servers.
           Record WHO added, not just who was added; the actor is half the
           judgment."

/query: add-use-remove cycles
  note:   "Membership granted, a logon or service touched under it, and the
           membership revoked — inside hours. Diff the window's adds
           against its removes on the same principal pair. Legitimate JIT
           privilege systems produce exactly this shape from ONE known
           service identity; the same cycle authored by a human account,
           or by anything not on the PAM carve, is an intruder tidying up
           after themselves. The cleanup is the confession."

## Policy as a delivery vehicle

/query: GPO creations, modifications, and link changes
  note:   "A GPO is remote execution across every machine it links to, with
           SYSTEM privileges and no malware. Rank by blast radius — GPOs
           linked to domain controllers or server OUs first — and by
           payload: scheduled-task and script additions inside a policy
           edit are the shape that turns a policy object into a
           deployment tool. The editing account and the edit's source
           host both belong in evidence."

/query: the heavyweight rarities — trust changes, AdminSDHolder edits, DSRM changes
  note:   "Each of these is nearly a tripwire on its own: new domain
           trusts, ACL edits on AdminSDHolder, DSRM account changes,
           directory-services restore activity. Their legitimate frequency
           in most estates is measured in quarters, so a single event
           carries the sweep."

## Judge the actor

/baseline: which identities make privilege changes here, and from which hosts
  window: 30d
  note:   "Same doctrine as the cloud twin: the changing population is
           small, and the question is never 'did a membership change' but
           'has this identity, from this host, ever made this KIND of
           change'. Privilege changes issued from a workstation that has
           never issued one — or worse, from a server that just appeared
           in the lateral-movement hunt's new edges — is the join that
           decides the lead."

/pivot: what the added principal did with the privilege
  note:   "Walk forward from every surviving add: first logons under the
           new membership, services touched, whether the credential-
           harvesting hunt's shapes follow within the day. Privilege
           granted and unused softens the lead; privilege granted and
           immediately spent on a DC hardens it past argument."

## Rule out the boring explanation

/enrichment: tickets, change windows, and the PAM system's own records
  note:   "Helpdesk staff add people to groups all day with tickets behind
           them, and PAM systems churn add-remove cycles by design. Carve
           the PAM service identity by signer-grade evidence, not name,
           and treat ticket-absence honestly: many real estates have
           ticketless-but-legitimate change; the narrative should weigh
           it, not auto-convict on it."

## Emit

/lead: privilege or policy change outside the estate's administrative pattern
  entity: actor
  note:   "Evidence carries the change events, the actor's history for that
           change kind, the cycle timeline where one exists, and the
           spent-privilege trail. For GPO leads include the policy diff
           itself — the reader must see what the policy now DOES, and
           reconstructing that from event IDs is exactly the rework a
           dismissed lead is made of."
