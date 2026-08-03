---
kind: hunt
title: "Mailbox rules that steal, hide, or forward"
subtitle: "Auto-forwarding to external, rules that eat replies from finance and security, and rule creation joined to out-of-character sessions"
category: email
owner: "team · soc-leads"
authored: 2026-08-03
schedule: "30 2 * * *"
timezone: "UTC"
lookback_window: 24h
telemetry:
  all_of:
    - mailbox.audit
  optional:
    - identity.authentication
mitre_tactic: collection
mitre_technique: T1114.003
budget:
  max_turns: 30
  max_tool_calls: 100
  max_rows: 4000
  max_wall_seconds: 600
tags:
  - email
  - bec
  - persistence
---
# Mailbox rules that steal, hide, or forward

**Hypothesis:** the first durable thing a mailbox intruder does is write a rule — forward a copy out, or delete the replies that would give the game away. Rules are the BEC trade's whole persistence layer, they are written in the first minutes of access, and every creation is auditable. The population of new rules per day is small enough to judge one by one, which most estates never do.

## The rules themselves

/query: new or modified inbox rules that forward or redirect
  window: 24h
  from:   m365_audit
  note:   "External destinations first — free-mail domains, lookalikes of
           the org's own domain, and addresses the mailbox has never
           corresponded with rank highest. Forward-as-attachment and
           redirect variants are the same move wearing different verbs;
           enumerate all of them rather than keying on one operation name."

/query: rules that delete, mark read, or bury on arrival
  note:   "The concealment half. Conditions matching invoice, payment,
           wire, bank, password, or the display names of finance staff and
           security tooling, paired with delete/mark-read/move-to-RSS-or-
           Notes actions, exist for exactly one purpose: keeping the
           mailbox owner from seeing the conversation being had in their
           name. A rule filing mail from the org's OWN security sender is
           a finding on its own."

/query: tenant-level mail-flow changes
  note:   "The same two moves at transport scope — new transport rules that
           BCC or redirect, journal changes, new outbound connectors — are
           rarer, admin-authored, and worth more. Cross-check the actor
           against the cloud persistence hunt's actor baseline; a transport
           rule from an account that has never touched mail flow is that
           hunt's story landing in this one."

## The session behind the rule

/pivot: the sign-in context in which each flagged rule was created
  note:   "This join is what turns a rule from odd to conclusive. A rule
           created minutes after a sign-in that was itself out of character
           — new geo, new device, legacy protocol — welds this lead to the
           sign-in hunt's lead; one intrusion, two windows. Rule creation
           via EWS or Graph from an unfamiliar client is its own tell even
           when the sign-in looked clean."

/query: what else the session did in the mailbox
  note:   "Search terms, MFA-reset mails read, drafts created but not sent,
           OAuth consents granted. BEC sessions rehearse — the rule plus a
           search for 'wire instructions' inside one session is a narrative
           the reader should get pre-assembled."

## Rule out the boring explanation

/baseline: the mailbox owner's rule-writing history and delegation setup
  note:   "People do forward to personal mail — chronically, openly, and
           usually with a rule that is months old. Assistants manage
           executive inboxes with aggressive filing rules. The boring cases
           are OLD rules and DELEGATED authorship; a first-ever forwarding
           rule, external, created by the account itself from a new
           session, fails every boring test at once. Personal-mail
           forwarding that IS legitimate is still a policy exposure —
           report it in the narrative as that, not as an intrusion lead."

## Emit

/lead: rule creation consistent with mailbox compromise
  entity: user
  note:   "Evidence carries the rule verbatim — conditions, actions,
           destination — the creating session with its context, and
           anything the session did besides. Recommend the reader check
           the forward destination's inbox-side history: how long mail has
           actually been flowing there is the dwell-time estimate, and the
           audit trail of the rule's creation date sets the floor."
