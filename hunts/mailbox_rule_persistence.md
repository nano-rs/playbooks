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
hypothesis: "The first durable thing a mailbox intruder does is write a rule: forward or redirect a copy outside, or delete, mark read or bury the replies that would expose the fraud, usually minutes after an out-of-character sign-in and often via EWS or Graph from an unfamiliar client. Transport rules, journal changes and new connectors are the same moves at tenant scope. The benign twins are old, openly-known forwarding to personal mail and assistants managing delegated executive inboxes."
risk_weight: 7
default_severity: medium
pivots:
  - name: mailbox_audit_census
    role: coverage
    query: "class_uid=6003 | stats count, dc(actor.user.name) AS actors, dc(api.operation) AS operations by api.service.name | sort -count | head 50"
  - name: inbox_rule_changes
    role: discovery
    query: 'class_uid=6003 (api.operation CONTAINS "inboxrule" OR api.operation="Set-Mailbox" OR api.operation CONTAINS "forwarding" OR api.operation CONTAINS "email_forwarding") | eval forwards=if(raw_data CONTAINS "forward" OR raw_data CONTAINS "redirect", 1, 0), conceals=if(raw_data CONTAINS "deletemessage" OR raw_data CONTAINS "markasread" OR raw_data CONTAINS "rss" OR raw_data CONTAINS "conversation history" OR raw_data CONTAINS "softdelete", 1, 0), finance_terms=if(raw_data CONTAINS "invoice" OR raw_data CONTAINS "payment" OR raw_data CONTAINS "wire" OR raw_data CONTAINS "bank" OR raw_data CONTAINS "password", 1, 0) | table id, timestamp, actor.user.name, api.operation, resources.name, src_endpoint.ip, http_request.user_agent, session.uid, forwards, conceals, finance_terms | sort -timestamp | head 200'
  - name: transport_and_connector_changes
    role: discovery
    query: 'class_uid=6003 (api.operation CONTAINS "transportrule" OR api.operation CONTAINS "journalrule" OR api.operation CONTAINS "outboundconnector" OR api.operation CONTAINS "inboundconnector" OR api.operation CONTAINS "remotedomain") | stats count AS changes, values(api.operation) AS operations, values(resources.name) AS objects, values(src_endpoint.ip) AS source_ips, min(timestamp) AS first_change, max(timestamp) AS last_change by actor.user.name | sort -changes | head 100'
  - name: rule_author_signins
    role: discovery
    query: '(class_uid=3002 user.name!="") OR (class_uid=6003 actor.user.name!="" (api.operation=*inboxrule* OR api.operation="set-mailbox")) | eval who=lower(if(class_uid=6003, actor.user.name, user.name)), author=if(class_uid=6003, 1, 0) | eventstats max(author) AS wrote_rule by who | where class_uid=3002 AND wrote_rule=1 | eval failed=if(status_id=2, 1, 0), basic=if(auth_protocol_id=11, 1, 0) | stats count AS signins, sum(failed) AS failed_signins, sum(basic) AS basic_auth_signins, dc(src_endpoint.location.country) AS countries, values(src_endpoint.location.country) AS country_list, values(src_endpoint.autonomous_system.name) AS asn_list, values(src_endpoint.ip) AS signin_ips, min(timestamp) AS first_signin, max(timestamp) AS last_signin by user.name | sort -countries, -signins, user.name | head 200'
budget:
  max_turns: 40
  max_tool_calls: 100
  max_rows: 5000
  max_wall_seconds: 900
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
           enumerate all of them rather than keying on one operation name.
           The inbox_rule_changes pivot lists them with forward, conceal and
           finance-term flags from raw_data; read the rule parameters there."

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
           hunt's story landing in this one. The transport_and_connector_changes
           pivot lists them per actor."

## The session behind the rule

/pivot: the sign-in context in which each flagged rule was created
  note:   "This join is what turns a rule from odd to conclusive. A rule
           created minutes after a sign-in that was itself out of character
           — new geo, new device, legacy protocol — welds this lead to the
           sign-in hunt's lead; one intrusion, two windows. Rule creation
           via EWS or Graph from an unfamiliar client is its own tell even
           when the sign-in looked clean. The rule_author_signins pivot
           already summarizes each rule author's sign-ins in the window."

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
