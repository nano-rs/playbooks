---
kind: hunt
title: "The CRM leaving in report-sized pieces"
subtitle: "Mass exports, API harvesting and first-seen integrations in Salesforce-class SaaS — judged against each user's own working rhythm"
category: data
owner: "team · soc-leads"
authored: 2026-08-03
schedule: "30 6 * * *"
timezone: "UTC"
lookback_window: 24h
telemetry:
  all_of:
    - saas.audit
  optional:
    - identity.authentication
mitre_tactic: collection
mitre_technique: T1213
budget:
  max_turns: 40
  max_tool_calls: 120
  max_rows: 6000
  max_wall_seconds: 900
tags:
  - data
  - saas
  - insider
  - exfiltration
---
# The CRM leaving in report-sized pieces

**Hypothesis:** the business systems — CRM, ITSM, HR, wiki — hold the data a competitor would actually pay for, and they leak through their own front door: report exports, API pulls, list downloads, all performed with valid credentials by someone who is allowed to see the records individually but has no business taking them wholesale. The M365 hunt watches files; this watches *records*, where the classic true positive is a sales rep exporting their pipeline in their last fortnight.

A note on age: this hunt is baseline-hungry, and a SaaS source with only weeks of ingest cannot say what anyone's normal is. If the history is thinner than the baseline window, the sweep should say so and grade its own confidence down — a fake baseline is worse than a held hunt.

## Exports and their owners

/query: report exports and bulk downloads per user
  window: 24h
  from:   saas_audit
  note:   "Judge against the user's own export history on three axes:
           volume (rows, not just report count), breadth (objects and
           record types they have never exported), and completeness — the
           tell that separates work from harvest is the ALL-COLUMNS,
           all-rows, no-filter export, because real work always filters.
           A first-ever exporter moving big is worth more than a chronic
           exporter moving slightly bigger."

/query: API-based harvesting shapes
  note:   "The UI export has an API twin: bulk-query jobs, paginated
           walks through whole objects, and query patterns that SELECT
           everything rather than something. Attribute API volume to the
           credential behind it — a user token doing bulk work its human
           has never done in the UI, or a connected app suddenly reading
           objects outside its historical scope."

## The integration side door

/query: first-seen connected apps and API clients against the platform
  note:   "The OAuth-grant hunt sees the consent moment tenant-wide; this
           watches what the grant DOES inside this platform. A new
           integration whose first day includes bulk reads of contacts,
           opportunities or cases is a harvester wearing an integration's
           clothes — legitimate integrations spend their first day on
           metadata and test calls, not on the entire Account object."

## Who, and when in their tenure

/enrichment: employment context for the heaviest movers
  note:   "The offboarding join is this hunt's highest-yield enrichment:
           resignation dates, notice periods, role changes. A big export
           inside a notice period reads completely differently from the
           same export at random — and it is the one case where the
           narrative should say the quiet part: this pattern is common,
           commonly litigated, and evidence quality matters."

/pivot: the session around the export
  note:   "Same discipline as the mailbox hunt: was the exporting session
           itself in character — device, network, hour? A mass export from
           an out-of-character session points at account takeover rather
           than insider risk, which changes the response entirely. Say
           which story the evidence supports."

## Rule out the boring explanation

/baseline: the platform's legitimate bulk movers
  note:   "BI service accounts, integration users, sales-ops running
           quarter-end territory jobs, and admins doing sandbox refreshes
           move bulk data on schedule. They are few, named, and periodic —
           the census absorbs them. What the census must NOT absorb is a
           human borrowing the BI account's credentials; a service
           account's export from a human's workstation network fails the
           carve."

## Emit

/lead: record extraction inconsistent with the extractor's history
  entity: user
  note:   "Evidence carries the export inventory (objects, row counts,
           timestamps), the user's own baseline, the session context, and
           the employment context where it exists. Name what the data WAS
           — 'the full opportunity pipeline for EMEA' triages itself;
           'large export' does not. If ingest history was too young for a
           real baseline, the lead must carry that caveat in its first
           line."
