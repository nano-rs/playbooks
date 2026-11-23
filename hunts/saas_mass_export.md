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
hypothesis: "Business SaaS (CRM, ITSM, HR, wiki, chat) leaks through its own front door: report exports, bulk downloads and API pulls performed with valid credentials by someone allowed to see records individually but with no business taking them wholesale, and new integrations whose first day is bulk reads. In the SaaS audit log that looks like one user or app with far more export or read calls, across more objects, than the rest of the population. The benign twins are BI service accounts, integration users, sales-ops quarter-end jobs and sandbox refreshes, which are few, named and periodic."
risk_weight: 6
default_severity: medium
pivots:
  - name: saas_audit_census
    role: coverage
    query: 'class_uid IN (6003, 6006) cloud.provider NOT IN ("AWS","GCP","Azure") api.service.name!="kubernetes" | stats count, dc(actor.user.name) AS users, dc(api.operation) AS operations by class_uid, metadata.product.name | sort -count | head 50'
  - name: export_volume_per_user
    role: discovery
    query: 'class_uid=6003 cloud.provider NOT IN ("AWS","GCP","Azure") (api.operation=*export* OR api.operation=*download* OR api.operation=*report* OR api.operation=*bulk* OR api.operation=*dump*) | stats count AS exports, dc(api.operation) AS distinct_ops, dc(resources.name) AS distinct_objects, values(api.operation) AS operations, values(src_endpoint.ip) AS source_ips by actor.user.name, metadata.product.name | sort -exports | head 200'
    scorer:
      method: zscore
      field: exports
      threshold: 3
  - name: api_read_volume
    role: discovery
    query: 'class_uid=6003 cloud.provider NOT IN ("AWS","GCP","Azure") api.service.name!="kubernetes" activity_id=2 | stats count AS reads, dc(resources.name) AS distinct_objects, dc(api.operation) AS distinct_ops by actor.user.name, metadata.product.name, http_request.user_agent | sort -reads | head 200'
    scorer:
      method: iqr
      field: reads
      threshold: 3
  - name: integration_grants
    role: discovery
    query: 'class_uid=6003 cloud.provider NOT IN ("AWS","GCP","Azure") (api.operation=*oauth* OR api.operation=*integration* OR api.operation=*connected_app* OR api.operation=*app_install* OR api.operation=*app_approved* OR api.operation=*authorize* OR api.operation CONTAINS "connected app") | stats count, values(api.operation) AS operations, values(resources.name) AS apps, min(timestamp) AS first_seen by actor.user.name, metadata.product.name | sort -count | head 200'
budget:
  max_turns: 40
  max_tool_calls: 120
  max_rows: 6000
  max_wall_seconds: 2700
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
           exporter moving slightly bigger. The export_volume_per_user pivot counts export, download, report and bulk operations per user and product; row counts and column selection are not columns, read them from the raw events."

/query: API-based harvesting shapes
  note:   "The UI export has an API twin: bulk-query jobs, paginated
           walks through whole objects, and query patterns that SELECT
           everything rather than something. Attribute API volume to the
           credential behind it — a user token doing bulk work its human
           has never done in the UI, or a connected app suddenly reading
           objects outside its historical scope. The api_read_volume pivot counts read activity per user, product and user agent."

## The integration side door

/query: first-seen connected apps and API clients against the platform
  note:   "The OAuth-grant hunt sees the consent moment tenant-wide; this
           watches what the grant DOES inside this platform. A new
           integration whose first day includes bulk reads of contacts,
           opportunities or cases is a harvester wearing an integration's
           clothes — legitimate integrations spend their first day on
           metadata and test calls, not on the entire Account object. The integration_grants pivot lists OAuth, app-install and integration events per actor."

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
