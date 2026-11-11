---
title: "User-reported phish"
subtitle: "Scope the campaign · pull identical messages from other mailboxes · purge"
category: email
owner: "team · email-sec"
authored: 2025-10-10
match_signals:
  - email.user_report
  - phish.reported
danger_policy:
  "action:high": approval
  "action:medium": auto
  "action:low": auto
review_cadence: 90d
scope: tenant
tags:
  - email
  - phish
  - mailbox
---
# User-reported phish

/enrichment: message headers + URL unfurl
  from:   mail-security
  message: {{entity.msg_id}}
  fields: sender_ip, spf, dkim, dmarc, urls, attachments

/query: identical or near-identical messages in the last 24h
  window: 24h
  from:   mail-metadata
  where:  email.subject = "*{{entity.subject}}*" OR email.from = {{entity.sender}}
  group:  by email.to

/pivot: who clicked the URL
  from:   proxy-logs
  where:  class_uid = 4002 AND http_request.url.url_string = {{entity.url}}
  show:   actor.user.name, timestamp, src_endpoint.ip, src_endpoint.hostname

/decision: confirmed phish?
  options: [yes, no, marketing / unwanted but benign]

/action: purge from all mailboxes
  kind:   mail.purge
  target: {{entity.msg_id_set}}
  danger: medium
  reversible: false
  require_approval: true

/action: block sender domain
  kind:   mail.block_sender
  target: {{entity.sender_domain}}
  danger: low

/action: follow-up with clickers
  kind:   ticket.create_many
  target: ir-queue
  per:    {{entity.clickers}}
