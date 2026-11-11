---
title: "Exposed cloud credential — public paste / repo"
subtitle: "Access key or token discovered in a public source · rotate and blast-radius"
category: cloud
owner: "team · cloud-sec"
authored: 2025-10-01
match_signals:
  - secret.leak
  - github.secret_scanning
  - paste.credential
danger_policy:
  "action:high": approval
  "action:medium": auto
  "action:low": auto
review_cadence: 90d
scope: tenant
tags:
  - cloud
  - iam
  - secrets
---
# Exposed cloud credential

/enrichment: credential metadata
  from:   iam-keys
  key:    {{entity.key_id}}
  fields: owner, created, permissions, last_used, mfa

/query: every action this key has taken in 48h
  window: 48h
  from:   cloudtrail
  where:  class_uid = 6003 AND unmapped.user_identity.access_key_id = {{entity.key_id}}

/pivot: source IPs for this key
  from:   cloudtrail
  where:  class_uid = 6003 AND unmapped.user_identity.access_key_id = {{entity.key_id}}
  group:  by src_endpoint.ip

/decision: any activity from IPs not matching the owner's normal pattern?
  options: [yes, no]
  note_required_on: yes

/action: rotate the credential
  kind:   iam.key_rotate
  target: {{entity.key_id}}
  danger: medium
  reversible: true
  require_approval: false

/action: add to deny-list until rotated
  kind:   iam.key_deny_policy
  target: {{entity.key_id}}
  danger: medium
