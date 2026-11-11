---
title: "IAM privilege escalation"
subtitle: "Actor gained higher privileges than expected — via role assumption, policy attach, or user creation"
category: cloud
authored: 2025-09-15
match_signals:
  - iam.policy_attach
  - sts.assume_suspicious
  - iam.user_created
danger_policy:
  "action:high": approval
  "action:medium": auto
  "action:low": auto
review_cadence: 90d
scope: tenant
tags:
  - cloud
  - iam
  - privesc
---
# IAM privilege escalation

/query: IAM policy changes by this actor in 24h
  window: 24h
  from:   cloudtrail
  where:  class_uid = 6003 AND actor.user.uid = {{entity.actor}} AND api.operation IN ("AttachUserPolicy", "AttachRolePolicy", "CreatePolicy")

/pivot: every principal that currently has the attached policy
  from:   iam-graph
  policy: {{entity.policy_arn}}

/decision: was this change authorized?
  options: [yes — change-ticket found, no, needs review]

/action: revert the policy change
  kind:   iam.policy_detach
  target: {{entity.policy_arn}}
  danger: high
  reversible: true
  require_approval: true
