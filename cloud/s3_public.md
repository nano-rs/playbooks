---
title: "S3 bucket made public"
subtitle: "Public ACL or policy granting world read — data exposure risk"
category: cloud
authored: 2025-08-10
match_signals:
  - s3.put_public
  - s3.bucket_policy_public
danger_policy:
  "action:high": approval
  "action:medium": auto
  "action:low": auto
review_cadence: 90d
scope: tenant
tags:
  - cloud
  - s3
  - data-exposure
---
# S3 bucket made public

/enrichment: bucket contents summary
  from:   s3-inventory
  bucket: {{entity.bucket}}
  fields: object_count, size, sample_names, sensitivity_tags

/query: who made the change
  window: 24h
  from:   cloudtrail
  where:  requestParameters.bucketName = {{entity.bucket}} AND eventName IN (PutBucketAcl, PutBucketPolicy)

/decision: is public access intentional?
  options: [yes — static site / public CDN, no]

/action: revert to private
  kind:   s3.lock_down
  target: {{entity.bucket}}
  danger: medium
  reversible: true
