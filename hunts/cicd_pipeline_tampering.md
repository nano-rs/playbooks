---
kind: hunt
title: "The pipeline that can read every secret and sign every build"
subtitle: "Workflow edits that touch secrets, foreign runner registrations, protection-rule rollbacks and deploy-key sprawl in source control"
category: cloud
owner: "team · soc-leads"
authored: 2026-08-03
schedule: "30 8 * * *"
timezone: "UTC"
lookback_window: 24h
telemetry:
  all_of:
    - cicd.audit
mitre_tactic: credential-access
mitre_technique: T1552
budget:
  max_turns: 40
  max_tool_calls: 120
  max_rows: 5000
  max_wall_seconds: 900
tags:
  - cloud
  - cicd
  - source-control
  - supply-chain
---
# The pipeline that can read every secret and sign every build

**Hypothesis:** CI is the most privileged identity most orgs run — it holds the deploy credentials, reads the secrets, and its output is trusted by definition — and it executes whatever the repository tells it to. That makes workflow files a credential-access and code-execution surface reviewable in *diffs*: an attacker with any write path doesn't need malware, just an edit. The OAuth hunt watches tokens being minted; this watches the machinery those tokens feed.

## Workflow edits that change what CI can do

/query: changes to workflow and pipeline definitions, read as diffs
  window: 24h
  from:   github_audit
  note:   "The shapes that matter in the diff: secrets newly referenced or
           passed to steps that never needed them, permissions blocks
           widened, pull_request_target or similar triggers introduced
           (untrusted code meeting trusted context), new outbound calls
           in run steps — curl piped anywhere, artifacts posted to
           unfamiliar hosts — and third-party actions switched from
           pinned hashes to floating tags. Weight by author: a workflow
           edit from an account that has never touched CI config, or via
           a token rather than a person, reads differently than the
           platform team refactoring."

/query: workflow runs that deviate from their own history
  note:   "The edit is intent; the run is action. Runs whose duration,
           egress or secret-access pattern departs from that workflow's
           norm — especially on first execution after an edit flagged
           above — close the loop. A one-commit-old workflow exfiltrating
           env vars has a diff, a run, and a destination, all in evidence
           reach."

## Machinery joining the trusted side

/query: self-hosted runner registrations and group changes
  note:   "A runner is an agent with the pipeline's credentials; registering
           one is joining the trusted computing base. First-seen runner
           hosts, registrations by unexpected identities, and runners
           appearing in repos that never had them deserve individual
           reading — the population changes rarely enough that each event
           can afford it."

/query: deploy keys, app installations, and PAT scope against the org
  note:   "The durable side doors. New deploy keys with write on quiet
           repos, app installs demanding contents:write org-wide, and the
           PAT-minting shapes the OAuth hunt flags — cross-reference it
           rather than re-judging, and bring its verdicts into this
           hunt's timeline when the same identity appears in both."

## Guardrails quietly lowered

/query: protection-rule and review-requirement changes
  note:   "Branch protection disabled, required reviews dropped, status
           checks removed, force-pushes to protected branches — each one
           is someone arranging to move code without witnesses. The
           add-use-restore cycle matters here exactly as it does in the
           privileged-group hunt: protection dropped, a push, protection
           restored inside an hour is a shape with no innocent author."

## Rule out the boring explanation

/baseline: who maintains CI here, and what does routine churn look like
  window: 30d
  note:   "Platform teams refactor workflows in sweeps across many repos,
           and dependency bots pin and unpin actions on schedule. Both
           have stable authorship and fleet-shaped blast patterns. The
           lead is the single-repo, single-author edit that touches
           secrets or triggers — precision, not churn."

/pivot: the acting identity's wider session
  note:   "An identity editing CI minutes after its own out-of-character
           sign-in, or a token minted yesterday editing workflows today,
           joins this lead to the identity hunts' story. Compromised-
           maintainer and malicious-insider read identically in the diff;
           the session context is what separates them."

## Emit

/lead: pipeline change that widens credential or execution reach
  entity: repo
  note:   "Evidence carries the diff itself, the author and their CI
           history, the first post-edit run's behaviour, and any joined
           identity findings. Say what the pipeline can now DO that it
           could not before — 'this workflow can now read the deploy key
           and is triggered by fork PRs' is the sentence the reader acts
           on; a commit hash is not."
