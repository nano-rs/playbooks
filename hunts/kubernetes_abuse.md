---
kind: hunt
title: "Hands inside the cluster: exec, secrets, and privilege in Kubernetes"
subtitle: "Pod exec/attach, secret-harvesting breadth, privileged and hostPath pods, token minting and RBAC grants — audit telemetry most estates ingest and never read"
category: cloud
owner: "team · soc-leads"
authored: 2026-08-03
schedule: "0 7 * * *"
timezone: "UTC"
lookback_window: 24h
telemetry:
  all_of:
    - kubernetes.audit
  optional:
    - cloud.control_plane
mitre_tactic: execution
mitre_technique: T1609
budget:
  max_turns: 40
  max_tool_calls: 120
  max_rows: 6000
  max_wall_seconds: 900
tags:
  - cloud
  - kubernetes
  - containers
---
# Hands inside the cluster: exec, secrets, and privilege in Kubernetes

**Hypothesis:** cluster audit logs are the most commonly ingested-and-never-hunted source in cloud estates — live, verbose, and unread. Yet the interesting verbs are few: a human execing into a pod, a principal reading secrets it has no relationship with, a pod created with node-escape options, a token or binding minted to make access permanent. In a healthy cluster every one of these is rare, attributable, and boring to baseline — which is the definition of huntable ground.

## Hands on pods

/query: exec and attach operations — who, into what, with a TTY
  window: 24h
  from:   kubernetes_audit
  note:   "Interactive TTY exec is a human hand by definition. The population
           of humans who exec into pods is small, and the pods they exec
           into are usually their own team's. Rank: human into prod beats
           human into dev; a first-ever principal→namespace pairing beats a
           familiar one; a service account execing interactively beats
           both, because service accounts do not have hands."

## Appetite for secrets

/query: secret reads per principal — breadth across names and namespaces
  note:   "Workloads read their own few secrets forever; a harvester reads
           MANY, fast, often just after gaining a new binding. Breadth per
           principal per hour is the measure, and crossing a namespace
           boundary is worth more than volume inside one. List-then-get
           sequences are the classic harvest texture."

## Node-escape shapes

/query: pod creations with privileged security context, hostPath mounts, or host namespaces
  note:   "privileged: true, hostPath to /, hostPID/hostNetwork — the
           standard escape kit. Legitimate users exist (CNI, monitoring
           daemonsets, storage drivers) and they arrive via known
           controllers on known charts. A privileged pod created directly —
           kubectl run, no owning ReplicaSet or Helm release — by a human
           or a workload identity is the version worth an analyst."

## Making it permanent

/query: service-account token minting and role binding grants
  note:   "Long-lived token requests, new cluster-admin or broad-verb
           bindings, and bindings granted TO recently created service
           accounts are in-cluster persistence — the RBAC mirror of the
           cloud persistence hunt's backdoor accounts. Weight by scope
           (cluster over namespace) and by grantor rarity."

## Attribution out of the cluster

/pivot: the principal's identity back through cloud IAM to a human or workload
  note:   "Cluster identities resolve to cloud identities, and the cloud side
           carries the session context — source network, authentication
           shape, recent activity. An exec whose underlying cloud identity
           also tripped the sign-in or credential-misuse hunt is one
           intrusion narrated across three sources, and the lead should
           join them."

## Rule out the boring explanation

/baseline: each principal's operational history, and the change calendar
  note:   "Platform engineers exec during incidents, CI mints tokens on
           deploy, and chart upgrades create privileged pods in bulk. All
           of it clusters around change windows and known principals. The
           lead is the operation OUTSIDE its principal's history — and an
           incident-response exec at 3 a.m. should still be checked against
           whether an incident existed."

## Emit

/lead: cluster operation outside the principal's established pattern
  entity: principal
  note:   "Evidence carries the audit events verbatim, the principal's
           history (or first-seen fact), the cloud-side identity resolution,
           and any joined findings from neighbouring hunts. For secret
           harvesting, list the secrets touched by name — the reader's
           first action is rotation, and the list IS the rotation scope."
