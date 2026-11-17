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
hypothesis: "Cluster audit logs carry a few interesting verbs: a principal exec-ing or attaching into a pod, a pod created directly by a human instead of a controller, one principal reading many secrets across namespaces, and service-account tokens or cluster-wide role bindings minted to make access permanent. In a healthy cluster each is rare and attributable. The benign twins are platform engineers during incidents, CI minting tokens on deploy, and chart upgrades creating privileged pods through known controllers, all clustered around change windows and known principals."
risk_weight: 7
default_severity: high
pivots:
  - name: k8s_audit_census
    role: coverage
    query: 'class_uid=6003 api.service.name="kubernetes" | stats count, dc(actor.user.name) AS principals, dc(api.operation) AS operations by metadata.product.name | sort -count | head 20'
  - name: exec_attach_and_direct_pods
    role: discovery
    query: 'class_uid=6003 api.service.name="kubernetes" (api.operation IN ("create pods/exec","get pods/exec","create pods/attach","get pods/attach","create pods/portforward") OR (api.operation="create pods" actor.user.name NOT STARTSWITH "system:")) | stats count, values(resources.name) AS pods, values(http_request.user_agent) AS user_agents, values(status) AS outcomes, min(timestamp) AS first_seen, max(timestamp) AS last_seen by actor.user.name, api.operation, src_endpoint.ip | sort -count | head 200'
  - name: secret_read_breadth
    role: discovery
    query: 'class_uid=6003 api.service.name="kubernetes" api.operation IN ("get secrets","list secrets","watch secrets") | stats count AS secret_reads, dc(resources.name) AS distinct_secrets, values(api.operation) AS verbs by actor.user.name, src_endpoint.ip | sort -distinct_secrets, -secret_reads | head 200'
    scorer:
      method: zscore
      field: distinct_secrets
      threshold: 3
  - name: token_and_rbac_grants
    role: discovery
    query: 'class_uid=6003 api.service.name="kubernetes" api.operation IN ("create serviceaccounts/token","create serviceaccounts","create clusterrolebindings","update clusterrolebindings","patch clusterrolebindings","create rolebindings","update rolebindings","patch rolebindings","create clusterroles","update clusterroles","patch clusterroles","escalate clusterroles","bind clusterroles") actor.user.name NOT STARTSWITH "system:node:" | stats count, values(resources.name) AS objects, values(status) AS outcomes, min(timestamp) AS first_seen, max(timestamp) AS last_seen by actor.user.name, api.operation, src_endpoint.ip | sort -count | head 200'
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
           both, because service accounts do not have hands. The exec_attach_and_direct_pods pivot lists exec, attach and port-forward per principal, operation and source (api.operation reads like create pods/exec); namespace and TTY are not columns, read them from the raw event."

## Appetite for secrets

/query: secret reads per principal — breadth across names and namespaces
  note:   "Workloads read their own few secrets forever; a harvester reads
           MANY, fast, often just after gaining a new binding. Breadth per
           principal per hour is the measure, and crossing a namespace
           boundary is worth more than volume inside one. List-then-get
           sequences are the classic harvest texture. The secret_read_breadth pivot counts distinct secret names read per principal."

## Node-escape shapes

/query: pod creations with privileged security context, hostPath mounts, or host namespaces
  note:   "privileged: true, hostPath to /, hostPID/hostNetwork — the
           standard escape kit. Legitimate users exist (CNI, monitoring
           daemonsets, storage drivers) and they arrive via known
           controllers on known charts. A privileged pod created directly —
           kubectl run, no owning ReplicaSet or Helm release — by a human
           or a workload identity is the version worth an analyst. The request body (securityContext, hostPath) is not parsed into columns; exec_attach_and_direct_pods lists pods created by non-system principals, which is the created-directly half, so read the raw request for the escape options."

## Making it permanent

/query: service-account token minting and role binding grants
  note:   "Long-lived token requests, new cluster-admin or broad-verb
           bindings, and bindings granted TO recently created service
           accounts are in-cluster persistence — the RBAC mirror of the
           cloud persistence hunt's backdoor accounts. Weight by scope
           (cluster over namespace) and by grantor rarity. The token_and_rbac_grants pivot lists them per principal (node token requests excluded)."

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
