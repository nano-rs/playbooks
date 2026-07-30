---
kind: hunt
title: "Built-in tooling launched by something that has no business launching it"
subtitle: "Signed system binaries spawned from parents that have never spawned them here before"
category: endpoint
owner: "team · soc-leads"
authored: 2026-07-30
schedule: "0 5 * * *"
timezone: "UTC"
lookback_window: 24h
required_source_types:
  - windows_sysmon
mitre_tactic: defense-evasion
mitre_technique: T1218
budget:
  max_turns: 40
  max_tool_calls: 120
  max_rows: 6000
  max_wall_seconds: 900
tags:
  - endpoint
  - lolbin
  - execution
---
# Built-in tooling launched by something that has no business launching it

**Hypothesis:** an attacker preferring to live off the land still has to *start* the binary from somewhere, and that parent is usually the tell. `certutil.exe` is unremarkable; `certutil.exe` spawned by a macro-enabled Office process is not, and the difference is entirely in the edge, not the node.

The reason this works as a scheduled hunt rather than a detection rule is that the interesting set is defined by the estate rather than by a list. Every environment has its own legitimate parent→child pairs — a deployment tool that shells out, a monitoring agent that runs `wmic` — and enumerating them centrally produces either a rule that never fires or one that fires constantly.

## Learn what normal looks like here

/baseline: parent→child pairs observed across the estate, trailing 30 days
  note:   "Build the pair census first. The hunt is a comparison against this,
           and running the deviation query without it produces a list of every
           LOLBin execution in the estate, which is useless."

/query: executions of commonly-abused signed binaries
  window: 24h
  from:   windows_sysmon
  note:   "Cast wide here — certutil, bitsadmin, mshta, regsvr32, rundll32,
           msbuild, installutil, wmic, curl and the script hosts. Breadth is
           cheap at this stage because the pair baseline does the narrowing."

## Find the edge that has not been seen

/query: executions whose parent→child pair is absent from the baseline
  note:   "First-seen on the PAIR, not on either process. Both ends are usually
           individually mundane; it is their combination that has never happened
           on this estate before."

/pivot: the full process tree around the execution
  note:   "Walk up as well as down. The grandparent frequently carries the real
           story — a script host under Office under a mail client is a phishing
           chain, the same script host under a deployment agent is a Tuesday."

## Rule out the boring explanation

/enrichment: is the parent a known management or deployment agent
  note:   "New software genuinely does introduce new pairs. A pair that appears
           on many hosts at once, shortly after a deployment window, is a
           rollout — and a lead that misses this will be dismissed, teaching the
           suppression list to hide the next real one."

/baseline: how many distinct hosts show this new pair
  note:   "One host is interesting. Four hundred hosts in the same ten minutes is
           a change-management ticket. The count is what separates them, and it
           belongs in the evidence rather than in the analyst's head."

/query: what the child process did once it ran
  note:   "Execution alone is weak. Network egress, a file written to a staging
           directory, or a further spawn is what turns a curiosity into a lead."

## Emit

/lead: unusual parent for a commonly-abused signed binary
  entity: host
  note:   "Evidence should carry the process tree, the pair's estate-wide
           first-seen, the host count, and whatever the child went on to do.

           If the pair turned out to be a deployment rollout, do NOT emit a lead
           — say so in the sweep's outcome instead. A hunt that reports its own
           false positives as findings is worse than one that finds nothing,
           because it spends the analyst's trust rather than the estate's."
