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
telemetry:
  all_of:
    - endpoint.process
mitre_tactic: defense-evasion
mitre_technique: T1218
hypothesis: "Living-off-the-land binaries still have to be started by something, and the parent is the tell: certutil is unremarkable, certutil spawned by a macro-enabled Office process is not. In telemetry this is a parent/child pair for a commonly-abused signed binary that appears on one or two hosts in the window and is followed by network egress, file writes or further spawns. The benign twin is a new pair introduced by a deployment or management agent, which appears on many hosts at once inside a change window."
risk_weight: 6
default_severity: medium
pivots:
  - name: lolbin_execution_census
    role: coverage
    query: 'class_uid=1007 activity_id=1 process.name IN ("certutil.exe","bitsadmin.exe","mshta.exe","regsvr32.exe","rundll32.exe","msbuild.exe","installutil.exe","wmic.exe","curl.exe","wscript.exe","cscript.exe","regasm.exe","regsvcs.exe","odbcconf.exe","cmstp.exe","msiexec.exe","hh.exe","forfiles.exe","pcalua.exe","esentutl.exe","expand.exe","msxsl.exe","powershell.exe","pwsh.exe") | stats count, dc(device.hostname) AS hosts, dc(process.parent_process.name) AS parents by process.name | sort -count'
  - name: rare_lolbin_parent_pairs
    role: discovery
    query: 'class_uid=1007 activity_id=1 process.name IN ("certutil.exe","bitsadmin.exe","mshta.exe","regsvr32.exe","rundll32.exe","msbuild.exe","installutil.exe","wmic.exe","curl.exe","wscript.exe","cscript.exe","regasm.exe","regsvcs.exe","odbcconf.exe","cmstp.exe","msiexec.exe","hh.exe","forfiles.exe","pcalua.exe","esentutl.exe","expand.exe","msxsl.exe","powershell.exe","pwsh.exe") | stats count, dc(device.hostname) AS hosts, values(device.hostname) AS host_sample, values(actor.user.name) AS users, first(process.cmd_line) AS sample_cmd_line, earliest(timestamp) AS first_seen by process.parent_process.name, process.name | where hosts <= 2 | sort hosts, count, process.parent_process.name, process.name | head 200'
    scorer:
      method: rare
      field: process.parent_process.name
      threshold: 2
  - name: lolbin_follow_on_activity
    role: discovery
    query: 'class_uid IN (1001, 1007, 4001) actor.process.name IN ("certutil.exe","bitsadmin.exe","mshta.exe","regsvr32.exe","rundll32.exe","msbuild.exe","installutil.exe","wmic.exe","curl.exe","wscript.exe","cscript.exe","regasm.exe","regsvcs.exe","odbcconf.exe","cmstp.exe","msiexec.exe","hh.exe","forfiles.exe","pcalua.exe","esentutl.exe","expand.exe","msxsl.exe","powershell.exe","pwsh.exe") | stats count, dc(dst_endpoint.ip) AS destinations, values(dst_endpoint.ip) AS destination_sample, dc(file.path) AS files_written, values(file.path) AS file_sample, dc(process.name) AS children, values(process.name) AS child_sample by device.hostname, actor.process.name | sort -destinations, -files_written, device.hostname, actor.process.name | head 200'
budget:
  max_turns: 40
  max_tool_calls: 120
  max_rows: 6000
  max_wall_seconds: 2700
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
           LOLBin execution in the estate, which is useless. The
           `lolbin_execution_census` pivot gives the per-binary host and
           parent counts for this window; a 30-day pair census is not a
           pivot, so confirm a pair's absence with a wider search."

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
           on this estate before. The `rare_lolbin_parent_pairs` pivot lists
           pairs seen on at most 2 hosts in the window, with their hosts,
           users and a sample command line."

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
           directory, or a further spawn is what turns a curiosity into a lead.
           The `lolbin_follow_on_activity` pivot measures connections, file
           writes and child processes per host for each watched binary."

## Emit

/lead: unusual parent for a commonly-abused signed binary
  entity: host
  note:   "Evidence should carry the process tree, the pair's estate-wide
           first-seen, the host count, and whatever the child went on to do.

           If the pair turned out to be a deployment rollout, do NOT emit a lead
           — say so in the sweep's outcome instead. A hunt that reports its own
           false positives as findings is worse than one that finds nothing,
           because it spends the analyst's trust rather than the estate's."
