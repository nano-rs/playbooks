---
kind: hunt
title: "The quiet hour before encryption"
subtitle: "Recovery sabotage, service-kill storms and security tamper — near-zero-FP tripwires carved only by trusted parentage"
category: endpoint
owner: "team · soc-leads"
authored: 2026-08-03
schedule: "0 */4 * * *"
timezone: "UTC"
lookback_window: 8h
telemetry:
  all_of:
    - endpoint.process
  optional:
    - endpoint.file
mitre_tactic: impact
mitre_technique: T1490
hypothesis: "Between foothold and detonation, ransomware operators delete shadow copies, disable boot recovery and backup catalogs, stop the services holding file locks in a burst, and blind the AV. These commands have almost no legitimate authors outside the management, backup and imaging stack, which runs them orchestrated, fleet-wide, inside a change window and parented by its own agent. The attacker version comes from an interactive shell or an unexpected parent on one host, off schedule; parentage is the only carve, never command content."
risk_weight: 8
default_severity: high
pivots:
  - name: endpoint_process_coverage
    role: coverage
    query: 'class_uid=1007 | stats count, dc(device.hostname) AS hosts by source_type'
  - name: recovery_sabotage
    role: discovery
    query: 'class_uid=1007 (process.cmd_line=*delete*shadows* OR process.cmd_line=*shadowcopy*delete* OR process.cmd_line=*resize*shadowstorage* OR process.cmd_line=*win32_shadowcopy* OR process.name="diskshadow.exe" OR process.cmd_line=*recoveryenabled*no* OR process.cmd_line=*ignoreallfailures* OR process.cmd_line=*delete*catalog* OR process.cmd_line=*delete*systemstatebackup*) | stats count, min(timestamp) AS first_seen, max(timestamp) AS last_seen, values(actor.user.name) AS users, values(process.cmd_line) AS commands by device.hostname, process.parent_process.name, process.name | sort -count | head 200'
    scorer:
      method: rare
      field: process.parent_process.name
      threshold: 2
  - name: service_stop_storm
    role: discovery
    query: 'class_uid=1007 ((process.name IN ("net.exe","net1.exe","sc.exe") process.cmd_line=*stop*) OR (process.name="sc.exe" process.cmd_line=*disabled*) OR process.name="taskkill.exe" OR (process.name IN ("powershell.exe","pwsh.exe") process.cmd_line=*stop-service*)) | stats count, dc(process.cmd_line) AS distinct_commands, min(timestamp) AS first_seen, max(timestamp) AS last_seen, values(actor.user.name) AS users, values(process.cmd_line) AS commands by device.hostname, process.parent_process.name | where distinct_commands >= 5 | sort -distinct_commands | head 200'
  - name: security_tool_tamper
    role: discovery
    query: 'class_uid=1007 (process.cmd_line=*set-mppreference* OR process.cmd_line=*add-mppreference* OR process.cmd_line=*disablerealtimemonitoring* OR process.cmd_line=*disableantispyware* OR process.cmd_line=*disableioavprotection* OR process.cmd_line=*removedefinitions* OR process.cmd_line=*windefend* OR process.cmd_line=*wdfilter*) | stats count, min(timestamp) AS first_seen, max(timestamp) AS last_seen, values(actor.user.name) AS users, values(process.cmd_line) AS commands by device.hostname, process.parent_process.name, process.name | sort -count | head 200'
    scorer:
      method: rare
      field: process.parent_process.name
      threshold: 2
budget:
  max_turns: 40
  max_tool_calls: 100
  max_rows: 5000
  max_wall_seconds: 900
tags:
  - endpoint
  - ransomware
  - impact
  - tripwire
---
# The quiet hour before encryption

**Hypothesis:** between foothold and detonation, ransomware operators prepare — delete the shadows, kill the recovery options, stop the services holding file locks, blind the AV. These commands have almost no legitimate authors outside the management and backup stack, which makes them tripwires: the only carve-out this hunt allows is *parentage*, never command content, because an attacker can type any command but cannot easily become the deployment agent.

The suggested cadence is four-hourly rather than nightly on purpose. Everything else in this library can wait for morning; the window between `vssadmin delete shadows` and mass encryption is sometimes minutes and rarely more than a day. A hunt is honestly the wrong tier for the detonation itself — that must be a detection — but the preparation window is huntable, and it is the last window that is.

## Recovery sabotage

/query: shadow copy deletion and resize-to-nothing
  window: 8h
  from:   edr_telemetry
  note:   "vssadmin delete shadows, wmic shadowcopy delete, diskshadow
           scripts, and the resize trick that evicts shadows without a
           delete verb. The legitimate authors are backup agents and
           imaging tools — carve by the PARENT being the known agent, not
           by the command looking routine. An interactive shell issuing
           the identical command is the finding. The recovery_sabotage pivot
           lists these commands per host and parent."

/query: boot and backup configuration kills
  note:   "bcdedit recoveryenabled no / ignoreallfailures, wbadmin delete
           catalog and systemstatebackup. These are rarer than shadow
           deletion and correspondingly heavier — outside an imaging
           pipeline there is close to no reason a Tuesday produces one."

## The lock-release storm

/query: bursts of service stops and process kills on one host
  note:   "Encryptors kill databases, mail stores and backup services to
           release file handles before walking the disk. The tell is the
           STORM — many stops in a tight window, targeting exactly the
           services that hold big files — versus the patch-window shape
           where the same stops arrive orchestrated, fleet-wide, and
           parented by the management stack. The service_stop_storm pivot
           counts distinct stop and kill commands per host and parent."

## Blinding the sensors

/query: security tooling tamper not parented by the management stack
  note:   "Defender exclusions added, real-time protection off, sensor
           services stopped, uninstall strings for AV products. The
           management tool does all of this legitimately during upgrades —
           parentage is again the entire carve. Verify the parent by signer
           and path, not by name; attackers know what the agent binary is
           called. The security_tool_tamper pivot lists these commands per
           host and parent."

## Context that changes the clock

/pivot: recent recon and lateral context for any tripped host
  note:   "A tripwire on a host that showed a discovery burst
           (command-line hunt) or new inbound admin edges (lateral-movement
           hunt) in the last day is not an anomaly to file — it is a
           countdown in progress, and the narrative should say so in those
           words. Check neighbours too: staging usually touches several
           hosts before any single one trips."

/baseline: is a change or imaging window open, and does the actor fit it
  note:   "Fleet reimaging genuinely produces shadow deletes and service
           storms. It also produces them from the deployment system,
           inside a window, across many hosts uniformly. One host, off
           schedule, from an interactive session fails every clause of
           that sentence."

## Emit

/lead: recovery sabotage or tamper outside trusted parentage
  entity: host
  note:   "Lead with the time — evidence carries the exact commands, the
           parentage that failed the carve, the burst timeline, and any
           joined recon/lateral context. This is the one lead in the
           library where the narrative should explicitly recommend urgency:
           a reader triaging it tomorrow morning may be reading it after
           the fact."
