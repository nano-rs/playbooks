---
kind: hunt
title: "Credential harvesting by things that are not credential utilities"
subtitle: "Hive exports, browser credstore reads, password hunting and shadow-copy pulls — every hit carried with its chain, both directions"
category: endpoint
owner: "team · soc-leads"
authored: 2026-08-03
schedule: "0 8 * * *"
timezone: "UTC"
lookback_window: 24h
telemetry:
  all_of:
    - endpoint.process
    - endpoint.file
mitre_tactic: credential-access
mitre_technique: T1003
hypothesis: "Credential material on an endpoint (SAM / SYSTEM / SECURITY hives, ntds.dit, LSASS memory, browser credential stores, password files) is touched constantly by the OS, backup agents and security tools, and almost never by anything else. In telemetry the attack shows as reg save / esentutl / ntdsutil / shadow-copy pulls, LSASS opened by an unexpected process, browser credstore files touched by a non-browser, and keyboard-driven password hunting (findstr /si password, *.kdbx, unattend.xml). The benign twin is the same touch by a signed backup or security agent from its install path."
risk_weight: 8
default_severity: high
pivots:
  - name: endpoint_telemetry_census
    role: coverage
    query: 'class_uid IN (1007, 1001) | stats count, dc(device.hostname) AS hosts by class_uid, activity_id'
  - name: hive_ntds_lsass_touches
    role: discovery
    query: 'class_uid=1007 ((process.name="reg.exe" process.cmd_line=*save* (process.cmd_line=*sam* OR process.cmd_line=*system* OR process.cmd_line=*security*)) OR process.cmd_line=*ntds.dit* OR process.name IN ("ntdsutil.exe","dsdbutil.exe","vssadmin.exe","diskshadow.exe","vshadow.exe") OR (process.name="esentutl.exe" process.cmd_line=*/vss*) OR process.cmd_line=*HarddiskVolumeShadowCopy* OR (process.cmd_line=*comsvcs* process.cmd_line=*minidump*) OR process.name IN ("procdump.exe","procdump64.exe","sqldumper.exe","createdump.exe","rdrleakdiag.exe") OR (activity_id=3 process.name="lsass.exe")) | stats count, earliest(timestamp) AS first_seen, latest(timestamp) AS last_seen, values(process.cmd_line) AS cmd_lines by device.hostname, actor.user.name, actor.process.name, actor.process.file.path, process.name | sort count | head 200'
  - name: browser_credstore_touches
    role: discovery
    query: 'class_uid=1001 (file.path="*\Login Data*" OR file.path=*\Cookies* OR file.path="*\Local State*" OR file.path=*\key4.db* OR file.path=*\logins.json* OR file.path=*\cookies.sqlite* OR file.path="*\Web Data*") actor.process.name NOT IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","iexplore.exe","msedgewebview2.exe") | stats count, dc(file.path) AS files, values(file.path) AS file_sample by device.hostname, actor.user.name, actor.process.name, actor.process.file.path | sort -files | head 200'
  - name: password_hunting_commands
    role: discovery
    query: 'class_uid=1007 activity_id=1 ((process.name="findstr.exe" (process.cmd_line=*pass* OR process.cmd_line=*pwd* OR process.cmd_line=*cred*)) OR process.cmd_line=*.kdbx* OR process.cmd_line=*unattend.xml* OR process.cmd_line=*sysprep.xml* OR process.cmd_line=*id_rsa* OR process.cmd_line=*web.config* OR process.cmd_line=*cpassword* OR process.cmd_line="*select-string*password*" OR process.cmd_line="*dir /s*pass*") | stats count, dc(process.cmd_line) AS distinct_commands, values(process.cmd_line) AS cmd_lines, earliest(timestamp) AS first_seen by device.hostname, actor.user.name, process.parent_process.name | sort -distinct_commands | head 200'
budget:
  max_turns: 40
  max_tool_calls: 120
  max_rows: 5000
  max_wall_seconds: 2700
tags:
  - endpoint
  - credential-access
---
# Credential harvesting by things that are not credential utilities

**Hypothesis:** credential material on an endpoint is touched constantly — by the OS, by backup agents, by security tools — and almost never by anything else. So the hunt is not "who touched the SAM" but "what touched it that is not on the short list of things whose *job* it is." And because a credential-access event with no context is untriageable, this hunt has one non-negotiable rule: no lead ships without its chain — what came before the touch, and where the material went after.

## The touches

/query: registry hive exports and raids on the domain database
  window: 24h
  from:   edr_telemetry
  note:   "reg save on SAM/SYSTEM/SECURITY, esentutl or raw copies against
           ntds.dit, dsdbutil snapshots. On domain controllers add the
           remote flavour: replication-request patterns from machines that
           are not domain controllers — the DCSync shape — which touch no
           file at all. The `hive_ntds_lsass_touches` pivot lists the
           process side per host with the acting process and its path,
           including Sysmon process-access (activity 3) events against
           lsass.exe; DCSync replication requests are not in endpoint
           telemetry and stay a manual check."

/query: shadow-copy creation followed by file pulls from inside it
  note:   "The locked-file workaround: mount or create a shadow, then copy
           SAM or ntds.dit out through the snapshot path. The two-step is
           the signature — a shadow created and read within minutes by the
           same session, with credential paths in the reads. Backup agents
           do this all day; they are the carve, and only by identity."

/query: browser credential stores read by non-browser processes
  note:   "Login Data, Cookies, Local State, key4.db opened by anything
           that is not the browser itself or a known backup process.
           Browser credstores are the highest-yield, lowest-privilege
           target on any workstation — no admin required — and stealer
           malware goes here FIRST. Cookie-store reads deserve equal rank:
           session theft outlives a password reset. The
           `browser_credstore_touches` pivot lists non-browser processes
           with file events on these stores; most EDRs record writes and
           creates, not reads, so a missing read is not an absence."

/query: password hunting in files and code
  note:   "findstr /si password, recursive greps for 'pwd=', dir sweeps for
           *.kdbx, unattend.xml, web.config, id_rsa. This is keyboard work,
           not tooling — it overlaps the command-line hunt's discovery
           texture, and a host appearing in both is one story. The
           `password_hunting_commands` pivot measures this per host and
           user."

## The carve, verified

/baseline: which process identities legitimately touch credential material here
  window: 30d
  note:   "Security agents, backup software, the browser itself. Build the
           list from observed history, carve by SIGNER AND PATH, never by
           process name — masquerading as the AV binary is a stealer's
           oldest trick, and a name-based carve is a standing invitation.
           A 'legitimate' toucher running from a user profile path fails
           the carve by definition."

## The mandatory chain

/pivot: chain-back — how the touching process came to exist
  note:   "Walk to the origin: dropped by a browser? Spawned under a service
           process? Arrived over an admin share? The chain-back usually
           lands in ground another hunt owns — drive-by, mail-to-endpoint,
           lateral movement — and the lead should name the connection.
           A credential touch with an unexplained origin is MORE alarming,
           not less; say the origin could not be established."

/pivot: chain-forward — where the material went
  note:   "Staging writes (archives, renamed copies in temp), outbound
           connections in the minutes after, or immediate authentication
           events using the harvested identities. Forward chain is what
           separates 'attempted' from 'accomplished', and it sets the
           blast radius the reader must contain — new logons with a dumped
           account are the difference between rotating one host's secrets
           and rotating a domain's."

## Emit

/lead: credential material touched outside the carve, with chain attached
  entity: host
  note:   "Both chains are the price of admission — a lead reading 'LSASS
           accessed' with no origin and no aftermath cannot be triaged
           without redoing the sweep, and the analyst who has to redo it
           will dismiss it. Name the accounts whose material was exposed;
           that list is the reader's rotation scope, and producing it here
           is cheaper than producing it during the incident."
