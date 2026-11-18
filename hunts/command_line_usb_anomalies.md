---
kind: hunt
title: "Command lines typed by hands, and staging via removable media"
subtitle: "Attacker keyboard fingerprints in command content — recon bursts, obfuscation, inlined secrets — plus USB in/out staging"
category: endpoint
owner: "team · soc-leads"
authored: 2026-08-03
schedule: "0 3 * * *"
timezone: "UTC"
lookback_window: 24h
telemetry:
  all_of:
    - endpoint.process
  optional:
    - endpoint.file
mitre_tactic: execution
mitre_technique: T1059
hypothesis: "Automation is repetitive and people are not. A human orienting on an unfamiliar machine leaves fingerprints in command content: several distinct discovery binaries (whoami, net, nltest, quser, ipconfig, systeminfo) on one host within minutes, obfuscation (encoded PowerShell, FromBase64String, caret mangling), and credentials inlined in arguments (net use /user:, runas, -password). Separately, bulk file writes to a removable volume are exfil staging and executions from one are inbound tooling. The benign twins are admin workstations with rich vocabularies, deployment tooling that ships encoded commands, and the small stable set of hosts that always use removable media."
risk_weight: 5
default_severity: medium
pivots:
  - name: endpoint_telemetry_census
    role: coverage
    query: 'class_uid IN (1007, 1001) | stats count, dc(device.hostname) AS hosts by class_uid'
  - name: discovery_command_bursts
    role: discovery
    query: 'class_uid=1007 activity_id=1 process.name IN ("whoami.exe","net.exe","net1.exe","nltest.exe","quser.exe","query.exe","qwinsta.exe","ipconfig.exe","systeminfo.exe","hostname.exe","tasklist.exe","arp.exe","route.exe","netstat.exe","dsquery.exe","klist.exe","cmdkey.exe","nslookup.exe","sc.exe","wmic.exe") | bin span=10m | stats dc(process.name) AS distinct_verbs, count, values(process.cmd_line) AS cmd_lines, values(process.parent_process.name) AS parents by device.hostname, actor.user.name, time_bucket | where distinct_verbs >= 5 | sort -distinct_verbs, -count | head 200'
  - name: obfuscation_and_inline_secrets
    role: discovery
    query: 'class_uid=1007 activity_id=1 (process.cmd_line=*-enc* OR process.cmd_line=*-encodedcommand* OR process.cmd_line=*frombase64string* OR process.cmd_line=/\^.*\^.*\^/ OR process.cmd_line="*net use*/user:*" OR process.cmd_line=*runas* OR process.cmd_line=*-password* OR process.cmd_line="*password=*" OR process.cmd_line="*pwd=*" OR process.cmd_line="* /p:*") | stats count, dc(device.hostname) AS hosts, values(device.hostname) AS host_sample, values(process.cmd_line) AS cmd_lines by process.parent_process.name, process.name, actor.user.name | sort hosts, count | head 200'
  - name: removable_volume_activity
    role: discovery
    query: '(class_uid=1001 activity_id IN (1,3,5) file.path=/^[d-z]:\\/) OR (class_uid=1007 activity_id=1 process.file.path=/^[d-z]:\\/) | stats count, dc(file.path) AS files_written, values(file.path) AS file_sample, dc(process.file.path) AS executions, values(process.file.path) AS execution_sample by device.hostname, actor.user.name, class_uid | sort -files_written, -executions | head 200'
    scorer:
      method: zscore
      field: files_written
      threshold: 3
budget:
  max_turns: 40
  max_tool_calls: 120
  max_rows: 6000
  max_wall_seconds: 900
tags:
  - endpoint
  - command-line
  - discovery
  - removable-media
---
# Command lines typed by hands, and staging via removable media

**Hypothesis:** automation is repetitive and people are not. An estate's command-line traffic is overwhelmingly machine-generated — the same strings, the same order, forever — and a human exploring a machine they do not know leaves fingerprints in the *content*: discovery verbs in bursts, obfuscation, secrets inline, commands that wander. This hunt reads what was typed, not just what ran.

## Fingerprints in the content

/query: discovery commands clustered tightly on one host
  window: 24h
  from:   edr_telemetry
  note:   "whoami, net user, net group, nltest, quser, ipconfig, systeminfo —
           each is harmless and each runs constantly. The fingerprint is the
           BURST: five distinct discovery commands on one host in ten minutes
           is somebody orienting. Keep the burst's exact sequence; operators
           have habits, and the sequence sometimes matches a known one.
           These bursts are also the leading edge the ransomware-precursor
           hunt feeds on — a burst today is context for a tripwire tomorrow.
           The `discovery_command_bursts` pivot measures 5 or more distinct
           discovery binaries per host and user in a 10-minute bucket, with
           the command lines."

/query: obfuscation markers in command content
  note:   "Base64 blobs, caret-mangling, string concatenation in shells,
           encoded PowerShell. Legitimate software does ship encoded
           commands — the deployment stack is full of them — so judge
           against the per-host vocabulary below before ranking, not after."

/query: credentials inlined in command text
  note:   "Passwords on net use, secrets passed as arguments, runas chains.
           Double signal: sloppy admin practice worth flagging on its own,
           and the classic texture of lateral movement one keyboard at a
           time. The `obfuscation_and_inline_secrets` pivot covers both
           markers, grouped by parent, binary and account with host counts."

## Judge against the host's own vocabulary

/baseline: per-host command-line vocabulary, trailing 30 days
  note:   "The load-bearing comparison. Admin workstations have rich, messy
           vocabularies; servers have tiny ones. The identical burst means
           nothing on the sysadmin's box and everything on a file server
           that has run the same four commands for a month."

/pivot: the session around a flagged burst
  note:   "Walk outward: what ran before (how did they get on?), what ran
           after (what did orientation lead to?). A recon burst that ends in
           an archive being written or a new outbound connection has already
           graduated from curiosity."

## Removable media, both directions

/query: file writes to removable volumes, and executions from them
  window: 24h
  note:   "Two different stories: bulk writes TO a device are exfil staging —
           weight by volume and by whether the content came from shares or
           repositories the user rarely touches. Execution FROM a device is
           inbound tooling. Either way the device identity matters: record
           it. The `removable_volume_activity` pivot approximates removable
           media as drive letters D: to Z: (the device type is not a
           column), so mapped or secondary fixed drives show too: check the
           volume before calling it USB."

/baseline: which users and hosts normally touch removable media at all
  note:   "In most estates the population is small and stable — engineering
           labs, AV crews, the odd executive. First USB activity ever on a
           host, or on an account, is worth more than any volume threshold
           applied estate-wide."

## Emit

/lead: human-textured command activity or out-of-character media use
  entity: host
  note:   "Quote the command lines verbatim in the evidence — the texture IS
           the finding, and a paraphrase destroys it. Carry the host's
           vocabulary baseline, the burst timing, and the session context.
           If the explanation is a named admin doing named work, no lead:
           say so in the narrative with the ticket if one exists."
