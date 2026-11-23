---
kind: hunt
title: "The chain between the browser and the first payload"
subtitle: "Browser-to-script-host lineage, container-file mount-then-execute, archive-extract-then-run, and write-then-run temporal joins"
category: endpoint
owner: "team · soc-leads"
authored: 2026-08-03
schedule: "0 7 * * *"
timezone: "UTC"
lookback_window: 24h
telemetry:
  all_of:
    - endpoint.process
    - endpoint.file
mitre_tactic: execution
mitre_technique: T1204.002
hypothesis: "Whatever the lure, a web-delivered intrusion must cross one narrow bridge: something the browser wrote to disk has to run. The crossings are enumerable (script hosts and LOLBins born under a browser, executables running from Downloads and Temp, ISO/IMG/VHD containers mounted to shed mark-of-the-web, archives extracted and promptly run) and each is commonplace alone; a file written by the browser or an extractor and executed within minutes, by a user who does not do this routinely, is the finding. Developers and IT staff crossing the bridge all day are the benign twin."
risk_weight: 6
default_severity: medium
pivots:
  - name: endpoint_file_process_coverage
    role: coverage
    query: 'class_uid IN (1001, 1007) | stats count, dc(device.hostname) AS hosts by source_type, class_uid'
  - name: browser_spawned_script_hosts
    role: discovery
    query: 'class_uid=1007 process.parent_process.name IN ("chrome.exe","msedge.exe","firefox.exe","iexplore.exe","brave.exe","opera.exe","msedgewebview2.exe") process.name IN ("wscript.exe","cscript.exe","mshta.exe","powershell.exe","pwsh.exe","cmd.exe","rundll32.exe","regsvr32.exe","msiexec.exe","certutil.exe","bitsadmin.exe","curl.exe","hh.exe") | stats count, min(timestamp) AS first_seen, max(timestamp) AS last_seen, values(actor.user.name) AS users, values(process.cmd_line) AS commands by device.hostname, process.parent_process.name, process.name | sort -count | head 200'
    scorer:
      method: rare
      field: process.name
      threshold: 2
  - name: user_scratch_path_execution
    role: discovery
    query: 'class_uid=1007 (process.file.path CONTAINS "\\downloads\\" OR process.file.path CONTAINS "\\appdata\\local\\temp\\" OR process.file.path CONTAINS "\\users\\public\\" OR process.file.path CONTAINS "\\temp\\rar$" OR process.file.path CONTAINS "\\temp\\7z" OR process.file.path CONTAINS "\\temp\\temp1_") | stats count, dc(device.hostname) AS hosts, values(device.hostname) AS host_sample, values(actor.user.name) AS users, values(process.parent_process.name) AS parents, values(process.file.path) AS paths by process.name | where hosts <= 3 | sort +hosts, -count | head 200'
  - name: web_written_payloads
    role: discovery
    query: 'class_uid=1001 activity_id IN (1,3,5,6) actor.process.name IN ("chrome.exe","msedge.exe","firefox.exe","iexplore.exe","brave.exe","opera.exe","msedgewebview2.exe","7z.exe","7zg.exe","7zfm.exe","winrar.exe","winzip32.exe","winzip64.exe") (file.name ENDSWITH ".iso" OR file.name ENDSWITH ".img" OR file.name ENDSWITH ".vhd" OR file.name ENDSWITH ".vhdx" OR file.name ENDSWITH ".lnk" OR file.name ENDSWITH ".js" OR file.name ENDSWITH ".jse" OR file.name ENDSWITH ".vbs" OR file.name ENDSWITH ".vbe" OR file.name ENDSWITH ".hta" OR file.name ENDSWITH ".wsf" OR file.name ENDSWITH ".ps1" OR file.name ENDSWITH ".bat" OR file.name ENDSWITH ".cmd" OR file.name ENDSWITH ".scr" OR file.name ENDSWITH ".msi" OR file.name ENDSWITH ".exe" OR file.name ENDSWITH ".dll") | stats count, min(timestamp) AS first_write, max(timestamp) AS last_write, values(file.path) AS files by device.hostname, actor.user.name, actor.process.name | sort -count | head 200'
budget:
  max_turns: 40
  max_tool_calls: 120
  max_rows: 6000
  max_wall_seconds: 2700
tags:
  - endpoint
  - execution
  - drive-by
  - motw
---
# The chain between the browser and the first payload

**Hypothesis:** whatever the lure — a poisoned search result, a fake update, a mailed link — the web-delivered intrusion must cross the same narrow bridge: something the user's browser wrote to disk has to run. The crossings are enumerable: script hosts born under browsers, executables running out of Downloads and Temp, container files mounted to shed mark-of-the-web, archives extracted and promptly run. Each crossing is individually commonplace; the recency join — *written by the web, executed within minutes* — is what makes them legible.

## Lineage crossings

/query: script hosts and LOLBins whose parent is a browser
  window: 24h
  from:   edr_telemetry
  note:   "wscript, cscript, mshta, powershell, rundll32 under chrome, edge,
           firefox or a webview. Browsers have almost no legitimate reason
           to spawn these; the short list of exceptions — protocol-handler
           launches, some update mechanisms — is stable per estate and
           worth learning by name rather than suppressing by pattern. The
           browser_spawned_script_hosts pivot lists these per host."

/query: script hosts and executables running from Downloads, Temp, and profile scratch paths
  note:   "Path is a weaker signal than lineage — plenty of legitimate
           installers run from Downloads. Rank by what ELSE is true: unsigned,
           first-seen hash estate-wide, name imitating a document
           ('invoice_pdf.exe'), or double extensions. The path buys a look;
           the accessories buy the lead. The user_scratch_path_execution
           pivot lists binaries run from these paths on at most three hosts."

## The MOTW-shedding wrapper

/query: container-file mounts followed by execution from the mounted volume
  note:   "ISO, IMG and VHD exist in phishing chains for exactly one reason:
           contents of a mounted container carry no mark-of-the-web, so
           SmartScreen and macro policy never see the payload. Mount event
           followed within minutes by execution from the new volume is the
           shape. The benign population — IT staging media, developers with
           VM images — is small, stable, and identifiable by the account
           doing the mounting."

/query: archive extraction followed by execution of the extracted file
  note:   "The zip-of-a-shortcut and zip-of-a-script families. Join extractor
           write events to subsequent executions of the written files;
           minutes-tight, same user session. LNK targets deserve reading —
           the shortcut IS the dropper, and its command line usually names
           the next stage."

## The generalising join

/query: files written by browsers or extractors, executed within a short window
  note:   "This is the abstraction over every section above, and it catches
           the variant nobody enumerated — the new container format, the
           renamed script host. Run it LAST and dedupe against earlier
           hits, so the specific shapes keep their sharper labels and this
           join only surfaces the remainder. The web_written_payloads pivot lists
           executable and container files written by browsers and
           extractors; join them to executions by host, user and path."

/pivot: the download provenance and what the payload did next
  note:   "Walk back to the URL or referrer where telemetry has it, and
           forward to what the first payload spawned, wrote, or contacted.
           A crossing with no aftermath is a user who dodged; a crossing
           with an outbound connection to a day-old domain is an intrusion
           in progress. The lead should say which."

## Rule out the boring explanation

/baseline: the user's own history with installers, scripts, and mounts
  note:   "Developers and IT staff cross this bridge legitimately all day.
           Their baseline is rich — and even for them, a container mount is
           usually novel. Judge each crossing against the user's own
           pattern, and note that 'developer machine' explains a script
           from Temp far better than it explains an ISO mount at midnight."

## Emit

/lead: web-written content executed through a recognized crossing
  entity: host
  note:   "Evidence carries the full chain: provenance (URL/referrer if
           held), the written file with hash and MOTW status, the mount or
           extraction event, the execution, and the aftermath. Name the
           crossing type explicitly — MOTW-bypass wrappers imply a
           deliberate, current toolkit and should read as more urgent than
           a bare download-and-run."
