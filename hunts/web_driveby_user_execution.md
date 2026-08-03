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
budget:
  max_turns: 40
  max_tool_calls: 120
  max_rows: 6000
  max_wall_seconds: 900
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
           worth learning by name rather than suppressing by pattern."

/query: script hosts and executables running from Downloads, Temp, and profile scratch paths
  note:   "Path is a weaker signal than lineage — plenty of legitimate
           installers run from Downloads. Rank by what ELSE is true: unsigned,
           first-seen hash estate-wide, name imitating a document
           ('invoice_pdf.exe'), or double extensions. The path buys a look;
           the accessories buy the lead."

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
           join only surfaces the remainder."

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
