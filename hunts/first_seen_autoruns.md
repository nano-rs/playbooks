---
kind: hunt
title: "Autostart entries that appeared yesterday"
subtitle: "Run keys, scheduled tasks, services and WMI subscriptions judged by estate-wide first-seen and by what wrote them"
category: endpoint
owner: "team · soc-leads"
authored: 2026-08-03
schedule: "0 4 * * *"
timezone: "UTC"
lookback_window: 24h
telemetry:
  all_of:
    - endpoint.persistence
mitre_tactic: persistence
mitre_technique: T1547
budget:
  max_turns: 40
  max_tool_calls: 120
  max_rows: 6000
  max_wall_seconds: 900
tags:
  - endpoint
  - persistence
  - autoruns
---
# Autostart entries that appeared yesterday

**Hypothesis:** an intruder who intends to come back must write themselves into something that survives a reboot, and the set of places to do that is famous and finite — run keys, scheduled tasks, services, WMI subscriptions, startup folders. The estate's autostart surface is large but astonishingly repetitive, so a value that no host had last week is a short list worth reading every morning.

## The census and the newcomers

/baseline: autostart entries across the estate — locations, values, target binaries
  window: 30d
  note:   "Key on the VALUE and the target binary hash, not the location —
           locations are shared by everything. The census collapses thousands
           of hosts into a few thousand distinct entries, almost all of them
           the same software everywhere. This hunt is a diff against that."

/query: autostart writes whose value is absent from the census
  window: 24h
  from:   windows_sysmon
  note:   "First-seen estate-wide, not first-seen on the host — new software
           reaching one more machine is not news. Rank WMI event
           subscriptions and services above run keys: rarer channels carry
           more intent, and WMI persistence in particular has almost no
           legitimate authors outside the management stack."

## The writer carries the story

/pivot: the process tree that wrote the new entry
  note:   "This is the strongest single discriminator the hunt has. An MSI
           engine or a deployment agent writing an autostart is software
           being installed; a script host, an Office child, or an
           unsigned binary in a user profile writing one is persistence
           being planted. Walk the tree up until it hits something with a
           reason to exist."

/enrichment: signer, age and global prevalence of the persisted binary
  note:   "Where does the autostart POINT: a signed binary in Program Files,
           or an unsigned one in AppData with a name imitating the former?
           Path–signer mismatch is the classic. Prevalence is corroboration
           only; day-one software is rare everywhere."

## Rule out the boring explanation

/baseline: how many hosts gained the same entry, and when
  note:   "Four hundred hosts in one maintenance window is a rollout; the
           same logic that clears deployments in the LOLBin hunt clears them
           here. One host — or worse, one host followed by a slow trickle of
           others — is the shape that deserves the analyst."

/query: did the persisted binary run yet, and what did it do
  note:   "An entry that has already fired and spawned network activity or
           further children upgrades itself. One that has not fired yet is
           still a lead — persistence is planted for later — but say which
           case the reader is looking at."

## Emit

/lead: first-seen autostart with an untrusted writer
  entity: host
  note:   "Evidence carries the entry verbatim, the writing process tree, the
           estate first-seen fact, the host count, and the target binary's
           signer and path. If the writer was the deployment stack, no lead —
           record the rollout in the narrative so next sweep's census already
           knows it."
