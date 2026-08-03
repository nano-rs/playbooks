---
kind: hunt
title: "Someone loosening the estate's grip on its own history"
subtitle: "Retention shortened, immutability disabled, jobs deleted, restore points purged — the backup platform's own logs, not the endpoint's"
category: data
owner: "team · soc-leads"
authored: 2026-08-03
schedule: "30 9 * * *"
timezone: "UTC"
lookback_window: 24h
telemetry:
  all_of:
    - backup.audit
mitre_tactic: impact
mitre_technique: T1490
budget:
  max_turns: 30
  max_tool_calls: 100
  max_rows: 4000
  max_wall_seconds: 600
tags:
  - data
  - backup
  - ransomware
  - tripwire
---
# Someone loosening the estate's grip on its own history

**Hypothesis:** ransomware crews learned to kill backups before killing anything else, and they learned to do it at the *platform* — consoles, retention policies, immutability locks — not host by host. The ransomware-precursor hunt sees the endpoint half (`vssadmin`, `wbadmin`); this hunt reads the backup product's own audit trail, where the events are few, heavy, and almost never legitimate outside a change window. It is closer to a tripwire set than a statistical hunt, and that is its value: quiet almost every night, unambiguous when not.

## The sabotage verbs

/query: retention, immutability, and copy-policy changes
  window: 24h
  from:   backup_platform
  note:   "Retention shortened, immutability or object-lock disabled,
           secondary-copy jobs turned off, GFS schedules gutted. Each is
           one API call that converts 'we can restore' into 'we think we
           can restore'. Legitimate frequency is quarterly at best —
           every event here can afford an individual reading, and a
           CLUSTER of them in one session is the finding regardless of
           who the actor claims to be."

/query: job and restore-point deletions
  note:   "Deleted backup jobs, purged restore points, catalogs cleared.
           Rank by what was deleted FOR: restore points for domain
           controllers, database servers and the backup server itself are
           the ones a crew clears first, because they are the ones a
           recovery needs first. Bulk deletion in tight sequence is the
           storm shape, same as the endpoint hunt's service kills."

## The console and its keys

/query: authentication anomalies against the backup console
  note:   "New source networks, first-seen admin accounts, off-hours
           sessions, and lockout bursts preceding a success. The backup
           console is a tier-zero asset that rarely gets tier-zero
           treatment — its admin population is tiny, so its baseline is
           tight, and a first-ever source for a known admin is already
           worth the pivot."

/pivot: what the authenticated session did, end to end
  note:   "The sabotage verbs plus the session that issued them tell one
           story: walk it. A session that authenticates from a new place,
           shortens retention, deletes restore points, and logs out has
           no innocent reading — and if the session's source host appears
           in the lateral-movement hunt's new edges, say so; the crew
           reached the console THROUGH something."

/query: backup service account used outside the platform's own machinery
  note:   "The backup service credential is a skeleton key — it can read
           every host it protects. Interactive logons with it, or its use
           from hosts that are not backup infrastructure, is the
           service-account-interactive hunt's logic applied to the single
           account whose theft matters most."

## Rule out the boring explanation

/enrichment: change tickets, storage-pressure events, and migration projects
  note:   "Storage teams do shorten retention when arrays fill, and
           migrations do delete jobs wholesale. Both arrive with tickets,
           in windows, from the storage team's identities — and storage
           pressure explains retention edits without explaining
           immutability being switched off, which nothing operational
           explains in a hurry. Carve precisely, not generously."

## Emit

/lead: backup capability reduced outside a change window
  entity: host
  note:   "Evidence carries the exact settings before and after, the
           deletion inventory, the session timeline, and the joined
           context from endpoint and lateral hunts where it exists. Like
           the ransomware tripwires, the narrative should state urgency
           plainly: capability that took years to build was reduced in
           minutes, and the window in which that matters may be hours.
           Also state the blast radius as a restore question — WHAT can
           no longer be restored, as of when."
