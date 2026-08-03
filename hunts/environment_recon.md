---
kind: hunt
title: "The terrain map every other hunt is standing on"
subtitle: "Inventory of log sources, volumes, freshness and field coverage — run on demand, not on a cadence"
category: data
owner: "team · soc-leads"
authored: 2026-08-03
schedule: "0 6 1 * *"
timezone: "UTC"
lookback_window: 30d
telemetry:
  all_of: []
budget:
  max_turns: 30
  max_tool_calls: 100
  max_rows: 8000
  max_wall_seconds: 900
tags:
  - telemetry
  - coverage
  - recon
---
# The terrain map every other hunt is standing on

**Hypothesis:** the estate's telemetry is not what everyone believes it is. Sources go quiet without anyone noticing, fields stop being populated after an agent upgrade, and a hunt that runs against a half-dead source returns a confident-looking nothing. This sweep exists so the *other* hunts' silence can be trusted.

This is not a hunt for adversary behaviour, and the suggested monthly cadence is a floor, not a rhythm — the real triggers are onboarding a new source, a fleet agent change, or another hunt starting to come back HELD. It is cheap, it touches no entity, and it is the reason semantic telemetry requirements can gate the rest of the library: a hunt held for a sick source is only useful if something actually diagnoses the source.

## What exists and how much of it

/query: distinct source types with per-day event volumes
  window: 30d
  note:   "The volume trend matters more than the total. A source that halved
           three Tuesdays ago did not get quieter — something upstream broke or
           was changed, and every hunt reading it has been sweeping half an
           estate since."

/query: most recent event per source type
  note:   "Freshness, not volume. A source can show healthy daily totals from a
           backfill while its live tail is hours behind — and a hunt with a 24h
           lookback reads the gap as calm."

## Is the quiet real

/baseline: per-source volume against its own trailing history
  note:   "Silent ingest breakage is the boring explanation for a quiet source.
           The un-boring one is that log tampering looks exactly the same from
           here — a source an attacker switched off and a source a migration
           broke produce the same silence, which is why a dead feed is a lead
           and not just a ticket."

/query: field-coverage sample on load-bearing fields
  note:   "Sample, do not census. Pull a few hundred recent events per source
           and check that the fields the other hunts join on — hostname, user,
           process, source IP — are actually populated. A field that went null
           after an upgrade breaks every join downstream without raising any
           error anywhere."

## Emit

/lead: telemetry gap — a source that is dark, degraded, or hollowed out
  entity: source
  note:   "Evidence should carry the volume trend, the freshness lag, and which
           hunts list the source as required — the reader of this lead is
           deciding whether the estate has been blind, and for how long.

           If everything is healthy, say so in the sweep narrative with the
           numbers. 'Nothing found' from this sweep is the one nothing the rest
           of the library gets to lean on."
