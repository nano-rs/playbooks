# Hunts

Hunts are the **proactive** half of this library. A response playbook answers *"an alert fired, now what?"*; a hunt asks *"is something here nobody has alerted on?"* — on a schedule, with no case and no triggering alert, and it may find nothing at all.

They live here rather than in a separate repository because they share the authoring language, the sync mechanism, and the review workflow with the response playbooks alongside them. What they do not share is a runtime.

## The contract

```yaml
kind: hunt          # REQUIRED. Its absence means "response playbook".
```

`kind` is read from the frontmatter, never inferred from the directory. The path a repository is synced from is operator-configurable, so inferring from `hunts/` would silently reclassify every file in this folder the day someone retargets the repo.

### A synced hunt always lands disabled

`schedule:` below is a **suggested cadence**, not an instruction. Import records it and leaves the hunt switched off; a human enables it in the product.

This is not caution for its own sake. If a merge could enable a hunt, then merge access to this repository would silently be equivalent to the `hunts:run` permission — an autonomous process reading production telemetry on a cron, granted by approving a markdown file. The reviewer would be looking at prose, not a privilege grant. So the switch stays in the product, where it is visibly a decision.

The same rule governs recon-generated drafts: *nothing generated ever schedules itself.*

## Frontmatter

```yaml
---
kind: hunt
title: "Short, specific, reads as a hypothesis"
subtitle: "One line on what pattern this looks for and why it is worth looking"
category: identity        # identity | endpoint | cloud | data | network | email
owner: "team · soc-leads"
authored: 2026-07-30

# Suggested cadence. Recorded on import; a human enables it.
schedule: "0 3 * * *"
timezone: "UTC"
lookback_window: 24h

# ATT&CK data sources are mapped to nano source types, and a hunt whose
# required source is unhealthy is HELD rather than run partial — comparable
# yield matters more than a result.
required_source_types:
  - windows_security
  - squid_proxy
mitre_tactic: lateral-movement
mitre_technique: T1021

# The ceiling a sweep may spend. NOT a prescribed method: inside this budget the
# agent chooses its own path — it may open on a raw query, pivot repeatedly, or
# abandon the hypothesis entirely and follow something better. Constraining the
# SHAPE of an investigation turns hunting back into a saved search.
budget:
  max_turns: 40
  max_tool_calls: 120
  max_rows: 5000
  max_wall_seconds: 900

tags: [lateral-movement, rdp]
---
```

## Step kinds

Hunts use a narrower vocabulary than response playbooks, because nobody is watching:

| Step | Purpose |
|---|---|
| `/query` | Pull data. The opening query is a starting point, not a contract. |
| `/pivot` | Follow an entity somewhere else. |
| `/enrichment` | Context from another system. |
| `/baseline` | Compare against stored history — "is this new for this asset?" |
| `/lead` | Emit a candidate finding with its evidence. |

`/decision`, `/review` and `/action` are **not available**. The first two are meaningless with no human present; `/action` changes the world, which is exactly what an unattended process on a schedule must not do.

## What a hunt cannot do

A sweep submits evidence and a narrative. It does not — and structurally cannot — set a lead's score, choose its fingerprint, write a suppression, schedule itself, promote a lead to a case, or ship a detection rule. Those are server-computed or analyst-confirmed. The freedom to wander is affordable precisely because the output is narrow.

## Writing a good hunt

- **State a hypothesis, not a query.** "Service accounts should not authenticate interactively" is a hunt; "list 4624 events" is a saved search.
- **Name the boring explanation in the body.** The agent should rule out the benign case before emitting a lead, and it needs to know what the benign case looks like here.
- **Prefer a narrow window and a wide question.** A hunt that scans 90 days to find one thing is a report; a hunt that asks a sharp question of yesterday can run nightly.
- **Expect to be wrong most nights.** A hunt that fires every sweep is a detection rule that has not been written yet — and if the same shape keeps recurring and getting promoted, the product will offer to make it one.
