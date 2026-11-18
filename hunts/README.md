# Hunts

Hunts are the **proactive** half of this library. A response playbook answers *"an alert fired, now what?"*; a hunt asks *"is something here nobody has alerted on?"* It runs on a schedule, with no case and no triggering alert, and it may find nothing at all.

They live here rather than in a separate repository because they share the authoring language, the sync mechanism, and the review workflow with the response playbooks alongside them. What they do not share is a runtime.

Every hunt in this folder uses the **playbook v2** format (nano 2.0.32 and later): a stated hypothesis, tested by a small set of deterministic pivots that the server runs with no model, followed by an AI investigator that reads the pivot results as data and explains them, and a separate reviewer that decides what reaches a human.

## The contract

```yaml
kind: hunt          # REQUIRED. Its absence means "response playbook".
```

`kind` is read from the frontmatter, never inferred from the directory. The path a repository is synced from is operator-configurable, so inferring from `hunts/` would silently reclassify every file in this folder the day someone retargets the repo.

### A synced hunt always lands disabled

`schedule:` below is a **suggested cadence**, not an instruction. Import records it and leaves the hunt switched off; a human enables it in the product.

This is not caution for its own sake. If a merge could enable a hunt, then merge access to this repository would silently be equivalent to the `hunts:run` permission: an autonomous process reading production telemetry on a cron, granted by approving a markdown file. The reviewer would be looking at prose, not a privilege grant. So the switch stays in the product, where it is visibly a decision. For the same reason a file cannot choose what happens to an escalation (see Policy below).

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
lookback_window: 24h      # 15m, 24h, 7d ... at most 30d

# Describe what evidence the hunt needs, not what a customer happened to name
# its source types. Recon maps these semantic capabilities to concrete source
# names (for example `corp_okta_prod` -> `identity.authentication`).
telemetry:
  # Every capability in this group must resolve to a live source.
  all_of:
    - identity.authentication
  # When present, at least one capability in this group must resolve.
  one_of:
    - network.web
    - network.connection
  # These improve the hunt but never hold a sweep.
  optional:
    - endpoint.process
mitre_tactic: lateral-movement
mitre_technique: T1021

# Playbook v2 (nano 2.0.32+).
hypothesis: "Service accounts authenticate machine to machine. One logging on
  interactively (console, RDP, unlock) is a person holding its credentials."
risk_weight: 6            # 1..10, scheduler priority (default 5)
default_severity: high    # high | medium | low | info (default medium)
pivots:
  - name: auth_coverage
    role: coverage
    query: 'class_uid=3002 | stats count, dc(user.name) AS users by logon_type_id'
  - name: interactive_service_logons
    role: discovery
    query: 'class_uid=3002 status="Success" logon_type_id IN (2,10,11) user.name=svc* | stats count, dc(src_endpoint.ip) AS sources by user.name, dst_endpoint.hostname | sort -count | head 100'
    scorer:
      method: rare
      field: user.name
      threshold: 2

# The ceiling a sweep may spend. NOT a prescribed method: inside this budget the
# investigator chooses its own path after reading the pivots.
budget:
  max_turns: 40
  max_tool_calls: 60
  max_rows: 5000
  max_wall_seconds: 900

tags: [lateral-movement, rdp]
---
```

`required_source_types` remains available for private, deployment-specific
hunts that intentionally require an exact source name. Stock and portable hunts
should use `telemetry` so customer naming does not become part of the contract.

## Playbook v2: hypothesis and pivots

### `hypothesis`

One to four sentences, at most 4,000 characters: what the attacker behavior looks like in telemetry, and what its benign twin looks like. It is trusted, analyst-authored text; the investigator tests it and the reviewer judges findings against it. The **Hypothesis:** paragraph in the body is the human version of the same idea.

A file without `hypothesis` still imports: the product reads the subtitle, else the first paragraph of the body, as its hypothesis. Stock hunts always set it.

### `pivots`

Up to 12 per hunt (stock hunts use 3 to 7). Each pivot is a deterministic query the server runs over the sweep window, through the query guard, with **no model**. The investigator starts from their results.

| Key | Required | Meaning |
|---|---|---|
| `name` | yes | Unique in the file, 1 to 64 characters of `a-z`, `0-9`, `_`, `-`. |
| `role` | yes | `coverage`: proves the telemetry the hypothesis needs exists (a denominator). `discovery`: surfaces candidates. |
| `dataset` | no | Which Search dataset the **nPL** query reads: `events` (default, the event table), `signals` (detections that already fired) or `risk` (the per-entity risk grain). See below. |
| `query` | yes | At most 8,192 characters, on one line. |
| `scorer` | no | An outlier scorer over the pivot's rows (see below). |
| `sources` | no | The `source_type`s the pivot needs. Leave it out in stock hunts: the product infers it from the query, and a pivot with no source predicate runs on any source. |

Rules for every pivot:

- **OCSF only.** nano stores events as OCSF. Use real `ocsf_logs` columns (`device.hostname`, `actor.user.name`, `process.cmd_line`, `src_endpoint.ip`, `dst_endpoint.port`, `api.operation`, `query.hostname` ...), never the legacy UDM names (`src_ip`, `user`, `command_line`, `event_id` ...). Field placement depends on the class: process, file and registry events name the host in `device.hostname` and the user in `actor.user.name`; authentication names the subject in `user.name` and the source in `src_endpoint.*`; API activity names the identity in `actor.user.name`.
- **Filter on `class_uid` first**, then specific field predicates. Do not filter on customer `source_type` names in a stock hunt.
- **Aggregate first.** A pivot reads at most 1,000 rows (its scorer sees all of them) and hands the investigator the first 200, and every pivot of a sweep draws on the same `budget.max_rows`. So discovery pivots group by the entity (`stats ... by`), apply thresholds with `where`, and end in `sort` (with a tiebreak key) and `head`. A raw `table` of events is only acceptable behind a very selective filter, with `head`.
- **Deterministic and cheap.** No `ai`, `inputlookup`, `join`, `append`, `transaction` or `sequence` commands, and nothing that depends on the wall clock: the server binds the sweep window.
- nPL string comparisons are already case-insensitive. Write `process.name="powershell.exe"`; the compiler emits the indexed `lower(col)` form and puts the time bounds and every filter in one `WHERE`.

### Datasets: `events`, `signals`, `risk`

Every pivot is nPL, the same language and compiler as Search, so an analyst always reads the pivot's own query. `dataset:` picks what it reads, exactly like `dataset=<name>` in Search:

- `events` (default): the event table, OCSF columns.
- `signals`: every detection that fired in the sweep window, real-time and scheduled, one row each. Columns: `id`, `timestamp`, `rule_id`, `rule_name`, `severity` (lowercase), `risk_score`, `risk_entity`, `matched_log_id` (the matched event's `id`), `source_type`, `detection_path` (`realtime` or `scheduled`).
- `risk`: the per-entity risk grain (decayed over trailing 24h / 7d windows anchored at the end of the sweep window). A risk pivot reads the entities whose latest finding falls inside the sweep window.

Do not start the query itself with `dataset=` (the Search spelling): the `dataset:` field picks the dataset, and import refuses the selector in the query. The server compiles the pivot for its dataset and runs it through the same guard and table allowlist as every hunt query. An events pivot can still reach detections through a subsearch, for example `id IN [dataset=signals severity="high" | return matched_log_id]`, and every events pivot's rows come back with the detections their entities already triggered, so a pivot does not need its own "already detected" column.

nPL notes that matter for pivots:

- **Compare two fields in `eval`, not in `where`.** `where a=b` compares the field `a` with the text `"b"`. Write `| eval same=if(a==b, 1, 0) | where same=1`.
- **Chained aggregation** works: `| stats ... by a, b | stats ... by a`, and `eventstats` adds a group's aggregate to every row (use it instead of an `IN` subquery over the same table).
- **`streamstats` runs in timestamp order** (oldest first). To keep the newest N rows of a group, count the group with `eventstats count AS n by g`, number it with `streamstats count AS seq by g`, and keep `where seq>n - N`.
- Time arithmetic is in seconds: `eval recent=if(timestamp>=now() - 86400, 1, 0)`.

A legacy `dataset: signals` pivot written as one SQL `SELECT` over `{signals}` / `{events}`, binding `{earliest:DateTime64(6, 'UTC')}` / `{latest:DateTime64(6, 'UTC')}`, still runs (nano 2.0.32), but it is no longer the authoring path: analysts see it only through an approximate nPL conversion.

### Scorers

```yaml
scorer:
  method: zscore    # zscore | iqr | rare
  field: distinct_rules
  threshold: 2
```

A scorer is computed in code over the pivot's rows, after the pivot runs, with no model. Use one only where a statistical outlier **is** the signal, and score a population, not a list already cut by a threshold: the largest z-score n rows can produce is (n-1)/sqrt(n), so a `zscore` threshold of 3 needs at least 11 rows to ever flag one.

| Method | Flags | `threshold` |
|---|---|---|
| `zscore` | rows where the numeric `field` is more than `threshold` standard deviations from the mean | above 0, at most 100 |
| `iqr` | rows outside `[Q1 - k*IQR, Q3 + k*IQR]`, k = `threshold` | above 0, at most 100 |
| `rare` | values of `field` seen in at most `threshold` rows | 1 to 1,000,000 |

`field` is a column the pivot returns: an alias set with `AS`, or a grouped field name exactly as written (`process.parent_process.name`).

### Policy

| Key | Values | Default |
|---|---|---|
| `risk_weight` | 1 to 10: scheduler priority among due hunts | 5 |
| `default_severity` | `high`, `medium`, `low`, `info`: the severity floor of the hunt's findings; the reviewer may raise it, never lower it | `medium` |

A file cannot set `critical`: a critical floor would let every escalation through without the reviewer's confidence check, so an analyst raises a hunt to `critical` in the product.

There is no `escalation_mode` key. Whether a hunt's escalations stay off, notify, or open cases is chosen in the product: every synced hunt starts at `notify`, and case mode unlocks only once the reviewer has a proven record on that hunt. Like enabling the hunt, it is a human decision, so the product ignores the key if a file sets it.

Releases before 2.0.32 ignore these keys, and every synced hunt starts at the defaults there.

### Budget

`budget:` is the ceiling one sweep may spend, checked at import against fixed ceilings. A file without it gets the defaults. Each sweep also gets an AI token budget of 500,000, which a file does not set.

| Field | Default | Ceiling |
|---|---|---|
| `max_turns` | 40 | 200 |
| `max_tool_calls` | 60 | 1,000 |
| `max_rows` | 5,000 | 100,000 |
| `max_wall_seconds` | 900 | 3,600 |

### Older releases

The v2 keys are additive. nano releases before 2.0.32 ignore `hypothesis`, `pivots`, `risk_weight` and `default_severity` (the frontmatter parser ignores unknown keys) and run the hunt from its body as before. That is why every hunt keeps an opening `/query` or `/baseline` step in the body: older releases seed the sweep from it, and every release requires it.

## Step kinds

The body is the human documentation of the hunt and the investigator's guidance. Hunts use a narrower step vocabulary than response playbooks, because nobody is watching:

| Step | Purpose |
|---|---|
| `/query` | Pull data. The opening query is a starting point, not a contract. |
| `/pivot` | Follow an entity somewhere else. |
| `/enrichment` | Context from another system. |
| `/baseline` | Compare against stored history: "is this new for this asset?" |
| `/lead` | Emit a candidate finding with its evidence. |

`/decision`, `/review` and `/action` are **not available**. The first two are meaningless with no human present; `/action` changes the world, which is exactly what an unattended process on a schedule must not do.

## What a hunt cannot do

A sweep submits evidence and a narrative. It does not, and structurally cannot, set a lead's score, choose its fingerprint, escalate a finding (only the reviewer can), schedule itself, put itself in case mode, or ship a live alerting rule. Those are server-computed, reviewer-decided or analyst-confirmed. The freedom to wander is affordable precisely because the output is narrow.

## Validating a change

`scripts/validate_hunts.py` checks every file in this folder against the contract above (frontmatter, steps, budget ceilings, pivot shape, datasets, OCSF field names, policy values, and the legacy SQL rules). CI runs it on every pull request that touches `hunts/`:

```sh
pip install pyyaml
python3 scripts/validate_hunts.py hunts
```

With `NANO_VALIDATE_URL` and `NANO_VALIDATE_TOKEN` set (a nano 2.0.32+ install and an API token with `hunts:view`), it also compiles every pivot on that install through `POST /api/hunts/pivots/validate`, the same check the product applies when a hunt is saved. Nothing is executed.

## Writing a good hunt

- **State a hypothesis, not a query.** "Service accounts should not authenticate interactively" is a hunt; "list 4624 events" is a saved search.
- **Measure, then explain.** Put the shape you are looking for in the pivots, with thresholds the investigator does not have to rediscover every night. The model's job is to test the candidates against their benign twin and explain them, not to find them.
- **Name the boring explanation in the body.** The investigator rules out the benign case before filing a lead, and it needs to know what the benign case looks like here.
- **Prefer a narrow window and a wide question.** A hunt that scans 90 days to find one thing is a report; a hunt that asks a sharp question of yesterday can run nightly.
- **Expect to be wrong most nights.** A hunt that fires every sweep is a detection rule that has not been written yet, and if the same shape keeps recurring and getting promoted, the product will offer to make it one.
