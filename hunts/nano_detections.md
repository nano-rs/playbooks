---
kind: hunt
title: "Yesterday's detections, re-read for the story no single rule could see"
subtitle: "Reviews 24h of the detection engine's own output and escalates on convergence, novelty and the modes nobody is watching"
category: identity  # placeholder — see "A note on this playbook's metadata" below
owner: "team · soc-leads"
authored: 2026-08-05
schedule: "0 6 * * *"
timezone: "UTC"
lookback_window: 24h

# Deliberately NO all_of / one_of. This hunt reads the engine's own findings
# stream, which is written by nano itself and has no bound source capability —
# naming one that recon cannot resolve would hold every sweep forever, silently.
# `optional` never blocks, so it is the only safe way to say "richer with these".
telemetry:
  optional:
    - identity.authentication
    - endpoint.process
    - network.connection

hypothesis: "Every detection in the window was scored once, by a rule that could only see its own matches. Several DIFFERENT rules converging on one entity, a high or critical rule that fired only a handful of times under a flood of louder ones, or a matched event behind the most convergent entities that tells a multi-stage story is what no single rule could rank. The benign twin is a scanner, a service account or one misparsing source tripping many rules at once; one loud rule firing a hundred times is tuning work, not a hunt result."
risk_weight: 6
default_severity: medium
pivots:
  - name: detection_census
    role: coverage
    dataset: signals
    query: '* | stats count AS fires, dc(risk_entity) AS entities, values(severity) AS severities, sum(risk_score) AS total_risk, min(timestamp) AS first_fire, max(timestamp) AS last_fire by rule_name, detection_path | sort -fires, rule_name | head 200'
  - name: signal_clusters
    role: discovery
    dataset: signals
    query: 'risk_entity!="" | eval low=if(severity="low" OR severity="info" OR severity="informational", 1, 0) | stats dc(rule_id) AS distinct_rules, count AS fires, sum(low) AS low_fires, values(rule_name) AS rules, min(timestamp) AS first_fire, max(timestamp) AS last_fire by risk_entity | sort -distinct_rules, -fires, risk_entity | head 200'
    scorer:
      method: zscore
      field: distinct_rules
      threshold: 2
  - name: high_severity_low_volume
    role: discovery
    dataset: signals
    query: 'severity IN ("high", "critical") | stats count AS fires, dc(risk_entity) AS entities, values(risk_entity) AS entity_sample, values(matched_log_id) AS matched_log_ids, min(timestamp) AS first_fire, max(timestamp) AS last_fire by rule_id, rule_name, severity, detection_path | where fires<=5 | eval is_critical=if(severity="critical", 1, 0) | sort -is_critical, fires, rule_name | head 200'
  - name: top_entity_events
    role: discovery
    dataset: signals
    query: "SELECT id, timestamp, source_type, class_uid, `device.hostname`, `actor.user.name`, `src_endpoint.ip`, `dst_endpoint.ip`, `actor.process.cmd_line`, `process.name`, `process.cmd_line`, `user.name`, `query.hostname`, `api.operation` FROM {events} WHERE timestamp >= {earliest:DateTime64(6, 'UTC')} AND timestamp <= {latest:DateTime64(6, 'UTC')} AND id IN (SELECT matched_log_id FROM {signals} WHERE timestamp >= {earliest:DateTime64(6, 'UTC')} AND timestamp <= {latest:DateTime64(6, 'UTC')} AND risk_entity IN (SELECT risk_entity FROM {signals} WHERE timestamp >= {earliest:DateTime64(6, 'UTC')} AND timestamp <= {latest:DateTime64(6, 'UTC')} AND risk_entity != '' GROUP BY risk_entity ORDER BY uniqExact(rule_id) DESC, risk_entity ASC LIMIT 10)) ORDER BY timestamp DESC LIMIT 200"

budget:
  max_turns: 50
  max_tool_calls: 150
  max_rows: 8000
  max_wall_seconds: 1200

tags:
  - detection-review
  - triage
  - meta
---
# Yesterday's detections, re-read for the story no single rule could see

**Hypothesis:** every finding in the last 24 hours was already scored once, by a rule that could only see its own matches. That is the blind spot. A rule cannot know that the host it just flagged was flagged twice more by other rules under other tactics, that it is the first time it has ever fired, or that it is running in a mode where nobody will read its output. The engine produces a haystack and then asks a human to find the needle in it; this sweep re-reads the haystack for **shape** — convergence, novelty, and unwatched modes — and escalates only what a per-rule score structurally could not surface.

**Expect most mornings to be empty.** A detection estate that yields an escalation every single night is one where the noisy rules have not been tuned yet, and that is a tuning problem, not a hunting result.

## Where the findings live

/note: the detections source and its field shape
  note:   "Detection output is read through the signals source, never by
           filtering the event table yourself. It already unions the two
           paths nano writes: real-time signals, and scheduled findings
           (stored as OCSF Detection Finding rows, class_uid 2004, in
           ocsf_logs). Every row has the same ten columns: id, timestamp,
           rule_id, rule_name, severity (lowercase), risk_score,
           risk_entity, matched_log_id (the id of the OCSF event the rule
           matched), source_type (the origin source of that event) and
           detection_path (realtime or scheduled).

           detection_path is the only split the source carries. It tells
           you which engine produced the row, not whether the rule raised
           an alert: rule mode, MITRE mapping and alert state are not
           columns here. All four pivots of this hunt read this source,
           and top_entity_events joins matched_log_id back to the raw OCSF
           events."

/note: what this sweep can and cannot know about an alert
  note:   "HARD BOUNDARY, and the easiest thing in this playbook to get wrong.
           An alert has two halves living in two places. The FIRING is here in
           the signals source (its rule, severity, entity, risk score,
           detection path and the matched event it points at), and all of it
           is readable.

           The LIFECYCLE is not. Whether an alert was acknowledged, who owns
           it, whether it was closed, and whether it was dispositioned true
           positive, false positive or benign all live in a database this
           sweep has no access to and no permission for. Seeing an alert_id
           does not mean the alert's fate is knowable.

           So never assert that an alert was missed, ignored, unread,
           unassigned or wrongly closed. That claim cannot be evidenced from
           here, and a lead that makes it will be confidently wrong in front
           of the analyst best placed to notice. Report what FIRED and what it
           converged with; let the human supply the triage half."

/query: the 24h finding population, by rule and by entity
  window: 24h
  from:   signals
  note:   "The detection_census pivot already measures the first
           distribution (fires, entities and severities per rule_name and
           detection_path); signal_clusters measures the second.

           Open on the census, not on a suspicion. Two distributions matter
           and they answer different questions: count by rule_name
           tells you which rules are loud, and count by risk_entity
           tells you which entities are busy. The second is the one worth reading — loud
           rules are a tuning backlog, busy entities are the hunt.

           Note the shape of the day before going further. A single rule
           holding most of the volume usually means one misconfigured source
           or one broken parser, and that fact reframes everything below."

## Convergence — the thing no rule can see

/query: entities carrying findings from two or more DISTINCT rules
  note:   "This is the highest-yield question in the sweep. A user hit forty
           times by one rule is that rule's noise profile. A user hit by four
           different rules is a story, and nothing in the engine ranks it that
           way because each rule scored its own match in isolation.

           The signal_clusters pivot already ranks by distinct rule_id per
           risk_entity and z-scores distinct_rules; its rows are the
           convergence candidates.

           Rank by DISTINCT rule_id, never by signal
           count (the count is dominated by whichever rule is loudest and
           will bury exactly the entity you are looking for). Then read the
           surviving entities' rules for their MITRE tactics (the signals
           source carries no tactic column, so take it from the rule
           definitions): convergence across distinct tactics
           outranks convergence within one. Three rules that all fire on the
           same credential-access behaviour are three views of one event;
           credential-access plus discovery plus lateral-movement on one host
           in one night is a kill chain, and it is the only pattern here that
           should ever wake somebody."

/query: accumulated entity risk, for the entities convergence surfaced
  from:   signals
  note:   "Risk is not a separate table: it is the risk_score column of the
           signals source, keyed by risk_entity. Sum it per entity over the
           window for the entities convergence surfaced.

           The question it answers is whether this entity's 24h activity is
           a spike on a quiet baseline or the continuation of a slope that
           has been climbing for a week. This hunt's window is 24h, so the
           week-long slope belongs to the sibling playbook
           hunts/nano_risky_entities.md, which sums the same column over 7d
           and splits off the last 24h. A climbing slope with new tactics on
           top is the strongest signal this sweep can produce."

## Novelty — first firings and first entities

/baseline: has this rule ever fired before, and has it ever fired on this entity
  window: 30d
  note:   "Two different novelty questions, and the second is much better than
           the first. A rule firing for the first time ever is often just a
           rule that was deployed this week — check the rule's own age before
           treating a first firing as meaningful, or every deployment day
           produces a false escalation.

           The stronger question is per-rule entity novelty: a rule that fires
           five hundred times a day against the same three build servers, now
           firing against a fourth host, is far more interesting than its
           volume ever was. Loud rules are not useless — they are baselines
           with an alerting problem, and their rare entities are free signal
           that tuning thresholds throw away."

## The modes nobody is watching

/query: matches from rules in `live` mode — the ones that raised no alert
  note:   "nano's rule lifecycle is staging -> live -> alerting. A rule in
           LIVE mode matches and its findings are written here, but it raises
           no alert — it is baking in, and by design nobody is reading it.
           That makes live mode a genuine blind spot with a real detection
           behind it: the rule is good enough to have been promoted out of
           staging, and its matches are landing where only this sweep looks.

           The signals source has no rule-mode column: read the mode from the
           rule definitions of the rules the census lists, and treat rows from
           live-mode rules as the unwatched set. An entity whose profile is
           built from live-mode matches has a detection
           story that provably reached no queue.

           A high or critical severity live-mode finding on an entity that
           also appears in the convergence set is the single best escalation
           this playbook can produce — the estate already decided that
           behaviour was worth detecting, and then routed the answer nowhere."

/query: critical and high severity findings with low volume
  note:   "The high_severity_low_volume pivot already lists every high or
           critical rule that fired five times or fewer in the window, with
           its entities and matched event ids.

           Severity and volume are inversely informative. The critical rule
           that fired ONCE yesterday is the one that got buried under the
           medium-severity rule that fired nine thousand times, and a human
           scrolling an alert queue sorted by time will never reach it.
           Pull the low-count high-severity tail explicitly — it is small,
           it is cheap, and it is where the engine's own best judgement went
           unread."

## Rule out the boring explanation

/enrichment: is this entity a scanner, service account, or known-noisy source
  note:   "The three factories of spurious convergence, and all three are
           knowable, small sets. Vulnerability scanners trip discovery and
           lateral-movement rules across the whole estate by design. Service
           accounts trip authentication rules by volume alone. And a single
           source that started misparsing at midnight can manufacture a
           convergence pattern out of nothing but bad field mapping.

           Check the source_type column of the entity's signals (the origin
           source of the matched event) before believing an entity: convergence that traces back to ONE source type is far
           more likely to be a parser regression than an intruder, because a
           real intruder leaves evidence in several telemetry streams at
           once. Convergence across origins is the version worth keeping."

/enrichment: was there a change window, deployment, or migration overnight
  note:   "Estate-wide changes produce estate-wide detections. Patch nights,
           image rollouts and directory migrations all generate exactly the
           fan-out shape this sweep is built to find. If many unrelated
           entities converged simultaneously, suspect a change before
           suspecting an actor — and note that a real intrusion hidden inside
           a change window is the classic reason this check should narrow the
           lead rather than kill it."

## From finding back to fact

/pivot: the raw telemetry underneath the surviving findings
  note:   "REQUIRED before emitting, for two independent reasons.

           The first is analytical: a finding is a rule's claim about the
           world, not the world. The matched-events sample inside it may be
           redacted when the origin source is restricted, and a sample is not
           the event set. Read the underlying telemetry for the entity across
           the window and confirm the behaviour actually looks the way the
           rules asserted it does. The top_entity_events pivot already reads
           the matched OCSF events behind the ten most convergent entities.

           The second is mechanical, and it silently decides whether this
           sweep produces anything at all. A lead's entity is corroborated
           server-side against entities extracted from the logs rows cited as
           evidence — and the extractor reads the OCSF entity fields: users
           from actor.user.name and user.name, hosts from device.hostname,
           src_endpoint.hostname and dst_endpoint.hostname, IPs from
           src_endpoint.ip, dst_endpoint.ip and device.ip, hashes from
           file.hashes.sha256 and process.file.hashes.sha256, processes from
           process.name, actor.process.name and process.cmd_line, files from
           file.path and file.name, URLs from http_request.url.url_string,
           and domains from http_request.url.hostname and query.hostname. It
           does NOT read a signal's risk_entity (nor a class_uid 2004 finding
           row's payload), which is the only place a detection carries its
           subject. A lead evidenced purely by signal rows therefore fails
           corroboration and is discarded
           without an error anyone sees. Cite the raw telemetry rows where
           the entity appears in its own OCSF field."

## Emit

/lead: entities whose 24h detection profile tells a story their individual rules could not
  entity: user
  note:   "Entity type follows the subject — user, host, ip, domain, hash,
           process, url, file or email — and must match the OCSF field the
           corroborating evidence came from.

           Evidence carries the distinct rules that fired with their tactics
           and severities, the timeline across the window, the novelty facts
           from the baseline step, the mode of any rule that fired
           unwatched, and the raw telemetry rows that corroborate the entity.
           State the convergence explicitly — which rules, which tactics, in
           what order — because the ordering IS the story, and a flat list of
           rule names reads as a tuning backlog rather than an intrusion.

           Say what would falsify it. A reader who can dismiss this lead in
           thirty seconds because the host is a scanner is a reader the next
           sweep should not have to spend."

## A note on this playbook's metadata

/note: why the frontmatter looks the way it does
  note:   "category: identity is a PLACEHOLDER. This playbook's surface is
           the detection engine itself, and the schema offers only the six
           telemetry-domain categories — identity, endpoint, cloud, data,
           network, email. `identity` is chosen because it is what an
           unrecognised category resolves to anyway, so the stored result is
           the same either way. Do NOT 'fix' this by inventing a category
           such as platform or soc-ops — only the six documented values are
           accepted, and a playbook carrying anything else will not sync.

           mitre_tactic and mitre_technique are deliberately ABSENT. A review
           playbook spans every tactic its underlying rules cover, and
           stamping it with one would corrupt the coverage analytics that read
           those fields.

           This hunt is scheduled but, like every synced hunt, arrives
           disabled. A human turns it on in the product."
