---
kind: hunt
title: "Entities whose risk is accelerating, not merely high"
subtitle: "Reads accumulated detection risk per entity for breadth, slope and novelty: the entities a score leaderboard ranks last and an intruder shows up as first"
category: identity  # placeholder — see "A note on this playbook's metadata" below
owner: "team · soc-leads"
authored: 2026-08-05
schedule: "0 7 * * *"
timezone: "UTC"
# 7d is the slope horizon: the signals pivots sum risk over the whole window and
# split off its last 24h, and the raw-telemetry pivot covers the same horizon.
lookback_window: 7d

# Same reasoning as hunts/nano_detections.md: risk is derived from nano's own
# findings stream and has no bound source capability. Naming one recon cannot
# resolve holds every sweep forever, silently. `optional` never blocks.
telemetry:
  optional:
    - identity.authentication
    - endpoint.process
    - network.connection

hypothesis: "A risk leaderboard sorted by total score is the estate's busiest assets, the same list every morning. A compromise shows instead as breadth (several distinct rules on one entity), slope (most of its week's risk landing in the last 24 hours) and novelty (an entity with no detections earlier in the week). The benign twin is a domain controller, scanner or service account that accumulates high risk from one or two rules at a steady rate."
risk_weight: 6
default_severity: medium
pivots:
  - name: entity_risk_totals
    role: discovery
    dataset: signals
    query: 'risk_entity!="" | eval recent_risk=if(timestamp>=now() - 86400, risk_score, 0) | stats sum(risk_score) AS total_risk, dc(rule_id) AS distinct_rules, count AS fires, sum(recent_risk) AS risk_last_24h, dc(source_type) AS origin_sources, values(rule_name) AS rules, values(severity) AS severities, min(timestamp) AS first_fire, max(timestamp) AS last_fire by risk_entity | eval breadth_ratio=round(distinct_rules / fires, 3), recent_share=round(risk_last_24h / max(total_risk, 1), 3) | sort -distinct_rules, -total_risk, risk_entity | head 200'
    scorer:
      method: zscore
      field: distinct_rules
      threshold: 2
  - name: accelerating_entities
    role: discovery
    dataset: signals
    query: 'risk_entity!="" | eval recent=if(timestamp>=now() - 86400, 1, 0), recent_risk=if(recent=1, risk_score, 0), recent_rule=if(recent=1, rule_id, ""), prior=if(recent=0, 1, 0) | stats sum(risk_score) AS total_risk, sum(recent_risk) AS risk_last_24h, dc(recent_rule) AS distinct_rules_24h, dc(rule_id) AS distinct_rules, sum(prior) AS prior_fires, dc(source_type) AS origin_sources, values(rule_name) AS rules, min(timestamp) AS first_fire, max(timestamp) AS last_fire by risk_entity | eval recent_share=round(risk_last_24h / max(total_risk, 1), 3) | where distinct_rules_24h>=2 AND recent_share>=0.5 | sort -distinct_rules_24h, prior_fires, -risk_last_24h, risk_entity | head 200'
  - name: top_risk_entity_events
    role: discovery
    query: 'id IN [dataset=signals risk_entity IN [dataset=signals risk_entity!="" | eval recent_risk=if(timestamp>=now() - 86400, risk_score, 0) | stats dc(rule_id) AS distinct_rules, sum(recent_risk) AS risk_last_24h by risk_entity | where distinct_rules>=2 | sort -risk_last_24h, risk_entity | head 10 | return risk_entity] | return matched_log_id] | eval recent=if(timestamp>=now() - 86400, 1, 0) | where recent=1 | table id, timestamp, source_type, class_uid, device.hostname, actor.user.name, user.name, src_endpoint.ip, dst_endpoint.ip, actor.process.cmd_line, process.name, process.cmd_line, query.hostname, api.operation | sort -timestamp | head 200'

budget:
  max_turns: 45
  max_tool_calls: 130
  max_rows: 6000
  max_wall_seconds: 1080

tags:
  - risk
  - rba
  - triage
  - meta
---
# Entities whose risk is accelerating, not merely high

**Hypothesis:** a risk leaderboard sorted by score is a list of the estate's busiest assets, and it is nearly the same list every morning. Domain controllers, build servers, scanners and service accounts sit permanently at the top because they generate the volume that risk is computed from, and an analyst who reads the leaderboard daily learns to skim exactly the rows an intruder would appear in. What separates a compromise from a busy asset is never the score's height — it is **breadth** (how many distinct rules and tactics contributed), **slope** (whether it is accumulating now or coasting on decaying history), and **novelty** (whether this entity has ever been here before).

All three are computable from the signals source (risk_score and risk_entity per detection). None of them are what "top risky entities" sorts by.

**Sibling playbook.** `hunts/nano_detections.md` reads the raw findings stream for the day — novelty, unwatched modes, buried criticals. This one reads what those detections *accumulated into*, per entity, over seven days. They overlap deliberately at the convergence question and answer it at different resolutions; run both.

## Where risk comes from

/note: risk is a column of the signals source, aggregated here
  note:   "There is no separate risk table to read. Every detection nano
           produces, real-time signals and scheduled findings alike (the
           latter stored as OCSF Detection Finding rows, class_uid 2004, in
           ocsf_logs), is exposed through the signals source with ten
           columns: id, timestamp, rule_id, rule_name, severity (lowercase),
           risk_score, risk_entity, matched_log_id, source_type and
           detection_path (realtime or scheduled). Entity risk is
           sum(risk_score) per risk_entity over a window. Three consequences
           that decide how this playbook must be written:

           THE WINDOW IS THE SWEEP WINDOW. The pivots bind the hunt's 7d
           lookback and split off its last 24h with sumIf on timestamp, so
           24h-versus-7d is computed per entity inside one query.

           THE SCORE IS UNDECAYED. risk_score is each detection's own score;
           nothing here applies decay or an analyst's clear. Age is read from
           first_fire / last_fire and from the 24h share instead.

           THE ROWS ARE NOT EVENT ROWS. A per-entity aggregate cannot serve
           as evidence for a lead; see the corroboration note below, which is
           even more acute here than in the detections playbook.

           Columns the pivots return: risk_entity, total_risk, risk_last_24h,
           recent_share, distinct_rules, distinct_rules_24h, fires,
           breadth_ratio, prior_fires, origin_sources, rules, severities,
           first_fire, last_fire."

/query: the accumulated risk population
  window: 7d
  from:   signals
  note:   "The entity_risk_totals pivot already returns this population (up
           to 200 entities ranked by distinct rules, then total risk) and
           z-scores distinct_rules (breadth, not total score, is the
           signal; total score is the noise).

           Open on the whole population rather than the top N, because the
           top N is the part of this dataset with the least information in
           it. Read the distribution first: where the mass sits, how long the
           tail is, and what kind of entities dominate it.

           Open on the 7d horizon, not the 24h one. Restricting to the last
           24h would drop every COASTING entity, one whose risk was earned
           earlier in the week and has gone quiet, and those are the rows
           the slope step below contrasts against.

           Note the permanent residents as you go: the entities that would
           be at the top of any morning's leaderboard. They are this
           playbook's noise floor, and the rest of the sweep is largely about
           not spending the budget on them."

## Breadth: the ranking that actually discriminates

/query: entities ranked by distinct rules, not by score
  note:   "The most important query in this playbook. entity_risk_totals
           sorts on distinct_rules before total_risk for exactly this reason.

           Score is a sum, so it is dominated by whichever rule fires most.
           An entity with hundreds of fires and distinct_rules of 1 is a
           single noisy rule pointed at a single busy asset: high score, no
           story, and it will outrank everything worth reading. An entity
           with a modest score and distinct_rules of 3 or more is a chain:
           several independent detections, written by different people for
           different reasons, agreeing about one entity.

           Tactic diversity is stronger still, because it is the hardest
           property for noise to fake: a misconfigured source floods one
           rule, and a broken parser floods one family, but neither
           manufactures credential-access AND discovery AND lateral movement
           against the same entity. The signals source has no tactic column,
           so read the tactics from the definitions of the rules listed for
           each surviving entity and rank on them before rules and score."

/query: the breadth-to-volume ratio across the population
  note:   "breadth_ratio (distinct_rules / fires) separates the two
           populations explicitly. A low ratio is repetition: one rule
           saying one thing many times. A high ratio is corroboration:
           several rules each saying something once.

           A perfect ratio on a tiny count is not interesting on its own: one
           finding from one rule is a ratio of 1.0 and means nothing. Require
           a floor on distinct_rules before reading the ratio at all."

## Slope: accumulating now, or coasting on history

/query: risk in the last 24h against risk over the week
  note:   "The accelerating_entities pivot already measures this: it keeps
           entities with two or more distinct rules in the last 24h AND at
           least half of their week's risk in that day (that threshold is
           the signal; no statistical scorer is applied).

           Where within its week does an entity's risk sit? If
           risk_last_24h is a large share of total_risk (recent_share near
           1), the risk is concentrated in the last day: a spike against the
           entity's own quiet baseline, which is the shape worth chasing. If
           recent_share is roughly a seventh, the entity accumulates at a
           constant rate: this is the signature of a service account, a
           scanner or a permanently misconfigured source, and it will sit
           high on the leaderboard forever without ever being an incident.

           The comparison must be per-entity. Comparing one entity's 24h to
           another's 7d, or to an estate-wide average, ranks large entities
           above accelerating ones and reproduces exactly the leaderboard
           this playbook exists to improve on."

/query: how recent the contributing detections are
  note:   "There is no decayed score to compare against a raw one, so read
           age directly: last_fire says whether the risk is being earned
           right now, first_fire says how long the entity has been carrying
           it, and the rules list shows what most recently drove it.

           An entity whose risk is almost all in the last day, with breadth
           behind it, is the strongest single row this source produces."

## Novelty: has this entity ever been here

/baseline: has this entity carried meaningful risk before
  window: 30d
  note:   "Inside the window, accelerating_entities reports prior_fires:
           detections on the entity before the last 24h. prior_fires of 0
           means no detection on it earlier in the week. For a longer
           history, query the signals source over 30d for the entity.

           The permanent residents are permanent, so their presence carries no
           information, but a first appearance in the upper band does. Build
           the question as band membership over time rather than exact scores:
           scores move constantly, bands rarely, and 'this host has never been
           in the top band before' is a statement an analyst can act on.

           Check the entity's peers too. One workstation newly in the band is
           a lead; forty workstations newly in the band on the same night is a
           rule deployment, a parser change or a patch window, and reading
           them as forty leads is the fastest way to lose a reader."

/note: the cleared-entity blind spot
  note:   "When an analyst clears an entity, the risk engine stops counting
           findings before the clear. The signals source does not: it lists
           every detection, so these pivots still show a cleared entity's
           earlier risk, and they cannot see that a human already looked.

           So a high, steady entity here may be one an analyst dismissed
           yesterday, and a 'new' rise may be a RE-RISE after a clear. State
           the claim carefully: 'this entity has no detections earlier in the
           window' is supportable; 'this entity has never been risky' is not.
           And note which way the uncertainty cuts: an entity that
           re-accumulates after a clear is MORE interesting than a genuinely
           new one, not less, because something a human decided was
           finished has resumed."

## Rule out the boring explanation

/enrichment: is this entity a service account, scanner, jump host, or shared infrastructure
  note:   "The permanent residents, checked by name rather than inferred from
           their scores. These are knowable, small sets in every estate, and
           membership explains sustained high score with steady slope
           completely.

           Two ways to get this wrong. Dismissing an entity purely because it
           is a service account throws away one of the better compromise
           signals available, since service-account abuse looks exactly like
           service-account behaviour until you read the breadth. And treating
           a NEW member of the infrastructure set as an old one hides freshly
           commissioned boxes — including staging systems that were never
           meant to reach production. Check the membership date, not just the
           membership."

/enrichment: was there a rule deployment, tuning change, or source onboarding in the window
  note:   "Risk is computed from detection output, so a change to the
           detections changes every score beneath it. A newly deployed rule
           firing broadly raises breadth across unrelated entities
           simultaneously — the exact pattern the breadth query is built to
           find. A newly onboarded log source does the same by supplying
           telemetry that existing rules have never seen before.

           If many unrelated entities gained breadth at once, suspect the
           detection layer before suspecting the estate."

## From an aggregate back to fact

/pivot: the findings behind the score, then the raw telemetry beneath them
  note:   "REQUIRED, in two hops, and this is stricter than the equivalent
           step in the detections playbook.

           A per-entity risk row is a query-time aggregate. It is not a stored
           row, it has no timestamp of its own, and it cannot be cited as
           evidence for anything. Lead corroboration matches the entity
           against entities the server extracts from the raw OCSF event rows
           the sweep cites, and it
           reads the OCSF entity fields (actor.user.name, user.name,
           device.hostname, src_endpoint.hostname, dst_endpoint.hostname,
           src_endpoint.ip, dst_endpoint.ip, device.ip, file.hashes.sha256,
           process.file.hashes.sha256, process.name, actor.process.name,
           file.path, file.name, http_request.url.url_string,
           query.hostname). Neither a risk aggregate nor a signal's
           risk_entity is among them. A lead evidenced from signal rows
           alone therefore fails corroboration
           and is discarded with nothing surfaced to anyone.

           So: hop one, resolve the score into the signals that produced it
           and confirm the breadth is real rather than one rule renamed. Hop
           two, read the raw telemetry those signals matched on (their
           matched_log_id), and cite THOSE rows. The top_risk_entity_events
           pivot already returns the matched OCSF events for the ten
           multi-rule entities with the most risk in the last 24h (events from that
           same last day only). Confirm the behavior independently while there — a
           score is several rules' opinion, and this hunt is worth running
           only if it can tell the difference between an entity that behaved
           badly and an entity that rules agree about."

/note: entity_type does not mean the same thing on both sides
  note:   "A translation step that silently discards leads if skipped. A
           signal's risk_entity is a bare value with no type column; its type
           comes from the OCSF field the matched event carries it in. Leads
           accept exactly nine: ip, user, host, domain, hash, process, url,
           email, file.

           A host name (device.hostname, src_endpoint.hostname,
           dst_endpoint.hostname) must be emitted as `host`.

           A cloud account (cloud.account.uid) has NO valid lead type at all. A risky cloud
           account cannot be emitted as itself — it must be re-anchored onto
           an entity that does exist in the telemetry, typically the user or
           source ip that acted under that account. If no such entity can be
           found in the underlying rows, the finding cannot become a lead
           here; say so in the narrative rather than forcing a type that will
           be thrown away."

## Emit

/lead: entities whose risk is broad, recent and new rather than merely large
  entity: host
  note:   "Entity type must be one of the nine, and must match the OCSF field
           the corroborating rows came from — see the translation note above.

           Evidence carries the breadth (which distinct rules, which distinct
           tactics), the slope (last 24h against the week), the
           novelty facts with the cleared-entity caveat stated honestly, and
           the raw telemetry rows that corroborate the entity. Lead with the
           shape, not the number: 'four rules across three tactics in eleven
           hours, on a host with no prior risk history' is the finding, and
           'risk score 340' is a detail that means nothing without the
           estate's distribution next to it.

           Give the reader the dismissal. If this is a jump host or a scanner
           and the breadth is explained by its job, that belongs in the lead
           rather than in the reader's head — a sweep that makes its own
           weakest case is one whose strong cases get believed."

## A note on this playbook's metadata

/note: why the frontmatter looks the way it does
  note:   "category: identity is a PLACEHOLDER, as in hunts/nano_detections.md.
           This playbook's surface is the risk engine, and the schema offers
           only the six telemetry-domain categories. `identity` is what an
           unrecognised category resolves to anyway, so the stored result is
           the same either way. Do NOT substitute an invented category such
           as platform or soc-ops — only the six documented values are
           accepted, and a playbook carrying anything else will not sync.

           mitre_tactic and mitre_technique are deliberately ABSENT — this
           hunt ranks ON tactic breadth and therefore spans every tactic its
           underlying rules cover. Stamping it with one would corrupt the
           coverage analytics that read those fields.

           lookback_window is 7d because every pivot binds the sweep window:
           the week is the slope horizon and its last 24h are split off
           inside each query.

           Risk scores are owned by the risk engine. Nothing here sets, adjusts
           or clears a score — a hunt structurally cannot, and this one has no
           business trying."
