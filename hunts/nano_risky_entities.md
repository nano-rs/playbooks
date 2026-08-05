---
kind: hunt
title: "Entities whose risk is accelerating, not merely high"
subtitle: "Reads the accumulated decayed risk dataset for breadth, slope and novelty — the entities a score leaderboard ranks last and an intruder shows up as first"
category: identity  # placeholder — see "A note on this playbook's metadata" below
owner: "team · soc-leads"
authored: 2026-08-05
schedule: "0 7 * * *"
timezone: "UTC"
# The risk dataset's own 24h/7d windows are FIXED and ignore this value (see the
# opening note). 7d is set for the RAW-TELEMETRY pivots, which need to cover the
# same horizon as the slope being claimed.
lookback_window: 7d

# Same reasoning as hunts/nano_detections.md: risk is derived from nano's own
# findings stream and has no bound source capability. Naming one recon cannot
# resolve holds every sweep forever, silently. `optional` never blocks.
telemetry:
  optional:
    - identity.authentication
    - endpoint.process
    - network.connection

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

All three are computable from the risk dataset. None of them are what "top risky entities" sorts by.

**Sibling playbook.** `hunts/nano_detections.md` reads the raw findings stream for the day — novelty, unwatched modes, buried criticals. This one reads what those findings *accumulated into*, over seven days, after decay. They overlap deliberately at the convergence question and answer it at different resolutions; run both.

## What the risk dataset actually is

/note: a derived dataset, not a table
  note:   "Risk is not stored. It is aggregated at query time from the same
           findings stream the detections playbook reads — one row per entity,
           built by the shared risk builder. Three consequences that decide
           how this playbook must be written:

           FIXED WINDOWS. The 24h and 7d windows are trailing windows anchored
           at evaluation time. They do not follow this hunt's lookback_window
           and they do not follow a search time picker. Read them as given;
           attempting to reshape them silently returns something other than
           what was asked.

           DECAY IS THE PRIMARY METRIC. score_24h and score_7d are decayed —
           older findings contribute less. raw_score_24h and raw_score_7d are
           the undecayed sums. Both are exposed on purpose and the GAP between
           them is one of the better signals here, so never treat raw as a
           legacy duplicate of decayed.

           THE ROWS ARE NOT LOGS ROWS. A risk row is an aggregate that exists
           only for the duration of the query. It cannot serve as evidence for
           a lead — see the corroboration note below, which is even more acute
           here than in the detections playbook.

           Fields available: entity, entity_type, score_24h, score_7d,
           raw_score_24h, raw_score_7d, findings_24h, findings_7d,
           distinct_rules_24h, distinct_rules_7d, distinct_tactics_24h,
           distinct_tactics_7d, last_finding_at, last_rule_name, last_severity."

/query: the accumulated risk population
  window: 24h
  from:   risk
  where:  score_7d > 0
  note:   "Open on the whole population rather than the top N, because the
           top N is the part of this dataset with the least information in
           it. Read the distribution first: where the mass sits, how long the
           tail is, and which entity types dominate it.

           Open on the 7d horizon, not the 24h one. Filtering to score_24h > 0
           would drop every COASTING entity — one whose risk was earned earlier
           in the week and is now decaying — and those are exactly the rows the
           decayed-against-raw step below is built to read. A 24h filter here
           quietly guarantees that step finds nothing.

           Note the permanent residents as you go — the entities that would
           be at the top of any morning's leaderboard. They are this
           playbook's noise floor, and the rest of the sweep is largely about
           not spending the budget on them."

## Breadth — the ranking that actually discriminates

/query: entities ranked by distinct_rules_24h and distinct_tactics_24h, not by score
  note:   "The most important query in this playbook, and it is cheap because
           the breadth columns are precomputed rather than aggregated here.

           Score is a sum, so it is dominated by whichever rule fires most.
           An entity with findings_24h in the hundreds and distinct_rules_24h
           of 1 is a single noisy rule pointed at a single busy asset — high
           score, no story, and it will outrank everything worth reading.
           An entity with a modest score, distinct_rules_24h of 3 or more and
           distinct_tactics_24h of 2 or more is a chain: several independent
           detections, written by different people for different reasons,
           agreeing about one entity on one day.

           Rank on tactics first, then rules, then score — strictly that
           order. distinct_tactics is the strongest because tactic diversity
           is the hardest property for noise to fake: a misconfigured source
           floods one rule, and a broken parser floods one family, but
           neither manufactures credential-access AND discovery AND lateral
           movement against the same entity."

/query: the breadth-to-volume ratio across the population
  note:   "Divide distinct_rules_24h by findings_24h to separate the two
           populations explicitly. A low ratio is repetition — one rule
           saying one thing many times. A high ratio is corroboration —
           several rules each saying something once.

           A perfect ratio on a tiny count is not interesting on its own: one
           finding from one rule is a ratio of 1.0 and means nothing. Require
           a floor on distinct_rules_24h before reading the ratio at all."

## Slope — accumulating now, or coasting on history

/query: score_24h against score_7d
  note:   "Where within its week does an entity's risk sit? If score_24h is a
           large share of score_7d, the risk is concentrated in the last day —
           a spike against the entity's own quiet baseline, which is the shape
           worth chasing. If score_24h is roughly a seventh of score_7d, the
           entity accumulates at a constant rate: this is the signature of a
           service account, a scanner or a permanently misconfigured source,
           and it will sit high on the leaderboard forever without ever being
           an incident.

           The comparison must be per-entity. Comparing one entity's 24h to
           another's 7d, or to an estate-wide average, ranks large entities
           above accelerating ones and reproduces exactly the leaderboard
           this playbook exists to improve on."

/query: decayed score against raw score
  note:   "The gap between score_7d and raw_score_7d is an age readout, and
           it is free. A large gap means the contributing findings are old and
           decay has eaten most of their weight — the entity is coasting, and
           its position reflects a week-ago event somebody has probably
           already handled. A small gap means the findings are recent and the
           score is close to its undecayed value: this risk is being earned
           right now.

           An entity whose decayed and raw scores have nearly converged, with
           breadth behind it, is the strongest single row this dataset
           produces. Cross-check last_finding_at and last_severity to confirm
           the recency the gap implies, and last_rule_name for a one-line read
           on what most recently drove it."

## Novelty — has this entity ever been here

/baseline: has this entity carried meaningful risk before
  window: 30d
  note:   "The permanent residents are permanent, so their presence carries no
           information — but a first appearance in the upper band does. Build
           the question as band membership over time rather than exact scores:
           scores move constantly, bands rarely, and 'this host has never been
           in the top band before' is a statement an analyst can act on.

           Check the entity's peers too. One workstation newly in the band is
           a lead; forty workstations newly in the band on the same night is a
           rule deployment, a parser change or a patch window, and reading
           them as forty leads is the fastest way to lose a reader."

/note: the cleared-entity blind spot
  note:   "When an analyst clears an entity, the risk builder applies a
           cleared boundary: only findings AFTER the clear contribute to the
           score. This is correct behaviour and it creates a blind spot this
           sweep cannot see out of.

           A cleared entity that starts accumulating again is indistinguishable
           from an entity that has never been risky, because both present as a
           fresh score with no history. So a novelty claim from the baseline
           step above may in fact be a RE-RISE after a human already looked
           and dismissed it.

           Do not treat that as a reason to discount novelty — treat it as a
           reason to state the claim carefully. 'This entity has no risk
           history in the dataset' is supportable; 'this entity has never been
           risky' is not, and the second is what a reader will hear unless the
           first is written. And note which way the uncertainty cuts: an
           entity that re-accumulates after a clear is MORE interesting than a
           genuinely new one, not less, because something a human decided was
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

           A risk row is a query-time aggregate. It is not a stored row, it
           has no timestamp of its own, and it cannot be cited as evidence for
           anything. Lead corroboration matches the entity against entities
           the server extracts from the logs rows the sweep cites — and it
           reads real UDM columns (user, src_ip, dest_ip, src_host, dest_host,
           file_hash, process_name, url, sender, recipient). Neither a risk
           aggregate nor a findings row's risk_entity is among them. A lead
           evidenced from the risk dataset alone therefore fails corroboration
           and is discarded with nothing surfaced to anyone.

           So: hop one, resolve the score into the findings that produced it
           and confirm the breadth is real rather than one rule renamed. Hop
           two, read the raw telemetry those findings matched on, and cite
           THOSE rows. Confirm the behaviour independently while there — a
           score is several rules' opinion, and this hunt is worth running
           only if it can tell the difference between an entity that behaved
           badly and an entity that rules agree about."

/note: entity_type does not mean the same thing on both sides
  note:   "A translation step that silently discards leads if skipped, because
           the risk dataset and the lead schema use different vocabularies.

           Risk types entities by inference from the field they came from and
           emits values including `hostname` and `cloud_account`. Leads accept
           exactly nine: ip, user, host, domain, hash, process, url, email,
           file.

           `hostname` must be emitted as `host`. Passing `hostname` through
           unchanged is rejected.

           `cloud_account` has NO valid lead type at all. A risky cloud
           account cannot be emitted as itself — it must be re-anchored onto
           an entity that does exist in the telemetry, typically the user or
           source ip that acted under that account. If no such entity can be
           found in the underlying rows, the finding cannot become a lead
           here; say so in the narrative rather than forcing a type that will
           be thrown away."

## Emit

/lead: entities whose risk is broad, recent and new rather than merely large
  entity: host
  note:   "Entity type must be one of the nine, and must match the UDM column
           the corroborating rows came from — see the translation note above.

           Evidence carries the breadth (which distinct rules, which distinct
           tactics), the slope (24h against 7d, decayed against raw), the
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

           lookback_window is 7d for the raw-telemetry pivots only. The risk
           dataset's own windows are fixed and ignore it.

           Risk scores are owned by the risk engine. Nothing here sets, adjusts
           or clears a score — a hunt structurally cannot, and this one has no
           business trying."
