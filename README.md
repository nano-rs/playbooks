# nano Playbooks

Official playbook library for [nano](https://nanos.sh) — Markdown + slash-command format that analysts can sync, fork, and customize.

## Usage

Add this repository in nano:

1. Navigate to **Settings → Playbook Repositories**
2. Click **Add Repository**
3. Enter:
   - **URL**: `https://github.com/nanos-sh/playbooks`
   - **Branch**: `main`
   - **Format**: `nano-playbook-md`
4. Click **Sync** to fetch playbooks
5. Browse and attach playbooks to cases as needed

## Repository Structure

```
├── identity/   # auth, sessions, credentials, IdP
├── endpoint/   # workstations, malware, EDR
├── cloud/      # AWS/GCP/Azure, IAM, workloads
├── data/       # DLP, S3, egress, large transfers (data exfil)
├── network/    # firewall, DNS, lateral movement
└── email/      # phish, BEC, OAuth app abuse
```

## Playbook Format

Each playbook is a single `.md` file with YAML frontmatter describing metadata and a body written as Markdown with `/slash-commands` for each investigative step. The parser turns that body into a step tree the nano agent can execute.

**Filename convention:** `{category}/{slug}.md` — e.g. `identity/credential_reuse.md`.

### Full example

```markdown
---
title: "Credential reuse — offboarded / dormant account"
subtitle: "Attacker using old credentials for a user who has since left or gone inactive"
category: identity
owner: "team · soc-leads"
authored: 2025-11-14
match_signals:
  - access_key.used
  - offboarded
  - dormant_account
  - iam.credential_reuse
danger_policy:
  "action:high": approval
  "action:medium": auto
  "action:low": auto
review_cadence: 90d
scope: tenant
tags:
  - identity
  - offboarding
  - iam
---
# Credential reuse · offboarded / dormant account

Agent-first identity investigation for the pattern "account that shouldn't be active is active."

## Phase 1 · establish state

/enrichment: HR system · is the user currently employed
  system: workday
  employee: {{entity.user}}
  fields: status, end_date, manager, team

/query: last 30d of auth events for this user
  window: 30d
  from:   auth-events
  where:  actor = {{entity.user}}
  group:  by day

/decision: is this a live user account?
  options:
    - yes · user is employed and active
    - no · user is offboarded
    - partial · employed but on leave / role changed
  note_required_on: no, partial

/action: rotate or disable the compromised credential
  kind:   iam.key_rotate
  target: {{entity.key_id}}
  danger: medium
  reversible: true
```

### Frontmatter fields

| Field | Purpose |
|-------|---------|
| `title` | Display title for the playbook |
| `subtitle` | One-line summary of when to use it |
| `category` | One of `identity`, `endpoint`, `cloud`, `data`, `network`, `email` |
| `owner` | Team or person responsible for maintaining the playbook |
| `authored` | ISO date the playbook was first published |
| `match_signals` | Signals / tags that auto-suggest this playbook on matching cases |
| `danger_policy` | Per-danger-level approval policy (`approval` requires human click; `auto` can self-execute) |
| `review_cadence` | How often the playbook should be revisited (default `90d`) |
| `scope` | `tenant` or `global` |
| `tags` | Free-form tags for search and filtering |

## Step kinds

Step kinds exposed by the slash syntax:

| Kind | Purpose |
|------|---------|
| `/query` | nano search query — agent runs on open, result inlines into the case |
| `/pivot` | Entity expansion (same primitive as PIVT) |
| `/enrichment` | Third-party lookup (WHOIS, VT, HR, IdP, etc.) |
| `/decision` | Human yes/no/other, with a required note on configurable options |
| `/action` | Mutates the case or external system (assign, escalate, containment) |
| `/review` | "Look at this" — human ticks when read |
| `/note` | Inline guidance / playbook author commentary (not executed) |

A step block looks like:

```
/query: find other failed logins from this IP
  window: 24h
  from:   auth-events
  where:  src_ip = {{entity.ip}} AND result = failure
```

The indented body is a YAML-ish param bag the renderer reads.

## Promoted playbooks

Several stock playbooks are marked as **promoted** in the nano UI — they surface first in the picker because they have high attach/complete rates across deployments. Current promoted set: `credential_reuse`, `login_spray`, `malware_detection`, `ransomware_precursor`, `exposed_credential`, `phish_reported`, `bec_wire_fraud`. Promotion is a runtime stat managed by nano — it is not carried in the playbook file itself.

## Contributing

1. Fork this repository
2. Add a playbook following the format above — put it in the category folder that best fits the investigation surface
3. Dry-run the playbook against real cases in your tenant before submitting
4. Submit a pull request

## License

MIT — see [LICENSE](LICENSE).
