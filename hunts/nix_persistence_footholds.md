---
kind: hunt
title: "Footholds on the machines that never reboot"
subtitle: "authorized_keys additions, new cron and systemd units, fresh SUID binaries and shell-profile edits on Linux — with the macOS launchd sibling where Mac telemetry exists"
category: endpoint
owner: "team · soc-leads"
authored: 2026-08-03
schedule: "30 4 * * *"
timezone: "UTC"
lookback_window: 24h
telemetry:
  all_of:
    - endpoint.persistence
  optional:
    - endpoint.process
    - endpoint.file
mitre_tactic: persistence
mitre_technique: T1098.004
budget:
  max_turns: 40
  max_tool_calls: 120
  max_rows: 6000
  max_wall_seconds: 900
tags:
  - endpoint
  - linux
  - macos
  - persistence
---
# Footholds on the machines that never reboot

**Hypothesis:** Linux servers are where the estate's crown jewels actually run, and where its endpoint hunting usually is not. Persistence there is spare and old-fashioned — an SSH key appended, a cron line, a systemd unit, a SUID bit — and each mechanism has a small, slow-moving legitimate population. The Windows autoruns hunt gets a census and a diff; this is the same discipline for the fleet that never reboots and rarely gets looked at.

## Keys that let someone back in

/query: writes to authorized_keys files and new key material
  window: 24h
  from:   linux_auditd
  note:   "Rank by the writer and the owner: a key appended to root's or a
           service account's authorized_keys by anything other than the
           configuration-management pipeline is the sharpest single event
           this hunt has. A key written by the WEB SERVER'S user is a
           webshell graduating to real access — join it to the
           service-spawned-shells hunt on the spot. Keep the key
           fingerprint: the same public key appearing on multiple hosts
           draws the intruder's map for you."

## Scheduled resurrection

/query: new cron entries and systemd units, timers, and unit modifications
  note:   "Census-and-diff, exactly like the Windows ASEP hunt: the estate's
           unit and crontab population is repetitive, so a first-seen unit
           name or payload path is a short list. Read the payload — a unit
           ExecStart pointing into /tmp, /dev/shm or a user home, or a
           cron line that curls and pipes to a shell, convicts on content.
           Configuration management authorship is the boring explanation
           and it is carved by the WRITER, not by how routine the unit
           looks."

## Privilege left behind

/query: new SUID/SGID binaries and capability grants
  note:   "The persistence that doubles as escalation: a copied shell with
           the SUID bit, setcap cap_setuid on something innocuous. The
           legitimate SUID population is famous and finite per distro —
           first-seen paths against the fleet census, plus ANY SUID binary
           in a world-writable or home path, is the whole query."

/query: shell profile and rc-file edits on shared and privileged accounts
  note:   "Lines appended to .bashrc, .profile, /etc/profile.d — cheap,
           durable, and executed by every future session. Weight by
           account privilege and by writer; a profile edit landing minutes
           after a key addition on the same host is one story told twice."

## The macOS sibling

/query: first-seen LaunchAgents and LaunchDaemons where Mac telemetry exists
  note:   "Same census logic, launchd vocabulary: new plists in
           LaunchAgents/LaunchDaemons paths, unsigned or ad-hoc-signed
           payloads, program paths under /tmp or ~/Library scratch. This
           section runs only where the EDR covers Macs — if it does not,
           say so in the sweep narrative rather than letting Mac silence
           read as Mac health."

## Rule out the boring explanation

/baseline: what the configuration-management and package pipelines wrote this window
  note:   "Ansible, puppet, package post-install scripts and image bakes
           write keys, units and crontabs all day, from known identities,
           in deployment-shaped bursts across many hosts. One host, one
           artifact, interactive session, outside a change window — the
           same four-clause test as everywhere else in this library, and
           it fails the same way when the answer is a rollout."

/pivot: the session behind any surviving artifact
  note:   "Walk back: the SSH session or process tree that wrote it, where
           it authenticated from, and what else it touched. Forward: has
           the key been USED yet, has the unit FIRED yet. Planted-but-
           unused is still a lead — it is an intruder's insurance policy,
           and finding it before first use is the good timeline."

## Emit

/lead: persistence artifact outside the deployment pipeline's authorship
  entity: host
  note:   "Evidence carries the artifact verbatim (key fingerprint, unit
           file, cron line), the writing session and its origin, the
           fleet first-seen fact, and the used-yet answer. Cross-host
           recurrence of the same artifact belongs in one lead, not N —
           the map is the finding."
