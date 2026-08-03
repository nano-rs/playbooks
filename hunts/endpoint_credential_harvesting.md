---
kind: hunt
title: "Credential harvesting by things that are not credential utilities"
subtitle: "Hive exports, browser credstore reads, password hunting and shadow-copy pulls — every hit carried with its chain, both directions"
category: endpoint
owner: "team · soc-leads"
authored: 2026-08-03
schedule: "0 8 * * *"
timezone: "UTC"
lookback_window: 24h
telemetry:
  all_of:
    - endpoint.process
    - endpoint.file
mitre_tactic: credential-access
mitre_technique: T1003
budget:
  max_turns: 40
  max_tool_calls: 120
  max_rows: 5000
  max_wall_seconds: 900
tags:
  - endpoint
  - credential-access
---
# Credential harvesting by things that are not credential utilities

**Hypothesis:** credential material on an endpoint is touched constantly — by the OS, by backup agents, by security tools — and almost never by anything else. So the hunt is not "who touched the SAM" but "what touched it that is not on the short list of things whose *job* it is." And because a credential-access event with no context is untriageable, this hunt has one non-negotiable rule: no lead ships without its chain — what came before the touch, and where the material went after.

## The touches

/query: registry hive exports and raids on the domain database
  window: 24h
  from:   edr_telemetry
  note:   "reg save on SAM/SYSTEM/SECURITY, esentutl or raw copies against
           ntds.dit, dsdbutil snapshots. On domain controllers add the
           remote flavour: replication-request patterns from machines that
           are not domain controllers — the DCSync shape — which touch no
           file at all."

/query: shadow-copy creation followed by file pulls from inside it
  note:   "The locked-file workaround: mount or create a shadow, then copy
           SAM or ntds.dit out through the snapshot path. The two-step is
           the signature — a shadow created and read within minutes by the
           same session, with credential paths in the reads. Backup agents
           do this all day; they are the carve, and only by identity."

/query: browser credential stores read by non-browser processes
  note:   "Login Data, Cookies, Local State, key4.db opened by anything
           that is not the browser itself or a known backup process.
           Browser credstores are the highest-yield, lowest-privilege
           target on any workstation — no admin required — and stealer
           malware goes here FIRST. Cookie-store reads deserve equal rank:
           session theft outlives a password reset."

/query: password hunting in files and code
  note:   "findstr /si password, recursive greps for 'pwd=', dir sweeps for
           *.kdbx, unattend.xml, web.config, id_rsa. This is keyboard work,
           not tooling — it overlaps the command-line hunt's discovery
           texture, and a host appearing in both is one story."

## The carve, verified

/baseline: which process identities legitimately touch credential material here
  window: 30d
  note:   "Security agents, backup software, the browser itself. Build the
           list from observed history, carve by SIGNER AND PATH, never by
           process name — masquerading as the AV binary is a stealer's
           oldest trick, and a name-based carve is a standing invitation.
           A 'legitimate' toucher running from a user profile path fails
           the carve by definition."

## The mandatory chain

/pivot: chain-back — how the touching process came to exist
  note:   "Walk to the origin: dropped by a browser? Spawned under a service
           process? Arrived over an admin share? The chain-back usually
           lands in ground another hunt owns — drive-by, mail-to-endpoint,
           lateral movement — and the lead should name the connection.
           A credential touch with an unexplained origin is MORE alarming,
           not less; say the origin could not be established."

/pivot: chain-forward — where the material went
  note:   "Staging writes (archives, renamed copies in temp), outbound
           connections in the minutes after, or immediate authentication
           events using the harvested identities. Forward chain is what
           separates 'attempted' from 'accomplished', and it sets the
           blast radius the reader must contain — new logons with a dumped
           account are the difference between rotating one host's secrets
           and rotating a domain's."

## Emit

/lead: credential material touched outside the carve, with chain attached
  entity: host
  note:   "Both chains are the price of admission — a lead reading 'LSASS
           accessed' with no origin and no aftermath cannot be triaged
           without redoing the sweep, and the analyst who has to redo it
           will dismiss it. Name the accounts whose material was exposed;
           that list is the reader's rotation scope, and producing it here
           is cheaper than producing it during the incident."
