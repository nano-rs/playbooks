---
kind: hunt
title: "Service processes running commands that read like a person typed them"
subtitle: "sqlservr, w3wp and friends spawning interactive-looking work — judged on command semantics, not lineage rarity"
category: endpoint
owner: "team · soc-leads"
authored: 2026-08-03
schedule: "0 6 * * *"
timezone: "UTC"
lookback_window: 24h
telemetry:
  all_of:
    - endpoint.process
mitre_tactic: persistence
mitre_technique: T1505.003
hypothesis: "When a database engine, web worker or app server spawns a shell, the lineage alone convicts nobody: many applications shell out by design. The discriminator is the command content. Machine-generated children are repetitive and parameterized (few distinct command lines, recurring for months); a webshell or xp_cmdshell session explores (whoami, hostname, net user, dir sweeps, ping -n 1 canaries, base64 blobs, output redirected into the webroot) and varies between consecutive commands. The benign twin is a scheduled DBA or monitoring job that is odd-looking but identical across runs."
risk_weight: 7
default_severity: high
pivots:
  - name: service_parent_census
    role: coverage
    query: 'class_uid=1007 activity_id=1 process.parent_process.name IN ("sqlservr.exe","w3wp.exe","tomcat.exe","tomcat8.exe","tomcat9.exe","java.exe","javaw.exe","httpd.exe","nginx.exe","php-cgi.exe","php.exe","node.exe","umworkerprocess.exe","msexchangemailboxreplication.exe","httpd","nginx","apache2","php-fpm","java","node") | stats count, dc(device.hostname) AS hosts, dc(process.name) AS child_binaries by process.parent_process.name'
  - name: service_shell_children
    role: discovery
    query: 'class_uid=1007 activity_id=1 process.parent_process.name IN ("sqlservr.exe","w3wp.exe","tomcat.exe","tomcat8.exe","tomcat9.exe","java.exe","javaw.exe","httpd.exe","nginx.exe","php-cgi.exe","php.exe","node.exe","umworkerprocess.exe","msexchangemailboxreplication.exe","httpd","nginx","apache2","php-fpm","java","node") process.name IN ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","certutil.exe","bitsadmin.exe","rundll32.exe","regsvr32.exe","whoami.exe","net.exe","net1.exe","ipconfig.exe","systeminfo.exe","hostname.exe","tasklist.exe","nltest.exe","quser.exe","ping.exe","sh","bash","dash","zsh","python","python3","perl","curl","wget","id","uname") | stats count, dc(process.cmd_line) AS distinct_cmds, dc(process.name) AS distinct_binaries, values(process.cmd_line) AS cmd_lines, earliest(timestamp) AS first_seen, latest(timestamp) AS last_seen by device.hostname, actor.user.name, process.parent_process.name | sort -distinct_cmds | head 200'
    scorer:
      method: iqr
      field: distinct_cmds
      threshold: 1.5
  - name: service_exploratory_commands
    role: discovery
    query: 'class_uid=1007 activity_id=1 process.parent_process.name IN ("sqlservr.exe","w3wp.exe","tomcat.exe","tomcat8.exe","tomcat9.exe","java.exe","javaw.exe","httpd.exe","nginx.exe","php-cgi.exe","php.exe","node.exe","umworkerprocess.exe","msexchangemailboxreplication.exe","httpd","nginx","apache2","php-fpm","java","node") (process.name IN ("whoami.exe","net.exe","net1.exe","ipconfig.exe","systeminfo.exe","hostname.exe","tasklist.exe","nltest.exe","quser.exe","id","uname") OR process.cmd_line=*whoami* OR process.cmd_line="*net user*" OR process.cmd_line="*net group*" OR process.cmd_line=*ipconfig* OR process.cmd_line=*systeminfo* OR process.cmd_line="*ping -n 1*" OR process.cmd_line=*-enc* OR process.cmd_line=*frombase64string* OR process.cmd_line=*certutil* OR process.cmd_line=*inetpub* OR process.cmd_line=*/etc/passwd* OR process.cmd_line="*uname -a*") | stats count, dc(process.cmd_line) AS distinct_cmds, values(process.cmd_line) AS cmd_lines, earliest(timestamp) AS first_seen, latest(timestamp) AS last_seen by device.hostname, actor.user.name, process.parent_process.name, process.name | sort -distinct_cmds, first_seen | head 200'
budget:
  max_turns: 40
  max_tool_calls: 120
  max_rows: 5000
  max_wall_seconds: 900
tags:
  - endpoint
  - webshell
  - services
  - execution
---
# Service processes running commands that read like a person typed them

**Hypothesis:** when a database engine or a web worker spawns a shell, the lineage alone convicts nobody — plenty of applications shell out by design, and a rarity-based hunt drowns in them. The discriminator is *what the command says*. Machine-generated commands are repetitive, parameterized, and identical for months; a webshell or an xp_cmdshell session produces commands that explore — discovery verbs, varied shapes, output redirected to readable places, even typos. This hunt judges semantics, not rarity.

That deliberate choice is the whole design: `lolbin_unusual_parent` would miss a webshell under a w3wp that legitimately shells out every day, because the pair is baselined as normal. Reading the command content is how that gap gets covered.

## Collect the population

/query: children of service processes — shells, script hosts, and living-off-the-land binaries
  window: 24h
  from:   edr_telemetry
  note:   "Parents that matter: sqlservr, w3wp, tomcat/java app servers,
           httpd/nginx workers, php-fpm, node, exchange worker processes.
           Take ALL their cmd/powershell/script-host children — do not
           pre-filter on rarity, that is precisely the mistake this hunt
           exists to avoid. The `service_shell_children` pivot collects them
           per host, account and service parent, with the distinct command
           count (an IQR outlier on that count is flagged) and the command
           lines verbatim."

## Judge the words, not the edge

/query: classify each command's semantics — generated or exploratory
  note:   "Machine texture: same executable, same argument shape, fixed
           paths, no discovery verbs, recurring on a schedule. Human texture:
           whoami, hostname, net user, dir/type/copy wandering across
           directories, ping -n 1 canaries, output appended to files under
           the webroot, base64 blobs, and variation between consecutive
           commands. One interactive-looking command is interesting; a
           conversation of them under one worker process is the finding.
           The `service_exploratory_commands` pivot lists the children whose
           binary or command line carries a discovery verb or encoding
           marker. A verb run by a grandchild (cmd.exe under w3wp running
           whoami) shows under cmd.exe, not w3wp: follow the cmd.exe rows
           down by hand."

/baseline: each service process's own command history
  window: 30d
  note:   "The strongest version of the semantic judgment is a diff: this
           w3wp has emitted the same three maintenance commands for a year,
           and today it asked who it was. Per-parent history also absorbs
           the estates where an app legitimately runs odd-looking commands —
           odd-but-stable is machine, odd-and-novel is hands."

## Walk the chain both ways

/pivot: for web workers, the requests that preceded each spawn
  note:   "A webshell's spawns correlate tightly with requests to one
           specific resource — often recently written, oddly named, or in an
           upload path. Finding that resource converts the lead from 'shell
           activity' to 'here is the implant', and its first-write time
           dates the compromise. If web logs are not available for the
           join, say so in the narrative."

/query: what the spawned commands went on to touch
  note:   "Follow the session forward: files written (especially into
           web-served paths), credentials touched, outbound connections,
           lateral edges. An exploratory burst that graduates to persistence
           or movement should be assembled into one timeline here, not left
           for the reader to reconstruct."

## Rule out the boring explanation

/enrichment: is there a scheduled job or application feature that explains the shape
  note:   "DBA maintenance jobs run through xp_cmdshell in more estates than
           anyone admits, and some monitoring tools poke systems in ways
           that look exploratory. Both are periodic and identical across
           runs — the per-parent baseline should have absorbed them, so a
           survivor of that filter with a genuine interactive texture has
           earned the lead."

## Emit

/lead: interactive-textured commands under a service process
  entity: host
  note:   "Quote the command sequence verbatim and in order — the
           conversational texture is the evidence, and a summary flattens
           it. Carry the parent's command history baseline, the correlated
           requests where found, and the downstream timeline. Name the
           implant file if the pivot found one; that single fact halves the
           reader's time-to-action."
