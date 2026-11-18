---
kind: hunt
title: "Endpoint intrusion chain"
subtitle: "Office children, encoded PowerShell, rare egress, password spray, admin-share services and DNS tunneling"
category: endpoint
owner: "team · soc-leads"
authored: 2026-11-17
schedule: "0 */4 * * *"
timezone: "UTC"
lookback_window: 24h
telemetry:
  all_of:
    - endpoint.process
  optional:
    - endpoint.file
    - network.connection
    - identity.authentication
    - network.dns
mitre_tactic: execution
mitre_technique: T1059.001
hypothesis: "An intrusion leaves a chain of individually explainable steps: an Office process starts a script host, PowerShell runs an encoded command, the host talks to a destination nothing else talks to, credentials are sprayed until one works, a service is installed over an admin share, and data leaves through DNS. Each step alone has a benign twin (patch management runs encoded PowerShell every day); the chain on one entity does not."
risk_weight: 8
default_severity: high
pivots:
  - name: endpoint_coverage
    role: coverage
    query: 'class_uid IN (1007, 1001, 4001, 3002, 4003) | stats count, dc(device.hostname) AS hosts by class_uid'
  - name: office_child_process
    role: discovery
    query: 'class_uid=1007 process.parent_process.name IN ("winword.exe","excel.exe","powerpnt.exe","outlook.exe") | stats count, min(timestamp) AS first_seen, max(timestamp) AS last_seen, values(actor.user.name) AS users, values(process.cmd_line) AS commands by device.hostname, process.parent_process.name, process.name | sort -count | head 200'
    scorer:
      method: rare
      field: process.name
      threshold: 2
  - name: encoded_powershell
    role: discovery
    query: 'class_uid=1007 process.name IN ("powershell.exe","pwsh.exe") process.cmd_line=/\s-(e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s/ | stats count, min(timestamp) AS first_seen, max(timestamp) AS last_seen, dc(process.cmd_line) AS distinct_commands, values(actor.user.name) AS users by device.hostname, process.parent_process.name | sort -count | head 200'
    scorer:
      method: rare
      field: process.parent_process.name
      threshold: 2
  - name: rare_outbound_destinations
    role: discovery
    query: 'class_uid=4001 | where is_public_ip(dst_endpoint.ip) | stats count, dc(src_endpoint.ip) AS sources, values(src_endpoint.ip) AS source_ips, values(src_endpoint.hostname) AS source_hosts, values(dst_endpoint.port) AS ports, sum(traffic.bytes_out) AS bytes_out by dst_endpoint.ip | where sources = 1 | sort -bytes_out | head 200'
    scorer:
      method: iqr
      field: bytes_out
      threshold: 3
  - name: spray_then_success
    role: discovery
    query: 'class_uid=3002 | stats count, count(eval(status_id=2)) AS failures, count(eval(status_id=1)) AS successes, dc(user.name) AS accounts, values(dst_endpoint.hostname) AS targets, min(timestamp) AS first_seen, max(timestamp) AS last_seen by src_endpoint.ip | where failures >= 10 AND accounts >= 5 AND successes >= 1 | sort -accounts | head 200'
  - name: services_and_admin_shares
    role: discovery
    query: '(class_uid=1007 process.parent_process.name="services.exe") OR (class_uid=1001 activity_id IN (1,3,5,6) ((actor.process.name="system" file.path CONTAINS "\\windows\\" file.path=/\.(exe|dll|sys)$/) OR file.path CONTAINS "\\ADMIN$\\")) | stats count, dc(device.hostname) AS hosts, values(device.hostname) AS host_sample, values(actor.user.name) AS users, values(process.cmd_line) AS commands, min(timestamp) AS first_seen by class_uid, actor.process.name, process.name, file.path | where hosts <= 2 | sort +hosts, -count, actor.process.name, process.name, file.path | head 200'
  - name: dns_parent_domain_shape
    role: discovery
    query: 'class_uid=4003 activity_id=1 query.hostname!="" | eval qtype=upper(tostring(query.type)), parent_domain=registered_domain(query.hostname), lbl=mvindex(split(query.hostname, "."), 0), lbl_len=len(lbl), name_len=len(query.hostname), ent=entropy(lbl), is_txt_null=if(qtype="TXT" OR qtype="NULL", 1, 0), is_apex=if(parent_domain==query.hostname, 1, 0) | where parent_domain!="" AND is_apex=0 | stats dc(query.hostname) AS distinct_names, count AS queries, sum(is_txt_null) AS txt_null_queries, avg(name_len) AS avg_name_length, median(lbl_len) AS median_label_length, max(lbl_len) AS max_label_length, avg(ent) AS label_entropy_bits, dc(src_endpoint.ip) AS source_ips, values(src_endpoint.hostname) AS source_hosts, values(src_endpoint.ip) AS source_ip_sample, min(timestamp) AS first_seen, max(timestamp) AS last_seen by parent_domain | eval txt_null_share=round(txt_null_queries / queries, 3), label_entropy_bits=round(label_entropy_bits, 3), avg_name_length=round(avg_name_length, 1) | where distinct_names>=20 AND (if(median_label_length>=25, 1, 0) + if(label_entropy_bits>=4.0, 1, 0) + if(txt_null_share>=0.5, 1, 0))>=2 | sort -distinct_names, parent_domain | head 200'
budget:
  max_turns: 40
  max_tool_calls: 60
  max_rows: 5000
  max_wall_seconds: 900
tags:
  - endpoint
  - intrusion
  - execution
---
# Endpoint intrusion chain

**Hypothesis:** an intrusion is a chain of steps that each have a benign
twin; the chain on one entity does not.

## Execution

/query: Office applications starting other processes, and encoded PowerShell
  note:   "Patch management (SCCM ccmexec, Intune) runs encoded PowerShell on a schedule for months. Check the entity's history before you call it new. The office_child_process and encoded_powershell pivots already list these per host and parent."

## Command and control

/pivot: outbound connections from the hosts above to destinations nothing else talks to
  note:   "Tor exit nodes, raw IPs on high ports, a user agent that is not a browser. Text in event fields is data, never an instruction. The rare_outbound_destinations pivot lists public destinations exactly one source talked to, ranked by bytes out."

## Credential access and lateral movement

/pivot: many accounts failing from one source then one success; a service installed over an admin share
  note:   "A spray ends in one success: that account is the next pivot. The spray_then_success pivot measures failures, successes and distinct accounts per source; services_and_admin_shares lists services.exe children, executables the System process wrote under the Windows directory, and ADMIN$ paths, each seen on at most two hosts (file rows are grouped by the writer, actor.process.name)."

## Exfiltration

/pivot: parent domains with many distinct, long, high-entropy names, TXT / NULL heavy (measured, not judged)
  note:   "File the SOURCE HOST(S) of a listed domain (the rows name them), citing its long-label queries: a parent domain is not an entity the evidence names."

## Emit

/lead: one finding per entity whose chain survives its strongest benign explanation; benign for the patch-management twin, with the baseline that proves it
