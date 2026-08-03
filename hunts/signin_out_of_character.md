---
kind: hunt
title: "Sign-ins that do not fit the account's owner"
subtitle: "New geographies, impossible travel, MFA oddities and session shapes judged against each account's own history"
category: identity
owner: "team · soc-leads"
authored: 2026-08-03
schedule: "0 1 * * *"
timezone: "UTC"
lookback_window: 24h
telemetry:
  all_of:
    - identity.authentication
  optional:
    - identity.mfa
mitre_tactic: initial-access
mitre_technique: T1078.004
budget:
  max_turns: 40
  max_tool_calls: 120
  max_rows: 6000
  max_wall_seconds: 900
tags:
  - identity
  - authentication
  - account-takeover
---
# Sign-ins that do not fit the account's owner

**Hypothesis:** a stolen credential is used by someone with the right password and the wrong everything else — geography, device, network, hours, MFA behaviour. Any one of those deviations is daily noise in a mobile workforce; two or three of them stacked on the same sign-in is not.

The comparison that matters is against the account's *own* history, never against the estate. An engineer who has signed in from two ASNs for a year and suddenly appears on a third, on a new device, with an MFA method registered an hour earlier, is a lead — even though every element of that sentence is unremarkable estate-wide.

## Build the owner's silhouette

/baseline: per-account sign-in profile — geos, ASNs, devices, hours, MFA methods
  window: 30d
  note:   "The profile is the hunt. Most accounts are startlingly boring: one
           country, two devices, office hours. That boringness is what makes a
           deviation legible, and accounts with genuinely chaotic histories
           (executives who travel, field staff) should be scored against their
           own chaos, not held to the office worker's baseline."

## Look for the stacked deviation

/query: sign-ins deviating from the owner's profile
  window: 24h
  from:   entra_signin
  note:   "Weight compound deviations, not single signals. New geo alone is a
           holiday; new geo + new device + first-seen ASN on the same sign-in
           is the shape worth an analyst's morning. Legacy-protocol fallback
           alongside modern-auth success on the same account is another
           stack worth surfacing — attackers probe the weak door too."

/query: geographically impossible sign-in pairs
  note:   "Compute travel speed between consecutive sign-ins per account.
           Discard pairs where either leg is a known corporate VPN or cloud
           egress range — impossible travel through a proxy is the single
           biggest source of dismissed leads this hunt can produce, and every
           dismissal trains the reader to skip the real one."

/query: MFA anomalies around otherwise-successful sign-ins
  note:   "Three shapes: a burst of denied prompts followed by an approval
           (fatigue), a new method registered shortly before or after a
           deviating sign-in (the intruder making the takeover durable), and
           method downgrades. The registration event is the strongest of the
           three — its timing relative to the odd sign-in belongs in evidence."

## Rule out the boring explanation

/enrichment: is the source network a VPN, cloud egress, or known travel pattern
  note:   "Corporate VPN gateway changes make whole departments 'move country'
           overnight. Check whether the new geo is new for MANY accounts at
           once — a fleet-wide shift is an IT change, one account shifting
           alone is the lead."

/pivot: what the session did after the deviating sign-in
  note:   "An owner signs in and does their job; an intruder inventories it.
           Mailbox rule creation, consent grants, or a burst of file access
           right after a deviating sign-in turns a maybe into a lead. A
           deviating sign-in followed by nothing may just be a dropped VPN."

## Emit

/lead: sign-in inconsistent with the account owner's established pattern
  entity: user
  note:   "Carry the account's baseline alongside the deviation — a lead that
           says 'new country' without showing the owner's normal countries
           makes the analyst rebuild the profile by hand. State which benign
           explanations were checked (VPN shift, fleet-wide change, travel
           cadence) and why they did not hold."
