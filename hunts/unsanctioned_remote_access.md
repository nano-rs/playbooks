---
kind: hunt
title: "Remote-access tooling nobody here sanctioned"
subtitle: "The full LOLRMM corpus swept by estate prevalence — the org runs one or two of these; every other one is a tripwire"
category: endpoint
owner: "team · soc-leads"
authored: 2026-08-03
schedule: "30 3 * * *"
timezone: "UTC"
lookback_window: 24h
telemetry:
  all_of:
    - endpoint.process
  optional:
    - network.connection
mitre_tactic: command-and-control
mitre_technique: T1219
budget:
  max_turns: 40
  max_tool_calls: 120
  max_rows: 6000
  max_wall_seconds: 900
tags:
  - endpoint
  - rmm
  - remote-access
  - tripwire
---
# Remote-access tooling nobody here sanctioned

**Hypothesis:** an intruder who installs a commercial RMM tool gets a signed, reputable, EDR-tolerated C2 channel with a vendor SLA — which is why it is now the single most common post-access move in real intrusions. But the defense is structural: any given org *sanctions* one or two remote-access products, so the rest of the corpus is zero-baseline by definition, and a first execution of any of them is a tripwire firing. Same logic as the LOLBAS hunt, pointed at a different toolbox.

The watchlist below is the complete LOLRMM project corpus — 311 tools as of 2026-08-03 — vendored in full so coverage is explicit. It knowingly includes dual-use staples (PuTTY, WinSCP, mstsc, PSEXEC, Tailscale, ngrok): the list does not claim they are bad, the *estate's prevalence* decides which entries are furniture here and which are tripwires. Refresh against the project on review cadence.

## Sweep the corpus

/baseline: execution and installation prevalence per watched tool, trailing 30 days
  watchlist: >
           247ithelp.com (ConnectWise), Absolute (Computrace), Access Remote
           PC, Acronis Cyber Protect (Remotix), Action1, Addigy, Adobe
           Connect, AeroAdmin, AliWangWang-remote-control, Alpemix, Ammyy
           Admin, Any Support, AnyDesk, Anyplace Control, AnyViewer, Apple
           Remote Desktop, Aspia, Atera, Auvik, AweRay, baramundi Management
           Suite, Barracuda, Basecamp, BeamYourScreen, BeAnyWhere, BeInSync,
           BeyondTrust, BeyondTrust (Bomgar), Bitvise SSH Client, Bitvise SSH
           Server, Bluetrait, CentraStage (Now Datto), Centurion, Chicken (of
           the VNC), Chrome Remote Desktop, Chrome SSH Extension, CloudFlare
           Tunnel, Comodo RMM, ConnectWise, Connectwise Automate (LabTech),
           ConnectWise Control, Controlio, CrossLoop, CrossTec Remote
           Control, CruzControl, DameWare, Dataplicity, DeskDay, DeskNets,
           DeskShare, DesktopNow, Dev Tunnels (aka Visual Studio Dev Tunnel),
           Devolutions Remote Desktop Manager, Distant Desktop, Domotz,
           DragonDisk, Duet Display, Duplicati, DW Service, Echoware, eHorus,
           Electric AI (Kaseya), EMCO Remote Console, Encapto, Ericom
           AccessNow, Ericom Connect, ESET Remote Administrator, ExtraPuTTY,
           ezHelp, Faronics Core, Faronics Deep Freeze, Faronics Deploy,
           Faronics Insight, FastViewer, FixMe.it, FleetDeck.io, Fortra, Free
           Ping Tool, Free Tools Launcher, FreeNX, FreeRDP, Freshservice,
           GatherPlace-desktop sharing, GetScreen, GLPI Agent, Gorelo RMM,
           GoTo Opener, GoToAssist, GoToAssist (GoTo Resolve), GoToAssist
           Agent Desktop Console, GotoHTTP, GoToMyPC, Goverlan, Guacamole,
           HeartbeatRM, HelpBeam, HelpU, HelpWire, HopToDesk, I'm InTouch,
           iDrive, ImmyBot, Impero Connect, Instant Housecall, Insync,
           IntelliAdmin Remote Control, InvGate, Iperius Remote, ISL Light,
           ISL Online, Itarian, ITSupport247 (ConnectWise), Ivanti Remote
           Control, JollysFastVNC, Jump Cloud, Jump Desktop, Kabuto, Kaseya
           (VSA), KHelpDesk, KickIdler, KiTTY, Komari, Koofr, LabTeach
           (Connectwise Automate), LabTech RMM (Now ConnectWise Automate),
           LANDesk, Laplink Everywhere, Laplink Gold, Level, Level.io, Lite
           Manager, LiteManager, LocalXpose, LogMeIn, LogMeIn rescue,
           Lunixar, Manage Engine (Desktop Central), ManageEngine,
           ManageEngine RMM Central, ManageEngine ServiceDesk Plus, MEGAsync,
           MeshCentral, Microsoft Quick Assist, Mikogo, MioNet (Also known as
           WD Anywhere Access), MioNet (WD Anywhere Access), Miradore,
           MobaXterm, Mocha VNC Lite, Monitic, Mouse Without Borders,
           mRemoteNG, MSP360, mstsc.exe (Microsoft Remote Desktop
           Connection), MultCloud, MyGreenPC, MyIVO, N-Able Advanced
           Monitoring Agent, N-ABLE Remote Access Software, Naverisk, Net
           Monitor for Employees, NetBird, NetLock RMM, Netop, Netop Remote
           Control (aka Impero Connect), Netop Remote Control (Impero
           Connect), Netreo, NetSupport Manager, Neturo, Netviewer, Netviewer
           (GoToMeet), Nezha, ngrok, Ninite Pro (Ninite Agent), NinjaOne
           (formerly NinjaRMM), NinjaRMM, NoMachine, NordLocker, NoteOn-
           desktop sharing, NTR Remote, NVDA (Non-Visual Desktop Access), OCS
           inventory, Onionshare, OptiTune, Pandora RC (eHorus), Panorama9,
           Parallels Access, Parsec, pcAnywhere, PChelpware, Pcnow, Pcvisit,
           PDQ Connect, Pilixo, PiTunnel, Pocket Cloud (Wyse), Pocket
           Controller, Pocket Controller (Soti Xsight), PSEXEC, PSEXEC
           (Clone), Pulseway, PuTTY, PuTTY Tray, QQ IM-remote assistance,
           Quest KACE Agent (formerly Dell KACE), Quick Assist, RAdmin,
           Rapid7, RdClient, RDCMan, rdp2tcp, RDPView, rdpwrap, RealVNC,
           Remcos, Remmina, Remmon, Remobo, Remote Desktop Manager
           (Devolutions), Remote Desktop Plus, Remote Manipulator System,
           Remote Ripple, Remote Utilities, Remote.it, RemoteCall, Remotely,
           RemotePass, RemotePC, RemotePulse, RemoteUtilities, RemoteView,
           RemSupp, RES Automation Manager, Rocket Remote Desktop, Rodex RMM,
           Royal Apps, Royal Server, Royal TS, RPort, RuDesktop, RunSmart,
           RustDesk, S3 Browser, ScreenConnect, ScreenMeet, SecureCRT,
           Seetrol, Senso.cloud, ServerEye, ShellHub, ShowMyPC, SimpleHelp,
           Site24x7, SkyFex, SmartCode Web VNC, SmartFTP, SmarTTY, Solar-
           PuTTY, Sophos-Remote Management System, Sorillus, Splashtop,
           Splashtop (Beta), Splashtop Remote, SpyAnywhere, SunLogin,
           SuperOps, SuperPuTTY, Supremo, Syncro, Syncthing, Synergy, SysAid,
           Syspectr, Tactical RMM, Tailscale, Tanium, Tanium Deploy,
           TeamViewer, TeleDesktop, Teramind, Terminals, TiFLUX, TigerVNC,
           TightVNC, tmate, ToDesk, Total Software Deployment, TrustConnect,
           TurboMeeting, Ultra VNC, UltraViewer, UltraVNC, Veyon, Visual
           Studio Dev Tunnel, VIZOR, VNC, VNC Connect, WebEx (Remote Access),
           WebRDP, Weezo, WinSCP, X2Go, Xeox, Xpra, XRDP, Xshell,
           Yandex.Disk, Zabbix Agent, ZeroTier, ZOC, Zoho Assist
  note:   "Census by binary internal name, signer and service/install
           artifacts — NOT by filename, which is the first thing an
           installer randomizes and an intruder renames. Expect three
           partitions: the sanctioned one-or-two (fleet-wide), a tolerated
           niche tail (one admin's PuTTY habit), and a large zero set.
           Publish the partition in the sweep narrative — the sanctioned
           list is something most orgs have never actually written down,
           and this census IS that document."

## The tripwires

/query: executions or installations of zero-prevalence tools
  window: 24h
  from:   edr_telemetry
  note:   "AnyDesk appearing in an estate that runs ScreenConnect is not a
           software choice, it is an access method. Rank by installation
           depth: a service or autorun registration outranks a portable
           one-shot execution — the former is meant to survive, and pair
           it with the autoruns hunt's census. A renamed binary matched on
           internal name or signer outranks both, because renaming is
           intent."

## Sanctioned tools in unsanctioned places

/query: first-seen-on-host executions of the SANCTIONED tools
  note:   "The sanctioned product is also the attacker's cheapest disguise —
           nobody questions a second ScreenConnect session. First install
           on a host outside the fleet-management flow, an agent enrolled
           to a DIFFERENT tenant or account than the org's own, or a
           helpdesk tool running on servers the helpdesk never touches:
           the product is legitimate, the deployment is the finding."

## The network leg

/query: rendezvous traffic for watched tools from hosts with no matching agent
  note:   "Every RMM SaaS has known rendezvous and relay domains. Traffic to
           them from a host where the census shows NO corresponding
           install means a portable copy ran and left, or something is
           tunnelling in the tool's clothing. This leg also catches the
           browser-only variants that never write a binary at all."

## Rule out the boring explanation

/pivot: how the tool arrived, and who was at the keyboard after
  note:   "Walk the provenance: dropped by a browser minutes after a
           'helpdesk' phone call is the social-engineering signature;
           installed by the software-deployment pipeline with a change
           ticket is IT piloting a product. Users installing personal
           remote-desktop tools to work from home is the common middle —
           unsanctioned but not hostile, and the narrative should call it
           shadow IT rather than intrusion, while still counting it."

/baseline: is there an active vendor or MSP relationship that explains the tool
  note:   "MSPs bring their own RMM, auditors bring their own VNC, and both
           arrive legitimately on exactly the machines they were hired to
           touch. The contract population is knowable — check it, and note
           that a REAL vendor tool on hosts outside the engagement's scope
           fails the check it just passed."

## Emit

/lead: remote-access tool outside the estate's sanctioned pattern
  entity: host
  note:   "Evidence carries the census partition the hit violated, the
           binary identity (internal name, signer, hash), installation
           artifacts, provenance chain, and any rendezvous traffic with the
           tenant or account identity where the tool exposes one — that
           account ID is often the single most attributable artifact an
           intrusion leaves. State watchlist coverage like the LOLBAS hunt
           does: 311 watched, N resolvable in this estate's telemetry."
