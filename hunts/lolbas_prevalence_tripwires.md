---
kind: hunt
title: "Signed binaries this estate never runs, running"
subtitle: "The full LOLBAS corpus swept by estate prevalence — zero-baseline entries become tripwires, sequences become kill chains"
category: endpoint
owner: "team · soc-leads"
authored: 2026-08-03
schedule: "0 2 * * *"
timezone: "UTC"
lookback_window: 24h
telemetry:
  all_of:
    - endpoint.process
mitre_tactic: defense-evasion
mitre_technique: T1218
budget:
  max_turns: 40
  max_tool_calls: 120
  max_rows: 6000
  max_wall_seconds: 900
tags:
  - endpoint
  - lolbas
  - execution
  - tripwire
---
# Signed binaries this estate never runs, running

**Hypothesis:** the LOLBAS corpus is public, finite, and abusable by design — so watch *all of it* and let the estate's own history split the list in two. Entries the estate runs daily need context to judge, and the parent-pair hunt (`lolbin_unusual_parent`) already owns that ground. Entries the estate has **never** run need no context at all: a binary with zero executions in thirty days that executes today is a tripwire firing, and a tripwire is the cheapest high-confidence signal a hunt can own.

The watchlist below is the complete LOLBAS project corpus — 240 entries as of 2026-08-03 — vendored deliberately rather than summarised, so the sweep's coverage is explicit and comparable between runs. Refresh it against the project on review cadence; the project adds entries monthly and a stale list is silent shrinkage.

## Sweep the whole corpus

/baseline: execution prevalence per watched entry, trailing 30 days
  binaries: >
           AccCheckConsole.exe, AddinUtil.exe, adplus.exe, AgentExecutor.exe,
           AppCert.exe, AppInstaller.exe, AppLauncher.exe, Appvlp.exe,
           Aspnet_Compiler.exe, At.exe, Atbroker.exe, Bash.exe, Bcp.exe,
           Bginfo.exe, Bitsadmin.exe, Cdb.exe, CertOC.exe, CertReq.exe,
           Certutil.exe, Change.exe, Cipher.exe, Cmd.exe, Cmdkey.exe,
           cmdl32.exe, Cmstp.exe, Colorcpl.exe, ComputerDefaults.exe,
           ConfigSecurityPolicy.exe, Conhost.exe, Control.exe, coregen.exe,
           Createdump.exe, Csc.exe, Cscript.exe, csi.exe,
           CustomShellHost.exe, DataSvcUtil.exe, DefaultPack.EXE,
           Desktopimgdownldr.exe, DeviceCredentialDeployment.exe,
           Devinit.exe, Devtoolslauncher.exe, devtunnel.exe, Dfsvc.exe,
           Diantz.exe, Diskshadow.exe, Dnscmd.exe, dnx.exe, Dotnet.exe,
           dsdbutil.exe, dtutil.exe, Dump64.exe, DumpMinitool.exe, Dxcap.exe,
           ECMangen.exe, Esentutl.exe, Eudcedit.exe, Eventvwr.exe, Excel.exe,
           Expand.exe, Explorer.exe, Extexport.exe, Extrac32.exe,
           Findstr.exe, Finger.exe, fltMC.exe, Forfiles.exe, Fsi.exe,
           FsiAnyCpu.exe, Fsutil.exe, Ftp.exe, Gpscript.exe, Hh.exe,
           Ie4uinit.exe, iediagcmd.exe, Ieexec.exe, Ilasm.exe, IMEWDBLD.exe,
           Infdefaultinstall.exe, Installutil.exe, IntelliTrace.exe,
           iscsicpl.exe, Jsc.exe, Ldifde.exe, Logger.exe, Makecab.exe,
           Mavinject.exe, Mftrace.exe, Microsoft.NodejsTools.PressAnyKey.exe,
           Microsoft.Workflow.Compiler.exe, Mmc.exe, Mofcomp.exe,
           MpCmdRun.exe, Mpiexec.exe, MSAccess.exe, Msbuild.exe,
           Msconfig.exe, Mscopilot.exe, Mscopilot_proxy.exe, Msdeploy.exe,
           Msdt.exe, Msedge.exe, msedge_proxy.exe, msedgewebview2.exe,
           Mshta.exe, Msiexec.exe, MsoHtmEd.exe, msoxmled.exe, Mspub.exe,
           msxsl.exe, Netsh.exe, Ngen.exe, Nmcap.exe, ntdsutil.exe, Ntsd.exe,
           odbcad32.exe, Odbcconf.exe, OfflineScannerShell.exe,
           OneDriveStandaloneUpdater.exe, OpenConsole.exe, Outlook.exe,
           Pcalua.exe, Pcwrun.exe, Pixtool.exe, Pktmon.exe, Pnputil.exe,
           Powerpnt.exe, Presentationhost.exe, Print.exe, PrintBrm.exe,
           Procdump.exe, ProtocolHandler.exe, Provlaunch.exe, Psr.exe,
           Query.exe, Rasautou.exe, rcsi.exe, rdrleakdiag.exe, Reg.exe,
           Regasm.exe, Regedit.exe, Regini.exe, Register-cimprovider.exe,
           Regsvcs.exe, Regsvr32.exe, Remote.exe, Replace.exe, Reset.exe,
           Rpcping.exe, Rundll32.exe, Runexehelper.exe, Runonce.exe,
           Runscripthelper.exe, Sc.exe, Schtasks.exe, scp.exe,
           Scriptrunner.exe, Setres.exe, SettingSyncHost.exe, setupugc.exe,
           Sftp.exe, Sigverif.exe, Sqldumper.exe, Sqlps.exe, SQLToolsPS.exe,
           Squirrel.exe, ssh.exe, Stordiag.exe, SyncAppvPublishingServer.exe,
           Tar.exe, te.exe, Teams.exe, TestWindowRemoteAgent.exe,
           Tracker.exe, Ttdinject.exe, Tttracer.exe, Unregmp2.exe,
           Update.exe, vbc.exe, Verclsid.exe, Visio.exe,
           VisualUiaVerifyNative.exe, VSDiagnostics.exe, Vshadow.exe,
           VSIISExeLauncher.exe, vsjitdebugger.exe, VSLaunchBrowser.exe,
           vsls-agent.exe, vstest.console.exe, Wab.exe, wbadmin.exe,
           wbemtest.exe, Wfc.exe, WFMFormat.exe, WinDbg.exe, winfile.exe,
           winget.exe, WinProj.exe, Winword.exe, Wlrmdr.exe, Wmic.exe,
           WorkFolders.exe, write.exe, wsb.exe, Wscript.exe, Wsl.exe,
           Wsreset.exe, wt.exe, wuauclt.exe, XBootMgr.exe, XBootMgrSleep.exe,
           xsd.exe, Xwizard.exe
  libraries: >
           Advpack.dll, Comsvcs.dll, Dfshim.dll, Ieadvpack.dll, Ieframe.dll,
           Mshtml.dll, Pcwutl.dll, PhotoViewer.dll, Scrobj.dll, Setupapi.dll,
           Shdocvw.dll, Shimgvw.dll, Shell32.dll, Syssetup.dll, Url.dll,
           Zipfldr.dll
  scripts: >
           CL_Invocation.ps1, CL_LoadAssembly.ps1, CL_Mutexverifiers.ps1,
           Desk.cpl, Launch-VsDevShell.ps1, Manage-bde.wsf, Pester.bat,
           Pubprn.vbs, Syncappvpublishingserver.vbs, UtilityFunctions.ps1,
           winrm.vbs
  note:   "One prevalence number per entry: distinct hosts executing it in the
           trailing window. Libraries count as invoked when they appear in
           rundll32/regsvr32/odbcconf command lines; scripts when a script
           host runs them. Expect the census to split roughly into a large
           never-runs set, a small always-runs set, and a thin middle. The
           never-runs set IS the product — persist it in the sweep narrative
           so the reader can see this estate's tripwire surface, and so
           shrinkage between sweeps is visible."

## The tripwires

/query: executions of zero-prevalence entries
  window: 24h
  from:   windows_sysmon
  note:   "Any hit here is a lead candidate on arrival — the estate itself
           established that nothing legitimate runs this binary. Match on
           image name AND on original-filename/hash where available: a
           renamed LOLBAS caught by internal name is a stronger finding, not
           a weaker one, because renaming is itself intent."

## The middle of the list

/query: low-prevalence entries executing outside their tiny niche
  note:   "Entries that run on two or three hosts — a build server's msbuild,
           a DBA box's sqlps — are effectively tripwires everywhere EXCEPT
           their niche. Judge by host-set membership, not by existence: the
           same binary on a fourth, unrelated host gets the zero-baseline
           treatment. High-prevalence entries get no judgment here at all;
           that is `lolbin_unusual_parent`'s job and duplicating it makes
           two mediocre hunts out of two sharp ones."

## Chains outrank nodes

/query: sequences of watched entries on one host inside a short window
  note:   "The corpus is a toolbox and real use composes it: download
           (certutil, bitsadmin, IMEWDBLD) then decode (certutil, expand)
           then execute (rundll32, regsvr32, mshta) is a kill chain even
           when every link individually survives prevalence. Sequence plus
           shared working directory or shared file artifact is the join."

/pivot: process tree and file artifacts around any tripwire hit
  note:   "Walk the usual questions — what launched it, what did it write,
           what came next. A tripwire hit whose parent is a deployment agent
           during a change window is how new software announces itself;
           record it and let the census absorb the new normal next sweep."

## Emit

/lead: execution of an estate-zero-baseline LOLBAS entry, or a composed chain
  entity: host
  note:   "Evidence carries the entry's prevalence history (the zero), the
           full command line, the process tree, and any chain partners.
           State which list partition the hit came from — tripwire, niche
           violation, or chain — because the reader's prior differs sharply
           between them. Watchlist coverage is part of the sweep narrative:
           240 watched, N executable in this estate's telemetry, so
           tomorrow's reader knows what was NOT visible."
