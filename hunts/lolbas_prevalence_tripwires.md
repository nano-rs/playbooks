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
hypothesis: "The LOLBAS corpus is public and finite. Most entries never execute in a given estate, so a corpus binary, library or script that runs on one to three hosts in the window (or whose hash the estate has barely seen) is a tripwire firing, and three or more download, decode and execute entries on one host within 30 minutes are a composed kill chain. The benign twins are a niche host that always runs the binary (a build server's msbuild, a DBA box's sqlps) and new software arriving through the deployment stack."
risk_weight: 6
default_severity: medium
pivots:
  - name: lolbas_corpus_census
    role: coverage
    query: 'class_uid=1007 activity_id=1 process.name IN ("acccheckconsole.exe","addinutil.exe","adplus.exe","agentexecutor.exe","appcert.exe","appinstaller.exe","applauncher.exe","appvlp.exe","aspnet_compiler.exe","at.exe","atbroker.exe","bash.exe","bcp.exe","bginfo.exe","bitsadmin.exe","cdb.exe","certoc.exe","certreq.exe","certutil.exe","change.exe","cipher.exe","cmd.exe","cmdkey.exe","cmdl32.exe","cmstp.exe","colorcpl.exe","computerdefaults.exe","configsecuritypolicy.exe","conhost.exe","control.exe","coregen.exe","createdump.exe","csc.exe","cscript.exe","csi.exe","customshellhost.exe","datasvcutil.exe","defaultpack.exe","desktopimgdownldr.exe","devicecredentialdeployment.exe","devinit.exe","devtoolslauncher.exe","devtunnel.exe","dfsvc.exe","diantz.exe","diskshadow.exe","dnscmd.exe","dnx.exe","dotnet.exe","dsdbutil.exe","dtutil.exe","dump64.exe","dumpminitool.exe","dxcap.exe","ecmangen.exe","esentutl.exe","eudcedit.exe","eventvwr.exe","excel.exe","expand.exe","explorer.exe","extexport.exe","extrac32.exe","findstr.exe","finger.exe","fltmc.exe","forfiles.exe","fsi.exe","fsianycpu.exe","fsutil.exe","ftp.exe","gpscript.exe","hh.exe","ie4uinit.exe","iediagcmd.exe","ieexec.exe","ilasm.exe","imewdbld.exe","infdefaultinstall.exe","installutil.exe","intellitrace.exe","iscsicpl.exe","jsc.exe","ldifde.exe","logger.exe","makecab.exe","mavinject.exe","mftrace.exe","microsoft.nodejstools.pressanykey.exe","microsoft.workflow.compiler.exe","mmc.exe","mofcomp.exe","mpcmdrun.exe","mpiexec.exe","msaccess.exe","msbuild.exe","msconfig.exe","mscopilot.exe","mscopilot_proxy.exe","msdeploy.exe","msdt.exe","msedge.exe","msedge_proxy.exe","msedgewebview2.exe","mshta.exe","msiexec.exe","msohtmed.exe","msoxmled.exe","mspub.exe","msxsl.exe","netsh.exe","ngen.exe","nmcap.exe","ntdsutil.exe","ntsd.exe","odbcad32.exe","odbcconf.exe","offlinescannershell.exe","onedrivestandaloneupdater.exe","openconsole.exe","outlook.exe","pcalua.exe","pcwrun.exe","pixtool.exe","pktmon.exe","pnputil.exe","powerpnt.exe","presentationhost.exe","print.exe","printbrm.exe","procdump.exe","protocolhandler.exe","provlaunch.exe","psr.exe","query.exe","rasautou.exe","rcsi.exe","rdrleakdiag.exe","reg.exe","regasm.exe","regedit.exe","regini.exe","register-cimprovider.exe","regsvcs.exe","regsvr32.exe","remote.exe","replace.exe","reset.exe","rpcping.exe","rundll32.exe","runexehelper.exe","runonce.exe","runscripthelper.exe","sc.exe","schtasks.exe","scp.exe","scriptrunner.exe","setres.exe","settingsynchost.exe","setupugc.exe","sftp.exe","sigverif.exe","sqldumper.exe","sqlps.exe","sqltoolsps.exe","squirrel.exe","ssh.exe","stordiag.exe","syncappvpublishingserver.exe","tar.exe","te.exe","teams.exe","testwindowremoteagent.exe","tracker.exe","ttdinject.exe","tttracer.exe","unregmp2.exe","update.exe","vbc.exe","verclsid.exe","visio.exe","visualuiaverifynative.exe","vsdiagnostics.exe","vshadow.exe","vsiisexelauncher.exe","vsjitdebugger.exe","vslaunchbrowser.exe","vsls-agent.exe","vstest.console.exe","wab.exe","wbadmin.exe","wbemtest.exe","wfc.exe","wfmformat.exe","windbg.exe","winfile.exe","winget.exe","winproj.exe","winword.exe","wlrmdr.exe","wmic.exe","workfolders.exe","write.exe","wsb.exe","wscript.exe","wsl.exe","wsreset.exe","wt.exe","wuauclt.exe","xbootmgr.exe","xbootmgrsleep.exe","xsd.exe","xwizard.exe") | stats count, dc(device.hostname) AS hosts, values(device.hostname) AS host_sample, min(prevalence_process_hash) AS estate_hash_hosts by process.name | sort hosts, process.name | head 250'
  - name: low_prevalence_lolbas_executions
    role: discovery
    query: 'class_uid=1007 activity_id=1 process.name IN ("acccheckconsole.exe","addinutil.exe","adplus.exe","agentexecutor.exe","appcert.exe","appinstaller.exe","applauncher.exe","appvlp.exe","aspnet_compiler.exe","at.exe","atbroker.exe","bash.exe","bcp.exe","bginfo.exe","bitsadmin.exe","cdb.exe","certoc.exe","certreq.exe","certutil.exe","change.exe","cipher.exe","cmd.exe","cmdkey.exe","cmdl32.exe","cmstp.exe","colorcpl.exe","computerdefaults.exe","configsecuritypolicy.exe","conhost.exe","control.exe","coregen.exe","createdump.exe","csc.exe","cscript.exe","csi.exe","customshellhost.exe","datasvcutil.exe","defaultpack.exe","desktopimgdownldr.exe","devicecredentialdeployment.exe","devinit.exe","devtoolslauncher.exe","devtunnel.exe","dfsvc.exe","diantz.exe","diskshadow.exe","dnscmd.exe","dnx.exe","dotnet.exe","dsdbutil.exe","dtutil.exe","dump64.exe","dumpminitool.exe","dxcap.exe","ecmangen.exe","esentutl.exe","eudcedit.exe","eventvwr.exe","excel.exe","expand.exe","explorer.exe","extexport.exe","extrac32.exe","findstr.exe","finger.exe","fltmc.exe","forfiles.exe","fsi.exe","fsianycpu.exe","fsutil.exe","ftp.exe","gpscript.exe","hh.exe","ie4uinit.exe","iediagcmd.exe","ieexec.exe","ilasm.exe","imewdbld.exe","infdefaultinstall.exe","installutil.exe","intellitrace.exe","iscsicpl.exe","jsc.exe","ldifde.exe","logger.exe","makecab.exe","mavinject.exe","mftrace.exe","microsoft.nodejstools.pressanykey.exe","microsoft.workflow.compiler.exe","mmc.exe","mofcomp.exe","mpcmdrun.exe","mpiexec.exe","msaccess.exe","msbuild.exe","msconfig.exe","mscopilot.exe","mscopilot_proxy.exe","msdeploy.exe","msdt.exe","msedge.exe","msedge_proxy.exe","msedgewebview2.exe","mshta.exe","msiexec.exe","msohtmed.exe","msoxmled.exe","mspub.exe","msxsl.exe","netsh.exe","ngen.exe","nmcap.exe","ntdsutil.exe","ntsd.exe","odbcad32.exe","odbcconf.exe","offlinescannershell.exe","onedrivestandaloneupdater.exe","openconsole.exe","outlook.exe","pcalua.exe","pcwrun.exe","pixtool.exe","pktmon.exe","pnputil.exe","powerpnt.exe","presentationhost.exe","print.exe","printbrm.exe","procdump.exe","protocolhandler.exe","provlaunch.exe","psr.exe","query.exe","rasautou.exe","rcsi.exe","rdrleakdiag.exe","reg.exe","regasm.exe","regedit.exe","regini.exe","register-cimprovider.exe","regsvcs.exe","regsvr32.exe","remote.exe","replace.exe","reset.exe","rpcping.exe","rundll32.exe","runexehelper.exe","runonce.exe","runscripthelper.exe","sc.exe","schtasks.exe","scp.exe","scriptrunner.exe","setres.exe","settingsynchost.exe","setupugc.exe","sftp.exe","sigverif.exe","sqldumper.exe","sqlps.exe","sqltoolsps.exe","squirrel.exe","ssh.exe","stordiag.exe","syncappvpublishingserver.exe","tar.exe","te.exe","teams.exe","testwindowremoteagent.exe","tracker.exe","ttdinject.exe","tttracer.exe","unregmp2.exe","update.exe","vbc.exe","verclsid.exe","visio.exe","visualuiaverifynative.exe","vsdiagnostics.exe","vshadow.exe","vsiisexelauncher.exe","vsjitdebugger.exe","vslaunchbrowser.exe","vsls-agent.exe","vstest.console.exe","wab.exe","wbadmin.exe","wbemtest.exe","wfc.exe","wfmformat.exe","windbg.exe","winfile.exe","winget.exe","winproj.exe","winword.exe","wlrmdr.exe","wmic.exe","workfolders.exe","write.exe","wsb.exe","wscript.exe","wsl.exe","wsreset.exe","wt.exe","wuauclt.exe","xbootmgr.exe","xbootmgrsleep.exe","xsd.exe","xwizard.exe") | stats count, dc(device.hostname) AS hosts, values(device.hostname) AS host_list, values(process.parent_process.name) AS parents, values(process.file.path) AS paths, values(process.cmd_line) AS cmd_lines, min(prevalence_process_hash) AS estate_hash_hosts by process.name | where hosts <= 3 | sort hosts, -count, process.name | head 200'
  - name: lolbas_library_script_invocations
    role: discovery
    query: 'class_uid=1007 activity_id=1 ((process.name IN ("rundll32.exe","regsvr32.exe","odbcconf.exe") (process.cmd_line=*advpack.dll* OR process.cmd_line=*comsvcs.dll* OR process.cmd_line=*dfshim.dll* OR process.cmd_line=*ieadvpack.dll* OR process.cmd_line=*ieframe.dll* OR process.cmd_line=*mshtml.dll* OR process.cmd_line=*pcwutl.dll* OR process.cmd_line=*photoviewer.dll* OR process.cmd_line=*scrobj.dll* OR process.cmd_line=*setupapi.dll* OR process.cmd_line=*shdocvw.dll* OR process.cmd_line=*shimgvw.dll* OR process.cmd_line=*shell32.dll* OR process.cmd_line=*syssetup.dll* OR process.cmd_line=*url.dll* OR process.cmd_line=*zipfldr.dll*)) OR (process.cmd_line=*cl_invocation.ps1* OR process.cmd_line=*cl_loadassembly.ps1* OR process.cmd_line=*cl_mutexverifiers.ps1* OR process.cmd_line=*desk.cpl* OR process.cmd_line=*launch-vsdevshell.ps1* OR process.cmd_line=*manage-bde.wsf* OR process.cmd_line=*pester.bat* OR process.cmd_line=*pubprn.vbs* OR process.cmd_line=*syncappvpublishingserver.vbs* OR process.cmd_line=*utilityfunctions.ps1* OR process.cmd_line=*winrm.vbs*)) | stats count, dc(device.hostname) AS hosts, values(device.hostname) AS host_list, values(process.cmd_line) AS cmd_lines by process.parent_process.name, process.name | where hosts <= 3 | sort hosts, -count, process.parent_process.name, process.name | head 200'
  - name: lolbas_chain_windows
    role: discovery
    query: 'class_uid=1007 activity_id=1 process.name IN ("certutil.exe","bitsadmin.exe","imewdbld.exe","desktopimgdownldr.exe","expand.exe","extrac32.exe","esentutl.exe","finger.exe","ftp.exe","mpcmdrun.exe","replace.exe","makecab.exe","diantz.exe","rundll32.exe","regsvr32.exe","mshta.exe","msbuild.exe","installutil.exe","odbcconf.exe","cmstp.exe","regasm.exe","regsvcs.exe","wmic.exe","pcalua.exe","forfiles.exe","msiexec.exe","msxsl.exe","ieexec.exe","presentationhost.exe","wscript.exe","cscript.exe","hh.exe") | stats dc(process.name) AS distinct_lolbas, count, values(process.name) AS chain, values(process.cmd_line) AS cmd_lines, min(timestamp) AS first_seen, max(timestamp) AS last_seen by device.hostname, actor.user.name | where distinct_lolbas >= 3 | sort -distinct_lolbas, -count, device.hostname, actor.user.name | head 200'
budget:
  max_turns: 40
  max_tool_calls: 120
  max_rows: 6000
  max_wall_seconds: 2700
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
           shrinkage between sweeps is visible. The `lolbas_corpus_census`
           pivot measures the binaries for this window (hosts per entry plus
           the estate hash prevalence); a 30-day zero is not a pivot, so
           confirm a zero with a wider search before calling it one."

## The tripwires

/query: executions of zero-prevalence entries
  window: 24h
  from:   windows_sysmon
  note:   "Any hit here is a lead candidate on arrival — the estate itself
           established that nothing legitimate runs this binary. Match on
           image name AND on original-filename/hash where available: a
           renamed LOLBAS caught by internal name is a stronger finding, not
           a weaker one, because renaming is itself intent. The
           `low_prevalence_lolbas_executions` pivot lists corpus binaries
           seen on at most 3 hosts in the window, with parents, paths and
           command lines; `lolbas_library_script_invocations` does the same
           for the libraries and scripts. Original filename is not a column,
           so a renamed copy is only visible through its path or hash."

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
           shared working directory or shared file artifact is the join.
           The `lolbas_chain_windows` pivot lists every host and user with
           3 or more distinct download, decode or execute entries in the
           window, with first_seen / last_seen; check that the links fall
           within about 30 minutes of each other."

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
