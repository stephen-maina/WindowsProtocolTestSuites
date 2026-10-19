---
name: test-debugging
description: Debug failures in any Windows Protocol Test Suite (FileServer SMB2/FSA/models, MS-SMBD, others) - locate or enable per-test logs, packet traces and SUT logs over SSH, then classify each failure as a SUT implementation defect, a test that asserts product-specific (Windows) behaviour instead of the specification, a genuine test bug, or an environment/config issue, using the MS Learn MCP for spec evidence. Use when a test fails, when triaging a full run, or when checking a test against [MS-SMB2] and related specs.
license: MIT
metadata:
  author: Microsoft
  version: "1.0"
---

# Test-failure debugging skill

Goal: for every failure, produce a verdict backed by evidence from three sources: the **driver** (test log, pcap), the **SUT** (kernel/event logs) and the **specification** (MS Learn). Never classify from the failure message alone.

## 1. Where the evidence is

| Source | Location | Produced by |
|---|---|---|
| Per-test shared diagnostics (manifest, `ptf-log.ndjson`, capture) | `<Diagnostics.ArtifactRoot>\session-<ts>\tests\<Test>__<id>\` (default `C:\WPTS-Diagnostics`) | `TestSuites/Common/Diagnostics*` (shared); wired into FileServer via `FileServer/src/Common/TestSuite/FileServerDiagnosticsSuite.cs`, and SMBD via `MS-SMBD/src/Diagnostics` |
| Per-test SUT log | same folder: `sut-linux-dmesg.log` (Linux) or `sut-windows.log` (Windows) | `Common/Diagnostics.Ptf/Sut/SutLogCollector.cs`; needs `SutLog.Enabled=true` and `Diagnostics.Enabled=true` |
| Whole-run evidence on a Linux SUT | `<OutDir>\summary.csv`, `tests\<name>.log` (dmesg slice per test), `smb445.pcapng`, `sut-dmesg.log`, `results.trx` | `TestSuites/FileServer/src/Batch/SutDebug/Run-FileServerWithSutLogs.ps1` |
| Pcap decoding | console | `FileServer/src/Batch/SutDebug/Parse-Smb2Pcap.ps1` |

### Enabling it (deployment ptfconfig, e.g. `CommonTestSuite.deployment.ptfconfig`)
- `Diagnostics.Enabled=true`, `Diagnostics.ArtifactRoot`, `Diagnostics.Capture.Provider` (`Automatic`), `Diagnostics.Capture.Targets` (blank = default client NIC), `Diagnostics.Capture.TrafficScope`, `Diagnostics.Retention` (`KeepAll`).
- `SutLog.Enabled=true` (uses `SutComputerName`, `AdminUserName`, `PasswordForAllUsers`).
- Edit the copy in `bin\Debug\net8.0` for quick trials. A rebuild overwrites it from source: keep a backup and re-apply.
- Read the property descriptions in the ptfconfig and the User Guide; do not guess key names.
- If diagnostics are off or the SUT is unreachable the artifact files are simply absent: say so and continue with driver evidence.

### Running tests with full evidence (Linux SUT)
```powershell
cd TestSuites\FileServer\src\Batch\SutDebug
.\Run-FileServerWithSutLogs.ps1 -TestDll ..\..\SMB2\TestSuite\bin\Debug\net8.0\MS-SMB2_ServerTestSuite.dll `
    -Filter "Name=<TestName>" -OutDir C:\FileServerRuns\<n>
```
- Filter is vstest syntax (`Name=A|Name=B`, `Name~Substring`, `TestCategory=Bvt`). A full SMB2 run takes about 20 minutes: run it async, not via hidden `Start-Process`.
- With ksmbd debug OFF the per-test dmesg slice is empty: turn debug ON first (section 2) for any test you triage.
- Pcap: `.\Parse-Smb2Pcap.ps1 -Pcap <ABSOLUTE path> -FromUtc <iso Z> -ToUtc <iso Z> [-HexCommand <smb2 command number>]`. Use absolute paths (.NET file calls ignore the PowerShell cwd). Driver and SUT clocks may differ in time zone; the runner prints both: convert before slicing.
- Helpers that turn a bad status into a timeout/assert text hide the code: read the status in the message.

## 2. SUT access over SSH (when available)
- Helper: `TestSuites/MS-SMBD/src/Batch/SutDebug/Invoke-SutSsh.ps1 -Command "<cmd>" [-Sudo]`. It reads `SutComputerName`, `SutUserName`, `SutPassword` from the **MS-SMBD** deployment ptfconfig (the FileServer runner reuses it), so that file must hold the SUT credentials. Never put secrets in scripts or commits.
- Multi-line commands: base64-encode the script and run `sh -c 'echo <b64> | base64 -d | sh'` (strip CR first). Never name a PowerShell function `R` or `H` (aliases).
- Check reachability first (`Test-Connection`, port 22). If unreachable, do not stall: state what could not be collected.
- Linux/ksmbd: `uname -r`; `dmesg -T | grep -i ksmbd`; debug toggle `echo smb > /sys/class/ksmbd-control/debug` (also `vfs oplock auth conn rdma ipc`; writing again toggles off; brackets around a name in `cat` mean ON). Workflow: enable, `dmesg -C`, run ONE test, read dmesg, disable.
- Create a Linux test environment with `TestSuites/FileServer/Setup/Scripts/Create-SMB2Env-Linux.sh` (shares, users, `--second-user`, durable/leases; see the User Guide). ksmbd user names are case-sensitive (`administrator`).
- Windows SUT: `Get-WinEvent Microsoft-Windows-SMBServer/Operational`, `Get-SmbServerConfiguration`; WinRM helper `MS-SMBD/src/Batch/SutDebug/Invoke-SutWinRM.ps1`.

## 3. Method (in order)
1. **Control first.** If a Windows Server SUT result exists, a test failing there is not a SUT defect. Compare outcomes across SUTs.
2. **Real failure.** Take the test log / trx `ErrorInfo` message and stack. Identify the failing request, expected status and actual status.
3. **Wire evidence.** Decode that test's request/response in the pcap (command, status, flags, create contexts; `-HexCommand` for raw bytes). Confirm the client sent what the test claims: a malformed request is a test/SDK bug.
4. **SUT evidence.** dmesg for the same window: look for the rejection reason (`error parsing ...`, `not implemented yet ioctl`, `owner mismatch`).
5. **Spec evidence** via MS Learn (section 4).
6. **Classify** (section 5) and act.

## 4. Specification evidence via MS Learn MCP
- `microsoft_docs_search` to find the page, then `microsoft_docs_fetch` to read the exact section. Open the section; never cite a number from memory.
- Specs: `[MS-SMB2]` (server processing 3.3.5.x, structures 2.2.x), `[MS-FSCC]`, `[MS-FSA]`, `[MS-SMBD]`, `[MS-DFSC]`, `[MS-RSVD]`, `[MS-FSRVP]`, `[MS-SQOS]`, `[MS-SWN]`. `microsoft_code_sample_search` is for API usage only.
- For each verdict record: document, section, verbatim requirement, level (MUST/SHOULD/MAY) and any product-behavior footnote (`<NNN>` notes in the Product Behavior appendix).
- Optional features (compression, directory leasing, per-share encryption, resilient handles, change notify, alternate streams, normalized names, SIGNING_CAPABILITIES) are not required of every server: the test must be Inconclusive when the server lacks them.
- Repository docs: `TestSuites/<Suite>/docs` (User Guide, Test Design Spec) and `ai-docs/`.

## 5. Classification
| Verdict | Evidence pattern | Action |
|---|---|---|
| **SUT implementation defect** | Request well-formed; spec MUST (or SHOULD without optional note); SUT returns another status or drops the connection; dmesg shows a rejection or `not implemented`. | Keep the test; document in the analysis report with spec quote and dmesg line. |
| **Test asserts product behaviour** | Expects a Windows-only status/value/default (timers, sizes), a Windows-only script, or treats SHOULD/optional as MUST; product-behavior note names Windows versions. | Assert the spec; gate the Windows-specific check on `TestConfig.Platform` or an `Is*Supported` flag; WHAT/WHY/SPEC comment; update docs. |
| **Genuine test bug** | Wrong precondition, deadlock/ordering, wrong ClientGuid/LeaseKey, signed-flag mix, malformed request, wrong access mask, SDK encoding bug. | Fix test/SDK; comment; rerun (and on a Windows control if available). |
| **Environment/config** | Missing share/user/NIC, cluster-only names, domain/LDAP needed in WORKGROUP, topology, licence. | Make Inconclusive when the environment lacks it, or fix config; not a defect. |
| **Unimplemented test** | Spec requirement with no test, or a documented Test ID with no method (grep code and the Test Design Spec; ignore model-generated files). | Report with spec section; add the test or annotate. |

Never turn a timeout or exception into a pass, and never weaken an assertion just so a SUT passes.

## 6. Rules for changes
- Every test-suite edit carries a comment at the site: **WHAT** it does, **WHY** (the defect), **SPEC** `[Doc] section - requirement level`.
- Annotate tests with the spec they validate (`// SPEC: [MS-SMB2] 3.3.5.9.8 - ...` or cite it in the Assert message).
- After each change: rebuild, run the affected tests, confirm the outcome, update the Test Design Spec / User Guide / analysis report, then commit and push. Never commit local ptfconfig edits, pcaps or run output; never rewrite history.
- Build: `MSBuild <project>.csproj /restore` (find MSBuild via `vswhere -latest -find "MSBuild\**\Bin\MSBuild.exe"`); restore the bin ptfconfigs after a rebuild.
- Avoid grepping the generated `SMB2Model\TestSuite` files (huge output).

## 7. Report per failure
`Test | expected vs actual status | pcap evidence | SUT log line | spec section + quote + level | verdict | action`.
Summarise a run as counts per verdict, SUT defects (with SUT version), tests changed, tests Inconclusive by config, and unimplemented-test findings.
