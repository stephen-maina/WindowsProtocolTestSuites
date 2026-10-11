---
name: smbd
description: MS-SMBD / SMB Direct (RDMA) server test suite work - running the suite, debugging failures from traces and logs, classifying a failure as spec / Windows behaviour / ksmbd (SUT) defect / test defect, and building spec context with the MS Learn MCP. Use for TestSuites/MS-SMBD, SMB over RDMA, ksmbd, RoCE.
license: MIT
metadata:
  author: Microsoft
  version: "1.0"
---

# MS-SMBD test suite skill

Suite: `TestSuites/MS-SMBD/src/MS-SMBD_Server.sln` (92 tests; adapters in `src/Adapter`, tests in `src/TestSuite/{SMBD,SMB2overSMBD}`).

## Build and run
- Build with the v143 toolset: `MSBuild.exe MS-SMBD_Server.sln /restore /m` (locate MSBuild via vswhere).
- Run from `src/TestSuite/bin/Debug/net8.0`: `dotnet test MS-SMBD_ServerTestSuite.dll --no-build --filter "Name=<Test>" --logger "trx;LogFileName=x.trx"`.
- Full suite: ~18 min on a Windows SUT, ~1h50m on ksmbd (timeouts). Run detached; redirect console to a file.
- Config: `MS-SMBD_ServerTestSuite.deployment.ptfconfig` (`Platform`, `DriverPlatform`, `SutComputerName`, `DomainName`) and `.ptfconfig`. Edit the copy in `bin` for quick trials; source is copied on build. `SutComputerName` feeds the SMB2 tree-connect path and `DeleteFile.ps1`; `DomainName` must be an IP/DNS name. Set `Platform=NonWindows` for ksmbd, `WindowsServer2025` for a Windows SUT.
- SUT prerequisites: share `SMBDTest` and `testFile_ReadLargeFile.txt` (8 MiB). `Setup/Scripts/SUT/Create-SMBDEnv.ps1` creates both on Windows only; on Linux create them by hand. The second-NIC test needs `ClientNonRNicIp` (e.g. 192.168.20.111) configured on the driver.

## Method: debugging from traces and logs
1. **Control run first.** Run the full suite against a Windows Server SUT. Anything failing there is a test, environment or hardware defect, never a SUT defect. Only then run the non-Windows SUT and diff outcomes.
2. **Read outcomes** from the trx with a streaming `XmlReader` (trx can be 200+ MB; never load whole). Real failure text is `ErrorInfo/Message` + `StackTrace`; `ptf-log.ndjson` does not always show it. The `dotnet test` console log also lists `Failed <name>` with the message.
3. **Evidence** is under `C:\WPTS-Diagnostics\session-<ts>\tests\<Test>__<guid>\{capture.etl, rdma.pcap, manifest.json, ptf-log.ndjson}` (config: `Diagnostics.SessionName`, `Diagnostics.Retention.MaxSessions`). netsh cannot see RDMA; `rdma.pcap` comes from `Mlx5Cmd.exe -Sniffer` (RoCEv2, UDP 4791).
4. **Decode rdma.pcap** (libpcap, linktype 1): IPv4 at offset 14, UDP at 34, BTH at 42 (opcode 0x04 = SEND, 0x11 = ACK, 0x64 = CM). SMBD data-transfer header at 54 (24 bytes: CreditsRequested u16, CreditsGranted u16, Flags u16, Reserved u16, RemainingDataLength u32, DataOffset u32, DataLength u32); SMB2 header (`FE 53 4D 42`) at 78. A zero-length SEND is an empty credit-grant message, which is legal (MS-SMBD 3.1.5.8).
5. **Classify each failure**: `accurate` (test matches spec), `SUT defect` (spec violation, quote the section), `Windows behaviour` (test asserts a Windows-only value), `test inaccurate` (assert/description/setup wrong), `environment`. Always cite the exact spec section and verbatim quote.
6. `ExpectPacket` converts any bad status into `TimeoutException`; read the status in the message (`0xC0000005`, `STATUS_INVALID_PARAMETER`).

## Spec context via MS Learn MCP
- Use `microsoft_docs_search` then `microsoft_docs_fetch` for `[MS-SMBD]` and `[MS-SMB2]` pages. MS-SMBD pages are sometimes thin: fall back to `docs/[MS-SMBD].pdf` or the docx. Verify section numbers directly; do not infer them.
- Key sections: MS-SMBD 3.1.5.1 (receive), 3.1.5.6/3.1.5.7 (negotiate sizes, "at least" minimums), 3.1.5.8 (data transfer validation, credit rules), 3.1.4.2/4.5/4.6 (send, RDMA write/read); MS-SMB2 2.2.43 / 3.3.5.4 / 3.3.5.12 / 3.3.5.13 (RDMA transform, optional).
- Appendix B values (idle timers 120 s/5 s, 1 MiB MaxReadWriteSize, 8136 send size) are Windows defaults, not normative: gate on `Platform`.

## Mandatory: comment every test-suite code change

Every edit to test-suite code (TestSuite, Adapter, config-driven logic) MUST carry a comment at the change site that states:

1. **What** the code now does (e.g. "skip empty credit-grant messages before validating the READ response").
2. **Why** the change was made (the defect: test asserted product behaviour, vacuous pass, wrong precondition, etc.).
3. **Spec reference**: document, section number and the normative wording or requirement level (MUST/SHOULD/MAY), e.g. `[MS-SMBD] 3.1.5.8 Receiving a Data Transfer Message`.
   For product-specific behaviour, cite the Appendix B product-behavior note and gate the code behind a `Platform` check.

Also keep the `SpecSection` TestProperty accurate. Do not leave `TODO(spec)` comments once a test is fixed. Verify the section against the spec (MS Learn MCP) before citing it.

## Debugging the SUT directly (optional, best effort)
Helper scripts in `TestSuites/MS-SMBD/src/Batch/SutDebug/` read `SutComputerName`, `SutUserName`, `SutPassword` from the deployment ptfconfig (no secrets in the scripts). They are debugging aids only; **if they cannot connect, carry on with the driver-side evidence** (pcap, ptf-log, trx) and tell the user what you could not collect.
- Linux SUT (ksmbd): `Batch\SutDebug\Invoke-SutSsh.ps1 -Command "<cmd>" [-Sudo]` (Windows OpenSSH at `C:\Windows\System32\OpenSSH\ssh.exe`, password via SSH_ASKPASS).
- Windows SUT: `Batch\SutDebug\Invoke-SutWinRM.ps1 -Command "<cmd>"` (WinRM; needs TrustedHosts on the driver and PSRemoting on the SUT; untested against a live Windows SUT, so expect to adjust).
- Always check reachability first: `Test-Connection <ip>`, port 22 or 5985. If ping fails but SMB (445) works, check the driver NIC network category: the RDMA NICs must be **Private** (`Get-NetConnectionProfile`, `Set-NetConnectionProfile -InterfaceAlias <nic> -NetworkCategory Private`); Public blocks ping/SSH/WinRM. Leave the internet-facing NIC alone.
- Useful Linux collection: `uname -r`; `modinfo ksmbd`; `dmesg -T | grep -i ksmbd`; ksmbd debug toggles at `/sys/class/ksmbd-control/debug` (writing a name toggles it: `smb auth vfs oplock ipc conn rdma`; `[x]` = on). Workflow: enable `rdma conn smb`, `dmesg -C`, run ONE test, read `dmesg -T`, then compare with `rdma.pcap`. Match timestamps (SUT clock may be in another time zone/offset).
- Useful Windows collection: `Get-WinEvent Microsoft-Windows-SMBServer/Operational`, `Microsoft-Windows-SMBDirect/Admin`, `Get-SmbServerConfiguration`, `Get-NetAdapterRdma`.
- Compare against the ksmbd source (`drivers/smb` / `fs/smb/server/transport_rdma.c`) when a failure looks like a SUT defect, and quote the line that causes it.

## Known findings (Linux ksmbd vs Windows Server 2025 control)
- ksmbd does not select the RDMA transform context (optional). Tests that need it must `Assume`, not `Assert`.
- Encrypted SMB2 TREE_CONNECT over SMB Direct hangs on ksmbd; the Windows control passes the encryption tests: ksmbd issue.
- ksmbd rejects valid negotiate minimums (MaxReceiveSize=128, MaxFragmentedSize=131072) and does not terminate on invalid data-transfer headers (3.1.5.8).
- ksmbd (kernel 7.0.0-38) answers a negotiate with PreferredSendSize 0 with `MaxFragmentedSize = 0`: it clamps `max_recv_size = min(max_recv_size, preferred_send_size)` then derives `max_fragmented_recv_size = credits * max_recv_size / 2`. SUT defect; the test's floor check is correct.
- An empty Data Transfer message (DataLength 0, RemainingDataLength 0) is a legal credit grant ([MS-SMBD] 3.1.5.4/3.1.5.8): READ-response validators must skip it. Idle/keepalive timers (120 s/5 s) are Windows defaults ([MS-SMBD] Appendix B <4>, <8>): gate timing asserts on `Platform`.
- Windows Server 2025 over RoCE returns STATUS_INVALID_PARAMETER for every V1-family WRITE (`RDMA_V1` and `RDMA_V1_INVALIDATE`, dialects 3.0.2 and 3.1.1) although [MS-SMB2] 3.3.5.13 allows it; those tests are `Inconclusive` for `Platform >= WindowsServer2025`. `BVT_Smb2OverRdma_Smb302_{Read,Write}_SMB2_CHANNEL_RDMA_V1_INVALIDATE` also fail there (Read: client 0xC0000005 mid RDMA write); keep the guards. "V1" is the SMB2 buffer-descriptor version, unrelated to the NDSPI v2 provider API; `RDMANdv2::Bind` succeeds, so do not blame missing memory windows.
- STATUS_INVALID_PARAMETER conditions for transform structures apply only when `Channel == SMB2_CHANNEL_RDMA_TRANSFORM` on 3.1.1 ([MS-SMB2] 3.3.5.13). A client with negotiated RDMATransformIds MUST use RDMA_TRANSFORM ([MS-SMB2] 3.2.4.7).
- `Smb2OverSmbdTestClient` always set `SMB2_FLAGS_SIGNED` on WRITE; `SmbdAdapter.SetWriteRequestSigned(false)` clears it (needed to build the FlagsSignedNotSet scenario).

## Rules for fixing tests (learned the hard way)
- Never turn a timeout/exception into `Assert.Pass` (vacuous pass). Use a real assertion (e.g. reconnect and assert success) or `Assert.Inconclusive` with the reason.
- Platform-specific expectation: gate with `TestConfig.IsWindowsPlatform` / `TestConfig.Platform >= Platform.WindowsServer2025`, not a spec assertion.
- Missing environment (file, NIC) is `Inconclusive`, not a protocol failure.
- After EACH fix: rebuild, run the targeted tests on the Windows control SUT, then the full suite before commit. Run MSBuild without `/m` if you see MSB3030 "could not copy ... not found" (parallel-build race); a rebuild fixes it.
- Keep `Platform` in source and bin ptfconfig consistent with the SUT; reset to `NonWindows` before the Linux run.
- Update `docs/Analysis_*` reports, the Test Design Spec and User Guide when behaviour/descriptions change.

## Gotchas
- PowerShell: never name a function `R` or `H` (aliases). Use `net use ... /REQUIREPRIVACY` to test SMB encryption.
- The ptfconfig is XML-namespaced: use `GetElementsByTagName('Property')`, not `SelectNodes('//Property')`.
- The `edit` tool: if `old_str` spans a neighbouring line, `new_str` must re-include it, or that line is deleted.
- `git push` needs `GIT_TERMINAL_PROMPT=0`; commit messages via file, not here-strings.
- Cleanup: `SmbdTestBase.TestCleanup` -> `DeleteFile.ps1` mounts the share on the driver; "Cannot find path" noise is for files a failed test never created.
