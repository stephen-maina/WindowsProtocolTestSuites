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

## Known findings (Linux ksmbd vs Windows Server 2025 control)
- ksmbd does not select the RDMA transform context (optional). Tests that need it must `Assume`, not `Assert`.
- Encrypted SMB2 TREE_CONNECT over SMB Direct hangs on ksmbd; the Windows control passes the encryption tests: ksmbd issue.
- ksmbd rejects valid negotiate minimums (MaxReceiveSize=128, MaxFragmentedSize=131072) and does not terminate on invalid data-transfer headers (3.1.5.8).
- `BVT_Smb2OverRdma_Smb302_{Read,Write}_SMB2_CHANNEL_RDMA_V1_INVALIDATE` fail even on Server 2025 over RoCE (NDSPI memory windows); they are guarded with `Inconclusive`.

## Gotchas
- PowerShell: never name a function `R` or `H` (aliases). Use `net use ... /REQUIREPRIVACY` to test SMB encryption.
- `git push` needs `GIT_TERMINAL_PROMPT=0`; commit messages via file, not here-strings.
- Cleanup: `SmbdTestBase.TestCleanup` -> `DeleteFile.ps1` mounts the share on the driver; "Cannot find path" noise is for files a failed test never created.
