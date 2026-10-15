# FileServer SMB2 suite against ksmbd (WORKGROUP) - findings

Run: Windows driver (ConnectX-4 Lx) to ksmbd 7.0.0-38 on Linux, `Platform=NonWindows`, NTLM, share `SMBDTest`.
Filter: `TestCategory!=DomainRequired & !=HvrsFsa & !=HvrsSmb`, excluding the hang described below.
Result (runs 4 and 5, identical): 44 passed, 109 failed, 131 not executed (Inconclusive / skipped by applicability).
Evidence per test is produced by `Batch\SutDebug\Run-FileServerWithSutLogs.ps1` (pktmon capture, SUT dmesg slice
per test, `summary.csv`, `results.trx`) and, when `SutLog.Enabled`/`Diagnostics.Enabled` are true, by the shared
per-test diagnostics (`capture.etl`, `ptf-log.ndjson`, `sut-linux-dmesg.log` in each test folder).

## Test defects fixed

| Test | Problem | Change |
|---|---|---|
| `TreeMgmt_SMB311_TREE_CONNECT_EXTENSION_PRESENT` | Calls the Windows-only `GetUserSid.ps1` adapter script and needs a clustered infrastructure share. On a Linux SUT the script never returns and the whole run hangs. | Reports Inconclusive when the SUT is not a Windows platform (WHAT/WHY/SPEC comment in the test; Test Design Spec updated). |

## Configuration / environment (not defects)

| Symptom | Cause | Action |
|---|---|---|
| 13 negotiate checks missing `GLOBAL_CAP_LEASING` | ksmbd advertises only LARGE_MTU and MULTI_CHANNEL; config claimed leasing | `IsLeasingSupported`, `IsDirectoryLeasingSupported`, `IsPersistentHandlesSupported` = false for ksmbd |
| `TreeConnect` `STATUS_ACCESS_DENIED` (BVT_Encryption_*), `TreeMgmt_SMB311_COMPRESS_DATA` | Shares `SMBEncrypted` / `SMBCompressed` do not exist on the SUT | Create shares or blank the properties |
| `Replay_PersistentHandle_*` | Needs cluster DNS name `GeneralFS.contoso.com` | Cluster-only |
| MultipleChannel* | Second client/SUT NIC IPs not configured | Configure `ClientNic2IPAddress` etc. |
| `BVT_Negotiate_SMB2002`, `Signing_*_Smb2002_*` get `STATUS_INSUFFICIENT_RESOURCES` | ksmbd default minimum protocol is SMB 2.1 | Set `server min protocol = SMB2_02` in ksmbd.conf to exercise 2.0.2 |

## Probable ksmbd defects (test is spec-correct, kept as is)

| Test | Observation | Specification |
|---|---|---|
| `BVT_SMB2Basic_QueryAndSet_FileInfo` | ChangeTime in the CREATE response (`08:51:50.115282`) differs from QUERY_INFO on the same open (`08:51:50.116886`) with no modification in between | [MS-SMB2] 3.3.5.9 / 3.3.5.20.1: both report Open.File.LastChangeTime |
| `Signing_WrongSessionKey_Rejected_*` | Server accepts a request signed with a wrong key (SUCCESS) | [MS-SMB2] 3.3.5.2.4: MUST fail with `STATUS_ACCESS_DENIED` (Smb311 rows additionally need the 3.1.1 signing-capabilities context) |
| `BVT_SMB2Basic_ChangeNotify_ChangeEa` (+8 siblings) | CHANGE_NOTIFY returns `STATUS_NOT_IMPLEMENTED` for EA changes | [MS-SMB2] 3.3.5.19 |
| `BVT_SMB2Basic_Query_FileNormalizedNameInformation_*` | `STATUS_INVALID_INFO_CLASS` | [MS-FSCC] 2.4.28 (optional class; consider gating on a feature flag) |
| `CreateClose_SymbolicLinkInMiddle`, `_InvalidSymbolicLink` | Returns `STATUS_OBJECT_PATH_NOT_FOUND` instead of `STATUS_STOPPED_ON_SYMLINK` | [MS-SMB2] 3.3.5.9 |
| `ValidateNegotiateInfo_Negative_InvalidDialects_*` | Connection not terminated | [MS-SMB2] 3.3.5.15 |
| Durable/Leasing/Replay tests (11 still failing after flags aligned) | `SMB2_CREATE_DURABLE_HANDLE_RESPONSE` never returned | Durable V1 not granted by ksmbd; tests need a feature flag gate (open item) |

## Next steps

* Create the encrypted/compressed shares and the NIC settings, then re-run the Config rows.
* Review remaining failing groups individually against the pcap and per-test dmesg before changing any test.
