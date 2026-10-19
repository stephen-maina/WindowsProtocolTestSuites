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
| `BVT_Negotiate_SMB2002`, `Signing_*_Smb2002_*` get `STATUS_INSUFFICIENT_RESOURCES` | ksmbd cannot select 2.0.2 as the sole dialect (see run 7 table); lowering the minimum protocol does not help | ksmbd defect |

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

## Verified with driver pcap + ksmbd debug dmesg (run 7)

| Test(s) | Evidence | Verdict |
|---|---|---|
| `BVT_Negotiate_SMB2002` | Request lists only 0x0202. ksmbd debug: `client requested dialect 0x202`, `conn->dialect 0xffff`, `Server dialect :0xffff not supported`, `Failed to process 0 [-22]` -> `STATUS_INSUFFICIENT_RESOURCES`. Still happens with `server min protocol = SMB2_02`. | ksmbd defect: cannot select 2.0.2 when it is the only dialect offered. The earlier "set min protocol" action was wrong; it does not fix this. |
| `BVT_Encryption_*` (6) | The pcap shows an encrypted request whose inner header has `SMB2_FLAGS_SIGNED` set with a zero signature (`SendSignedRequest=true`; the SDK encrypts and does not sign). ksmbd logs `bad smb2 signature` and returns `STATUS_ACCESS_DENIED`. | Test/SDK defect (spec confirmation of the signed-flag rule still to be recorded). Windows ignores the flag. |
| `BVT_Encryption_PerShareEncryptionEnabled`, `Signing_VerifySignatureWhenEncrypted` | ksmbd only has global `smb3 encryption`; no `SHAREFLAG_ENCRYPT_DATA` per share. | ksmbd limitation; gate the tests on a feature flag. |
| 27 tests (MultipleChannel*, NetworkInterfaceInfo*, AppInstanceId*) | Initially `The requested address is not valid in its context` because `ClientNic1/2IPAddress` were 192.168.1.111/2.111, not driver addresses. With a NIC on another subnet from `SutIPAddress` they time out. With only 192.168.20.111 set, `Assume` skips them (needs two client IPs reachable to the SUT). | Config. Needs two driver IPs on the SUT's subnet (or per-NIC SUT addresses, which the suite does not model). |
| `BVT_Replay_ReplayCreate` | `SutAlternativeIPAddress` was 192.168.2.11 (timeout). With 192.168.10.12 it connects and then fails on `Smb2CreateDurableHandleResponseV2` missing. | Config, then ksmbd limitation (durable V2 not granted). |
| `AppInstanceVersion_*`, `Negative_AppInstanceVersion_*` | Re-open with same AppInstanceId returns `STATUS_SHARING_VIOLATION` (0xC0000043); the previous open is never closed. | ksmbd gap: `SMB2_CREATE_APP_INSTANCE_ID` not implemented ([MS-SMB2] 3.3.5.9.13). |
| `MS_SMB2_Clarification`, `MS_FSA_Clarification` (4) | `Cannot resolve node01.contoso.com` | Cluster-only config. |
| `ResilientHandle*` (5) | `FSCTL_LMR_REQUEST_RESILIENCY` returns `STATUS_NOT_SUPPORTED` | ksmbd gap. |
| ChangeNotify (7 more) | CREATE returns `STATUS_ACCESS_DENIED`/`OBJECT_NAME_NOT_FOUND` during setup (streams / ACL setup) | Not yet triaged to root cause. |

## Next steps

* Fix the SIGNED flag on encrypted requests and gate per-share encryption, then re-run `Encryption`.
* Triage the remaining groups (ChangeNotify setup, `0xC000000D`/`0xC000009A` negotiate-context group, `Signing_WrongSessionKey`, symlink, ValidateNegotiateInfo) against pcap and dmesg before changing any test.
