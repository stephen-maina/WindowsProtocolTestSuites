# FileServer SMB2 suite against ksmbd (WORKGROUP) - findings

Run: Windows driver (ConnectX-4 Lx) to in-tree ksmbd (kernel 7.0.0-38, Ubuntu), `Platform=NonWindows`, NTLM, share `SMBDTest`.
Filter: `TestCategory!=DomainRequired & !=HvrsFsa & !=HvrsSmb`.

| Run | Passed | Failed | Not executed |
|---|---|---|---|
| 6 (before fixes) | 44 | 109 | - |
| 8 (after fixes below) | 85 | 102 | 99 (Inconclusive / skipped by applicability) |

The 99 not-executed tests are mostly `SUT does not support compression` (42), `applicable in server` / cluster (31), tests
marked under-development (12), `Assume` on unsupported features (3) and the per-share encryption gate (2).

Evidence per test comes from `Batch\SutDebug\Run-FileServerWithSutLogs.ps1` (driver pcap, SUT dmesg slice per test,
`summary.csv`) and `Batch\SutDebug\Parse-Smb2Pcap.ps1` (SMB2 header decode of the pcap window of a test).
ksmbd debug is enabled only briefly via `/sys/class/ksmbd-control/debug` and left OFF.

## 1. Test / SDK defects fixed

| Test | Problem | Spec | Change |
|---|---|---|---|
| `Encryption_*`, `Compound_Encrypt_*` (SDK) | Encrypted requests carried `SMB2_FLAGS_SIGNED` with a zero signature; ksmbd verified the signature after decrypting and returned `STATUS_ACCESS_DENIED`. | [MS-SMB2] 3.3.5.2.4 (a decrypted message is not signature-verified; SIGNED + not encrypted MUST be verified) | `Smb2Crypto.cs` clears SIGNED on encrypted packets. All `Compound_Encrypt_*` pass. |
| `BVT_Leasing_FileLeasingV1/V2` | Test called `client2.Write` before starting the break-notification task. The lease is RH, the write breaks it to NONE and [MS-SMB2] 3.3.4.7 requires ACK_REQUIRED for any lease other than exactly R, so the write blocks until acked: deadlock. | 3.3.4.7, 3.3.5.9.8 | Start `CheckBreakNotification` before the write. |
| `Leasing_FileLeasingV1/V2_SameLeaseKey` | `Negotiate` generated a new ClientGuid per client, so the two leases were legitimately different and a break was sent. | 3.3.5.9.8 (lookup by ClientGuid + LeaseKey) | `client1`/`client2` share one ClientGuid. |
| `TreeMgmt_SMB311_TREE_CONNECT_EXTENSION_PRESENT` | Windows-only `GetUserSid.ps1`; hangs the run on Linux. | 2.2.9.2 | Inconclusive on non-Windows. |
| `Signing_VerifySignatureWhenEncrypted`, AppInstanceId / MultipleChannel `SHAREFLAG_ENCRYPT_DATA` asserts | Per-share encryption is optional. | 2.2.10 | Gated by `IsPerShareEncryptionSupported` (default true). |

## 2. Configuration / environment (not defects)

| Symptom | Cause | Action |
|---|---|---|
| Durable / lease / persistent tests fail | ksmbd has `durable handles` and `smb2 leases` off by default | `Create-SMB2Env-Linux.sh --enable-durable` |
| Directory leasing tests fail or are skipped | ksmbd advertises `GLOBAL_CAP_DIRECTORY_LEASING` but never grants a directory lease (see section 3) | `IsDirectoryLeasingSupported=false` |
| MultipleChannel* time out / skip | Needs two client IPs on the SUT's subnet | Same-subnet topology, see User Guide 7.4 |
| `MultipleChannel_*` (about 10) still fail | ksmbd reports only the primary address per NIC in `FSCTL_QUERY_NETWORK_INTERFACE_INFO`, so the second SUT address is not discovered | Topology-limited |
| `Replay_PersistentHandle_*`, Clarification (4) | `GeneralFS.contoso.com`, `node01.contoso.com` are cluster names | Cluster-only |
| `DurableHandle*_DifferentDurableOwner` | Needs a second local account (`STATUS_LOGON_FAILURE`) | Create the second user on the SUT |
| `SMBCompressed` | ksmbd has no SMB2 compression | Compression tests are Inconclusive |

## 3. ksmbd defects / limitations (installed 7.0.0-38; tests are spec-correct and kept)

Strings of the installed `ksmbd.ko` show it lacks features present in newer upstream ksmbd (app-instance lookup, notify,
channel sequence). Those rows read "fixed upstream", not "never implemented".

| Test(s) | Evidence | Spec | Verdict |
|---|---|---|---|
| `BVT_Negotiate_SMB2002`, `BVT_Negotiate_Compatible_2002`, `Signing_*Smb2002*`, `DirectoryLeasing_Negative_SMB2002` | `client requested dialect 0x202`, `conn->dialect 0xffff`, returns `STATUS_INSUFFICIENT_RESOURCES`; `server min protocol = SMB2_02` does not help | 3.3.5.4 | ksmbd cannot select 2.0.2 as the only dialect |
| `Negotiate_SMB311_*Context*` (5) | Returns `0xC000009A` instead of `STATUS_INVALID_PARAMETER` | 3.3.5.4 | Installed version; fixed upstream |
| `ValidateNegotiateInfo_Negative_*` (6) | Connection not terminated after a failed validate | 3.3.5.15 | ksmbd defect |
| `AppInstanceId*`, `AppInstanceVersion*` | Re-open returns `STATUS_SHARING_VIOLATION`; module has no app-instance lookup | 3.3.5.9.13 | Installed version; fixed upstream |
| `Replay_*`, `BVT_Replay_*` | No `ChannelSequence` / replay handling | 3.3.5.2.10 | Installed version |
| ChangeNotify (about 16) | All return `STATUS_NOT_IMPLEMENTED`, including negative cases | 3.3.5.19 | Installed version; fixed upstream |
| `Signing_WrongSessionKey_Rejected_*` | Pcap: ECHO with corrupted signature returns SUCCESS | 3.3.5.2.4 | ksmbd defect. Smb311 rows also lack the SIGNING_CAPABILITIES context |
| `DirectoryLeasing_*` | `lease req for(dir)` logged, never granted, no lease context in response | 3.3.5.9.11 | ksmbd defect |
| `BVT_ResilientHandle_*`, `ResilientOpenScavengerTimer_*`, `BVT_Resiliency` | `FSCTL_LMR_REQUEST_RESILIENCY` returns `STATUS_NOT_SUPPORTED` | 3.3.5.15.9 | ksmbd limitation |
| `BVT_SMB2Basic_QueryAndSet_FileInfo` | ChangeTime differs between CREATE and QUERY_INFO with no change | 3.3.5.9, 3.3.5.20.1 | ksmbd defect |
| `FileNormalizedName*` | `STATUS_INVALID_INFO_CLASS` | [MS-FSCC] 2.4.28 | Optional class; candidate for a feature gate |
| `CreateClose_*Symbolic*` | `OBJECT_PATH_NOT_FOUND` instead of `STATUS_STOPPED_ON_SYMLINK` | 3.3.5.9 | ksmbd limitation |
| `BVT_EnumerateSnapShots`, `BVT_SetGetIntegrityInfo`, `BVT_SetZeroData`, `BVT_DuplicateExtentsToFile` | FSCTL not supported on the Linux file system | [MS-FSCC] 2.3 | Optional FSCTLs; Windows file-system features |
| `TreeMgmt_SMB311_COMPRESS_DATA` | `SMBCompressed` share without compression | 2.2.10 | Needs a gate (open) |
| `SessionMgmt_ReconnectWithDifferentDialect` | Re-binding with a different dialect succeeds | 3.3.5.5.3 | ksmbd defect |

## 4. Still to triage (no verdict yet)

`DurableHandleV2_*` returning `STATUS_INVALID_PARAMETER` (`WithLeaseV1AndV2_WithDifferentLeaseKey`,
`Reconnect_WithLeaseV1`, `Reconnect_WithBatchOplock`, `Reconnect_WithoutPersistence`),
`DurableHandleV1_Reconnect_AfterServerDisconnect`, `CreateClose_*DoubleDotDir` (possible Windows-specific expectation),
`CreateClose_DeleteFile_DesiredAccessNotIncludeDeleteOrGenericAll`, `BVT_SMB2Basic_Query_Quota_Info`.
Several verdicts above (FSCTL-based tests, symlink, session re-bind) come from the status code in the run summary and
have not yet been confirmed with pcap and dmesg.

## 5. Notes

* The SUT alias 192.168.20.114 is not persistent across reboot.
* Tuxera runs are blocked on an expired licence.
* Per-test global diagnostics are verified for SMB2. DFSC, RSVD, SQOS, ServerFailover, Auth, FSRVP and FSA are not yet
  verified; FSAModel and SMB2Model use the generated `PtfTestClassBase` and are not wired.
