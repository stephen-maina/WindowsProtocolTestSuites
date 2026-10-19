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
| `DirectoryLeasing_*` (`DirectoryLeasingExtendedTest`) | No applicability gate; ran with `IsDirectoryLeasingSupported=false`. | 2.2.4 GLOBAL_CAP_DIRECTORY_LEASING | `TestCleanup`-adjacent init now calls `CheckCapabilities`; Inconclusive when unsupported (verified in `tri13`). |
| `BVT_SMB2Basic_Query_FileNormalizedNameInformation_*` | `STATUS_INVALID_INFO_CLASS` treated as failure. | 3.3.5.20.1 | Inconclusive like `STATUS_NOT_SUPPORTED`. |
| `BVT_SMB2Basic_Query_Quota_Info` | IP-address `DomainName` passed the domain regex, then hit LDAP. | n/a (environment) | IP address is treated as non-domain: Inconclusive. |
| `TreeMgmt_SMB311_COMPRESS_DATA` | Ran without compression support. | 2.2.10 | `CheckCompressionAlgorithm()` gate: Inconclusive. |
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

## 4. Triage of the previously open items (run `tri9`, ksmbd debug dmesg + pcap)

| Test(s) | Evidence | Spec | Verdict |
|---|---|---|---|
| `DurableHandleV2_Reconnect_*` (`WithoutPersistence`, `WithBatchOplock`, `WithLeaseV1`, `WithLeaseV1AndV2_WithDifferentLeaseKey`) | Pcap: DH2C context is well formed (Next=0x40, DataOffset=0x18, DataLength=0x24, CreateGuid matches the DH2Q). dmesg: `error parsing durable handle context`, no lookup message. Upstream v7.0 `parse_durable_handle_context` rejects the context when `DataOffset + DataLength < sizeof(struct create_durable_handle_reconnect_v2)`, and that struct includes `Pad[4]` (64 bytes) while the context is 60 bytes. | 2.2.13.2.12, 3.3.5.9.12 | **ksmbd defect**: every DH2C reconnect returns `STATUS_INVALID_PARAMETER`. Newer ksmbd compares against `sizeof(dcontext)`. Tests are correct and kept. |
| `DurableHandleV1_Reconnect_WithDifferentDurableOwner` | With `nonadmin` created (`Create-SMB2Env-Linux.sh --second-user nonadmin`) the logon works. dmesg: `Durable handle reconnect failed: owner mismatch`, response `STATUS_OBJECT_NAME_NOT_FOUND` (0xC0000034) | 3.3.5.9.7 requires `STATUS_ACCESS_DENIED` | Config fixed; **ksmbd defect** |
| `DurableHandleV2_Reconnect_WithDifferentDurableOwner` | Same account; returns 0xC000000D, the DH2C parse defect above | 3.3.5.9.12 | ksmbd defect |
| `DurableHandleV1_Reconnect_AfterServerDisconnect` | Negotiate after create is answered instead of disconnecting | 3.3.5.4 | ksmbd limitation |
| `CreateClose_CreateAndCloseFileWithDoubleDotDir` | `x\..\y` is accepted; the spec describes `STATUS_INVALID_PARAMETER` as Windows-based server behavior | 3.3.5.9, [MS-FSCC] 2.1.5.1 | **Test defect, fixed**: assertion applies only when `Platform` is not `NonWindows`. Passes on ksmbd. |
| `CreateClose_DeleteFile_DesiredAccessNotIncludeDeleteOrGenericAll` | Server returns success; the spec says SHOULD fail with `STATUS_ACCESS_DENIED` | 3.3.5.9 (SHOULD) | ksmbd limitation (optional behavior) |
| `CreateClose_SymbolicLinkAtLast`, `CreateClose_InvalidSymbolicLink` | `STATUS_ACCESS_DENIED` / `STATUS_INVALID_PARAMETER` instead of `STATUS_STOPPED_ON_SYMLINK` | 3.3.5.9 | ksmbd limitation (Linux symlinks are not NTFS reparse points) |
| `BVT_SMB2Basic_Query_FileNormalizedNameInformation_DataFile` | `STATUS_INVALID_INFO_CLASS` | [MS-FSCC] 2.4.28 | ksmbd limitation (optional class) |
| `SessionMgmt_ReconnectWithDifferentDialect` | Re-bind with a different dialect returns SUCCESS | 3.3.5.5.3 | ksmbd defect |
| `BVT_SMB2Basic_Query_Quota_Info` | Test opens an LDAP connection (`Connect Error`) | n/a | Domain-only; not runnable in WORKGROUP |

| `BVT_EnumerateSnapShots` | dmesg: `not implemented yet ioctl command 0x144064` (FSCTL_SRV_ENUMERATE_SNAPSHOTS) -> `STATUS_NOT_SUPPORTED` | [MS-SMB2] 3.3.5.15.1 | ksmbd limitation (optional) |
| `BVT_SetGetIntegrityInfo` | dmesg: `not implemented yet ioctl command 0x9027c` (FSCTL_GET_INTEGRITY_INFORMATION) | [MS-FSCC] 2.3.29 | ksmbd limitation (ReFS feature) |
| `BVT_SetZeroData`, `BVT_DuplicateExtentsToFile` | Fail before any SMB traffic: `Cannot resolve node01.contoso.com` | n/a | Config: cluster-only FSA clarification tests |

`TreeMgmt_SMB311_COMPRESS_DATA` remains a verdict from the status code only.

## 5. Notes

* The SUT alias 192.168.20.114 is not persistent across reboot.
* Tuxera runs are blocked on an expired licence.
* Per-test diagnostics are wired and verified for all ten collections: SMB2, DFSC, RSVD, SQOS, Auth, ServerFailover and
  FSRVP through `CommonTestBase`; FSA, FSAModel and SMB2Model through `FileServerPtfTestClassBase`.
* `capture.etl` holds SMB traffic (SMB2 headers, encrypted transform headers). It is an NDIS packet capture; read it with
  `pktmon etl2txt capture.etl --hex`. RDMA data bypasses NDIS and is not captured.
* `Parse-Smb2Pcap.ps1 -HexCommand <n>` dumps the first 512 bytes of each packet of that SMB2 command.
## 6. Specification coverage audit (spec requirements with no test)

Every SMB2 test method now carries a `// SPEC: [MS-SMB2] <section> - <requirement>` comment (about 270 methods). Comments
were derived from each test's scenario; sections marked unverified below were not re-read on MS Learn and should be
spot-checked. Gaps were found by grepping `SMB2\TestSuite`, `FSA\TestSuite` and `SMB2Model` (generated files excluded).

**Documented in the Test Design Spec but no method in code (13):** `BVT_Leasing_LeaseState_DowngradeNotAllowed`,
`..._PartialOverlapRequest_NotDowngrade`, `..._UpgradeOnSupersetRequest`, `BVT_Leasing_CreateDuringLeaseBreak_SameLeaseKey_NotBlocked`
(each with a V2 variant), `BVT_Leasing_WriteCache_BreakOnIncompatibleShareMode`, `..._BreakOnReadDataAccess`,
`..._BreakOnWriteDataAccess`, `..._NoBreakOnReadControl` (+V2). Spec: 3.3.5.9.8, 3.3.5.9.11, 3.3.4.7.

**Spec requirements with no test (all MUST unless noted):**

| Area | Gap |
|---|---|
| NEGOTIATE 3.3.5.4 | Duplicate NEGOTIATE (disconnect); DialectCount 0; no common dialect (`STATUS_NOT_SUPPORTED`); duplicate ENCRYPTION/COMPRESSION/RDMA_TRANSFORM/SIGNING/PREAUTH contexts; short PREAUTH/ENCRYPTION DataLength; unknown contexts ignored; response SecurityMode/ClientGuid echo |
| SESSION_SETUP 3.3.5.5 | Unknown non-zero SessionId (`STATUS_USER_SESSION_DELETED`); binding negatives; unsigned setup when signing required; SessionFlags result |
| Encryption/signing 3.3.5.2.1.1, 3.3.5.2.4 | Malformed transform header, bad algorithm, unknown SessionId, tampered signature; unencrypted request on encrypted share; unsigned request when signing required |
| Compression 3.3.5.2.1.2 | Short header, oversize OriginalCompressedSegmentSize, corrupt payload, compression not negotiated |
| TREE_CONNECT/DISCONNECT/CLOSE | Nonexistent share (`STATUS_BAD_NETWORK_NAME`); request on disconnected TreeId (`STATUS_NETWORK_NAME_DELETED`); CLOSE POSTQUERY_ATTRIB; closed FileId (`STATUS_FILE_CLOSED`) |
| CREATE contexts 2.2.13.2.x | MxAc, QFid, AlSi, ExtA, TWrp not exercised; DesiredAccess 0 (SHOULD) |
| IOCTL 3.3.5.15 | Non-FSCTL flag (`STATUS_NOT_SUPPORTED`); unknown FSCTL; wrong FileId for DFS/QUERY_NETWORK_INTERFACE_INFO/VALIDATE_NEGOTIATE_INFO; copychunk and resume key; pipe FSCTLs; MaxTransactSize limits (SHOULD); resiliency on non-durable open |
| ECHO/CANCEL/FLUSH/READ/WRITE/LOCK | Standalone ECHO; cancel of pending LOCK/IOCTL; interim async responses; WRITE_THROUGH/UNBUFFERED; RDMA channel flags; read/write limits; unlock of unlocked range (`STATUS_RANGE_NOT_LOCKED`) |
| QUERY_DIRECTORY/QUERY_INFO | `SMB2_INDEX_SPECIFIED`; `SMB2_0_INFO_SECURITY` |
| Compound | Failure propagation in a related chain; invalid FileId in related request; padding/alignment; async compound |
| OpLock | Level 2 / exclusive, break-to-none, invalid ack, ForceLevel2 |

Not counted as gaps: optional features the server may lack, Windows-only behaviour, printer-share CREATE (not testable on a
disk share). The earlier explore-agent list of 25 candidates was replaced by this verified list. One existing assert message in
`CompressionTest.cs` (~line 488) cites section 3.3.5.2.13; the correct reference is 3.3.5.2.1.2 / 3.3.7.1.
