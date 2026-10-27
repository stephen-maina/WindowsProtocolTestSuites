# FileServer SMB2 – Specification of Missing Tests

**Purpose.** Design specification for tests that [MS-SMB2] requires or that the Test Design Spec documents, but that the
test suite does not implement. These are **test suite gaps**, not SUT (ksmbd) defects. Nothing here is to be added to or
worked around in ksmbd. Each entry is implementable against any compliant server (Windows or non-Windows).

**Source.** Historical coverage-audit inventory; the implementation-specific source analysis has been withdrawn.
This is not a current coverage assessment. Section numbers, MUST/SHOULD/MAY levels and status
codes below were re-read on MS Learn. Items that could not be retrieved are marked **(locate)**: look the section up
under 3.3.5.9 / 3.3.5.15 in the spec index before implementing.

**Conventions for implementation.**
- Place in the existing test class for the area; name `[Category]_[Protocol]_[Scenario]`; add a `// SPEC:` comment citing the section.
- Optional features: gate with `CheckCapabilities` / `CheckSigningAlgorithm` / `CheckCompressionAlgorithm` (Inconclusive).
- SHOULD, MAY or Windows-specific behaviour: assert only under `Platform.WindowsServer`, otherwise log.
- Update `FileServerTestDesignSpecification.md` and the User Guide when a test is added.
- Priority: **P1** = MUST with security/interop impact; **P2** = MUST, other; **P3** = SHOULD or low risk.

## References (MS Learn)

Base URL: `https://learn.microsoft.com/openspecs/windows_protocols/ms-smb2/<id>`. Guessed ids fail; use these.

| Section | Title | `<id>` |
|---|---|---|
| 2.2.2.2.1 | Symbolic link error response | f15ae37d-a787-4bf2-9940-025a8c9c0022 |
| 2.2.41 | TRANSFORM_HEADER | d6ce2327-a4c9-4793-be66-7b5bad2175fa |
| 2.2.42 | COMPRESSION_TRANSFORM_HEADER | 1d435f21-9a21-4f4c-828e-624a176cf2a0 |
| 3.1.5.1 | Verifying an incoming message (client) | 5b570c0b-0854-4324-8fb5-d410692dde3e |
| 3.3.4.6 | Object store indicates an oplock break | 2a09fc40-1615-42df-bda6-2865b8d6da95 |
| 3.3.4.7 | Object store indicates a lease break | c367fad4-c00f-4778-913d-c0560ead1360 |
| 3.3.5.2 | Receiving any message | ef8e06ba-c921-46c9-9780-a2e9843e1d30 |
| 3.3.5.2.1.1 | Decrypting the message | 94398d18-48ff-4b6c-a32d-0154b2e88238 |
| 3.3.5.2.1.2 | Decompressing the message | eacbd2d4-4383-4ea3-b9d9-c8ba9f5c9ff4 |
| 3.3.5.2.4 | Verifying the signature | 85df1680-2ee7-4d25-a916-a982371ddc75 |
| 3.3.5.2.9 | Verifying the session | b495e2da-8711-4772-b292-453be0394b49 |
| 3.3.5.2.11 | Verifying the tree connect | 9a639360-87be-4d49-a1dd-4c6be0c020bd |
| 3.3.5.4 | NEGOTIATE | b39f253e-4963-40df-8dff-2f9040ebbeb1 |
| 3.3.5.5 | SESSION_SETUP | e545352b-9f2b-4c5e-9350-db46e4f6755e |
| 3.3.5.5.1 / .2 / .3 | Session setup sub-sections | ea10b7ae-b053-4e4c-ab31-a48f7d0a79af / 5ecc02fb-0e60-4cba-afeb-f13100a6e65e / 5ed93f06-a1d2-4837-8954-fa8b833c2654 |
| 3.3.5.7 | TREE_CONNECT | 652e0c14-5014-4470-999d-b174d7b2da87 |
| 3.3.5.9 | CREATE | 8c61e928-9242-44ed-96a0-98d1032d0d39 |
| 3.3.5.9.5 | MxAc create context | 828a4d2d-0c9b-4c1c-8d2b-cc474172baa5 |
| 3.3.5.9.8 | RqLs (lease V1) create context | 24cfce29-5d80-4651-ba5f-a2661c666b41 |
| 3.3.5.10 | CLOSE | f2b4183a-29c2-4fc0-a5de-fe290408f68c |
| 3.3.5.11 | FLUSH | 026984f6-38af-4408-8200-50557eb0a286 |
| 3.3.5.12 | READ | 21e8b343-34e9-4fca-8d93-03dd2d3e961e |
| 3.3.5.13 | WRITE | 829f93f5-ed10-4f12-8347-42d235019459 |
| 3.3.5.14 (.1 unlock / .2 lock) | LOCK | a2f8b1cc-ebe0-4378-9da9-4e25de5c628f (79eb3c91-563b-4d48-a51c-0974f9d144f8 / 670c7eda-e683-4923-9477-414303959613) |
| 3.3.5.15 | IOCTL | c348a671-7750-49f8-9e61-cc59fa1a5701 |
| 3.3.5.16 | CANCEL | 57bae3d3-5dd7-4a5f-92cb-fc52e2087dad |
| 3.3.5.17 | ECHO | fa23e613-2768-49e5-aa68-97c4bba72379 |
| 3.3.5.18 | QUERY_DIRECTORY | 29dfcc9b-3aec-406b-abb5-0b4fe96712e2 |
| 3.3.5.20 / .1 | QUERY_INFO / info-file | abb48417-27e5-4a16-82e0-3e5981db97e8 / d64e0451-64a2-425a-848e-52a7dddab7b9 |
| 3.3.5.20.3 | SMB2_0_INFO_SECURITY | d03767e7-c799-45c9-8fa0-7bde4f2fb0f2 |
| 3.3.5.22 / .1 / .2 | Oplock/lease acknowledgment | d3c7cf4b-7399-46a2-92fd-77fbdd9b34d5 / 90f21fc9-3094-4d29-842d-55e9aeaf1d05 / 0ccd85cd-5e1d-4dc2-9698-71b4c87c0cec |
| 3.3.7.1 | Connection disconnect | eb5bfe99-47fe-4e87-8e87-08a084dcefb6 |
| Appendix A | Product behavior notes `<n>` | a64e55aa-1152-48e4-8206-edd96444e7f7 |

Related specs: [MS-FSA] 2.1.5.9 byte-range unlock (`ms-fsa/84e68de6-31a6-4cba-afd4-00b1bac6d1a2`); [MS-ERREF] NTSTATUS values
(`ms-erref/1bc92ddf-b79e-413c-bbaa-99a5281a6c90`); [MS-FSCC] 2.4 file information classes.

## A. Documented in the Test Design Spec, no method in code

Lease state rules: 3.3.5.9.8 (V1) and its V2 counterpart 3.3.5.9.11 (same rules, adds ParentLeaseKey/Epoch). Break
mechanics: 3.3.4.7. Break ack: 3.3.5.22.2 (`STATUS_UNSUCCESSFUL` if not breaking; `STATUS_REQUEST_NOT_ACCEPTED` if the acked
state is not a subset of BreakToLeaseState; `STATUS_OBJECT_NAME_NOT_FOUND` if the lease is unknown).

| ID | Test (V2 variant also needed unless noted) | Spec | Scenario / pass criteria | Pri |
|---|---|---|---|---|
| A1 | `BVT_Leasing_LeaseState_DowngradeNotAllowed` (+V2) | 3.3.5.9.8: if the requested state is not a superset of Lease.LeaseState, or Lease.Breaking is TRUE, the server MUST NOT promote | Open with RWH; reopen same LeaseKey requesting a lower state. Response LeaseState remains the held state. | P2 |
| A2 | `BVT_Leasing_PartialOverlapRequest_NotDowngrade` (+V2) | 3.3.5.9.8, 3.3.5.9.11 | Establish RH with no break pending; use the same ClientGuid and LeaseKey to request RW (not a superset). Server MUST NOT promote the lease: the state remains RH, not the union RWH. | P2 |
| A3 | `BVT_Leasing_UpgradeOnSupersetRequest` (+V2) | 3.3.5.9.8, 3.3.5.9.11 | Establish R with no break pending; use the same ClientGuid and LeaseKey to request RWH. Server MUST request promotion from the object store. If that promotion succeeds, the state MUST become RWH; without independently established store success, do not require an unconditional RWH grant. | P2 |
| A4 | `BVT_Leasing_CreateDuringLeaseBreak_SameLeaseKey_NotBlocked` (+V2) | 3.3.5.9.8 (Lease.Breaking TRUE: server returns the existing LeaseState with SMB2_LEASE_FLAG_BREAK_IN_PROGRESS), 3.3.4.7 | While a break is pending, CREATE with the same LeaseKey completes without waiting for the ack; response has BREAK_IN_PROGRESS and existing state. | P2 |
| A5 | `BVT_Leasing_WriteCache_BreakOnIncompatibleShareMode` (+V2) | 3.3.4.7 (notification fields: ACK_REQUIRED flag, CurrentLeaseState, NewLeaseState), [MS-FSA] 2.1.5.1 | A holds RWH; B opens with incompatible ShareAccess. A gets a break; B completes after ack. | P2 |
| A6 | `BVT_Leasing_WriteCache_BreakOnReadDataAccess` (+V2) | 3.3.4.7 | A holds RWH; B opens FILE_READ_DATA. A is broken to drop Write caching. | P2 |
| A7 | `BVT_Leasing_WriteCache_BreakOnWriteDataAccess` (+V2) | 3.3.4.7 | A holds RWH; B opens FILE_WRITE_DATA. A is broken. | P2 |
| A8 | `BVT_Leasing_WriteCache_NoBreakOnReadControl` (+V2) | 3.3.4.7 | A holds RWH; B opens READ_CONTROL only. No break (wait, assert none). | P2 |

The existing `Leasing_FileLeasingV1_SameLeaseKey` and `Leasing_FileLeasingV2_SameLeaseKey` methods exercise equal-state RWH reopens with the same ClientGuid and LeaseKey. They do not implement A2/A3 or the pending-break branch in A4; those scenarios remain planned, not covered by the equal-state tests.

## B. Spec requirements with no test

### B1. NEGOTIATE (3.3.5.4)
| ID | Scenario | Pass criteria | Pri |
|---|---|---|---|
| B1.1 | Second NEGOTIATE on a connection whose NegotiateDialect is set | MUST disconnect | P1 |
| B1.2 | DialectCount = 0 | MUST `STATUS_INVALID_PARAMETER` | P2 |
| B1.3 | No common dialect | `STATUS_NOT_SUPPORTED` | P2 |
| B1.4 | 3.1.1: zero or more than one PREAUTH context; more than one ENCRYPTION, COMPRESSION, RDMA_TRANSFORM or SIGNING context | `STATUS_INVALID_PARAMETER` | P2 |
| B1.5 | PREAUTH DataLength too short, ENCRYPTION or SIGNING too short, SigningAlgorithmCount 0 (INVALID_PARAMETER; ENCRYPTION is ignored if encryption unsupported); no PREAUTH hash overlap | INVALID_PARAMETER; `STATUS_SMB_NO_PREAUTH_INTEGRITY_HASH_OVERLAP` (0xC05D0000) | P2 |
| B1.6 | Unknown context type or NETNAME | Ignored; NEGOTIATE succeeds | P3 |
| B1.7 | Response SecurityMode | SIGNING_ENABLED set; SIGNING_REQUIRED set iff the server requires signing | P3 |

### B2. SESSION_SETUP (3.3.5.5, .1, .2, .3)
| ID | Scenario | Pass criteria | Pri |
|---|---|---|---|
| B2.1 | Non-zero SessionId unknown to the server (non-binding) | `STATUS_USER_SESSION_DELETED` | P2 |
| B2.2 | Binding negatives (3.3.5.5.2 steps 4.1.x): dialect mismatch; SIGNED flag missing; ClientGuid mismatch (MAY `USER_SESSION_DELETED`); session InProgress or already on this connection; anonymous/guest session; username mismatch; SupportsNotifications mismatch; bad signature (3.3.5.2.4) | INVALID_PARAMETER; INVALID_PARAMETER; (MAY) USER_SESSION_DELETED; `STATUS_REQUEST_NOT_ACCEPTED`; `STATUS_NOT_SUPPORTED`; `STATUS_NOT_SUPPORTED`; INVALID_PARAMETER; `STATUS_ACCESS_DENIED`. Expired session: `STATUS_NETWORK_SESSION_EXPIRED`. Binding on 2.0.2/2.1 or a non-multichannel server: SHOULD REQUEST_NOT_ACCEPTED | P1 |
| B2.3 | Signed session: unsigned request | `STATUS_ACCESS_DENIED` (3.3.5.2.4); MAY disconnect | P1 |
| B2.4 | EncryptData and RejectUnencryptedAccess, client lacks encryption capability | `STATUS_ACCESS_DENIED` (3.3.5.5 steps 1-2) | P2 |

### B3. Encryption and signing
| ID | Scenario | Spec | Pass criteria | Pri |
|---|---|---|---|---|
| B3.1 | Malformed TRANSFORM_HEADER (size <= header, Flags or EncryptionAlgorithm != 0x0001) | 3.3.5.2.1.1, 2.2.41 | MUST disconnect | P1 |
| B3.2 | TRANSFORM_HEADER with unknown SessionId | 3.3.5.2.1.1 | MUST disconnect | P1 |
| B3.3 | Tampered ciphertext or transform signature (decrypt failure) / tampered SMB2 Signature | 3.3.5.2.1.1; 3.3.5.2.4 | Disconnect (MUST) / `STATUS_ACCESS_DENIED` (MAY disconnect) | P1 |
| B3.4 | Unencrypted request on an encrypted session or EncryptData share | 3.3.5.2.9 step 2; 3.3.5.2.11 cases 1-2 (conditions differ by dialect) | `STATUS_ACCESS_DENIED` | P1 |
| B3.5 | Unsigned request when signing is required | 3.3.5.2.4 | `STATUS_ACCESS_DENIED` | P1 |
| B3.6 | OriginalMessageSize mismatch; nested SessionId != TransformSessionId; misaligned compound in an encrypted message | 3.3.5.2.1.1 (8.1.1.x / 8.2.1.x) | SHOULD / MUST disconnect | P2 |

### B4. Compression (3.3.5.2.1.2, 2.2.42) — all MUST disconnect when compression is supported and CompressionIds is non-empty
| ID | Scenario | Pass criteria | Pri |
|---|---|---|---|
| B4.1 | Message shorter than the compression header | Disconnect | P2 |
| B4.2 | OriginalCompressedSegmentSize > 256 + header + max(MaxRead, MaxWrite, MaxTransact); chained Pattern_V1 with Repetitions > original size (3.1.5.3) | Disconnect | P2 |
| B4.3 | Decompression failure; decompressed size != OriginalCompressedSegmentSize; decompressed ProtocolId != 0x424D53FE | Disconnect | P2 |
| B4.4 | Algorithm (or chained algorithm) not negotiated | Disconnect. Compression-not-negotiated at all is NOT specified: gate or log only | P2 |

### B5. TREE_CONNECT / CLOSE
| ID | Scenario | Spec | Pass criteria | Pri |
|---|---|---|---|---|
| B5.1 | Nonexistent share; malformed path; access not granted; MaxUses exceeded | 3.3.5.7 | `STATUS_BAD_NETWORK_NAME`; INVALID_PARAMETER; ACCESS_DENIED; REQUEST_NOT_ACCEPTED | P2 |
| B5.2 | Request on a TreeId with no tree connect | 3.3.5.2.11 | `STATUS_NETWORK_NAME_DELETED` | P2 |
| B5.3 | CLOSE with POSTQUERY_ATTRIB (and without) | 3.3.5.10 | Flags = 0x0001 and valid attributes; without the flag attributes are 0 and Flags = 0 | P2 |
| B5.4 | READ, WRITE, LOCK, IOCTL, QUERY_INFO, oplock ack, CLOSE on closed or unknown FileId | 3.3.5.10/.12/.13/.14/.15/.20/.22 | `STATUS_FILE_CLOSED` | P2 |

### B6. CREATE (3.3.5.9)
| ID | Scenario | Spec | Pass criteria | Pri |
|---|---|---|---|---|
| B6.1 | `MxAc` with no timestamp; with timestamp equal to ChangeTime | 3.3.5.9.5 | Maximal access returned; equal-timestamp gives QueryStatus `STATUS_NONE_MAPPED`, MaximalAccess 0 | P2 |
| B6.2 | `QFid` request | 3.3.5.9.x **(locate)**, 2.2.13.2.9 | Response QFid context with a 32-byte on-disk id | P2 |
| B6.3 | `AlSi` allocation size | 3.3.5.9.x **(locate)** | Honoured or ignored per spec | P3 |
| B6.4 | `ExtA` extended attributes | 3.3.5.9.x **(locate)**; `STATUS_EAS_NOT_SUPPORTED` if unsupported | EAs readable via QUERY_INFO, else the status | P3 |
| B6.5 | `TWrp` timewarp | 3.3.5.9.x **(locate)** | Gate on snapshot support; bad token `STATUS_OBJECT_NAME_NOT_FOUND` | P3 |
| B6.6 | DesiredAccess = 0; DELETE_ON_CLOSE without DELETE | 3.3.5.9 | DELETE_ON_CLOSE without DELETE: SHOULD `STATUS_ACCESS_DENIED` (log on non-Windows) | P3 |
| B6.7 | NameLength odd/beyond request; context NameLength < 4 or DataLength mismatch | 3.3.5.9 | `STATUS_INVALID_PARAMETER` | P2 |
| B6.8 | Pipe open with Delegate impersonation | 3.3.5.9 | `STATUS_BAD_IMPERSONATION_LEVEL` | P3 |

### B7. IOCTL (3.3.5.15)
| ID | Scenario | Pass criteria | Pri |
|---|---|---|---|
| B7.1 | Flags != SMB2_0_IOCTL_IS_FSCTL | MUST `STATUS_NOT_SUPPORTED` | P2 |
| B7.2 | Unknown FSCTL | **SHOULD**: `STATUS_NOT_SUPPORTED` if not allowed, `STATUS_INVALID_DEVICE_REQUEST` if allowed but unsupported by the file system. Accept either; assert only on Windows | P3 |
| B7.3 | FileId != 0xFFFFFFFFFFFFFFFF for DFS_GET_REFERRALS, DFS_GET_REFERRALS_EX, QUERY_NETWORK_INTERFACE_INFO, VALIDATE_NEGOTIATE_INFO, **PIPE_WAIT** | MUST `STATUS_INVALID_PARAMETER` | P2 |
| B7.4 | COPYCHUNK / SRV_REQUEST_RESUME_KEY limits, invalid key, zero chunks | Section **(locate)** under 3.3.5.15.x; read for exact statuses | P2 |
| B7.5 | Pipe FSCTLs (PIPE_TRANSCEIVE, PIPE_WAIT) | Section **(locate)** under 3.3.5.15.x | P3 |
| B7.6 | InputCount, MaxInputResponse or MaxOutputResponse > MaxTransactSize (SHOULD INVALID_PARAMETER); output never exceeds MaxOutputResponse (store BUFFER_OVERFLOW -> `STATUS_BUFFER_OVERFLOW`); InputOffset/InputCount bounds violations (not multiple of 8, past message end, inside header: MUST INVALID_PARAMETER); shared-VHD FSCTLs when unsupported: INVALID_DEVICE_REQUEST | See left | P2 |
| B7.7 | FSCTL_LMR_REQUEST_RESILIENCY converts a non-durable open | With SMB 2.1/3.x, supported resiliency, a valid open and sufficient input with an allowed Timeout, require a successful response and resilient-open behavior per 3.3.5.15.9. Prior durability is not required: Open.IsDurable becomes FALSE and Open.IsResilient becomes TRUE. Unsupported-feature and malformed-input cases are separate branches. | P3 |

### B8. ECHO / CANCEL / FLUSH / READ / WRITE / LOCK
| ID | Scenario | Spec | Pass criteria | Pri |
|---|---|---|---|---|
| B8.1 | Standalone ECHO (signed, and unsigned with SessionId 0); empty session table | 3.3.5.17 | SUCCESS (or INVALID_PARAMETER); empty session table: SHOULD disconnect | P3 |
| B8.2 | CANCEL of a pending LOCK and a pending IOCTL; CANCEL of an unknown request | 3.3.5.16 | Found and cancelled: ERROR response `STATUS_CANCELLED`; not found: no response; implementing cancel is a SHOULD; match by AsyncId when ASYNC flag set, else MessageId | P2 |
| B8.3 | Interim async response | 3.3.4.2 (id c1692ece-7c6d-45c8-a0e3-6b53c0483030) | `STATUS_PENDING` with AsyncId, final response has same AsyncId | P2 |
| B8.4 | WRITE with WRITE_THROUGH / UNBUFFERED | 3.3.5.13 | Success | P3 |
| B8.5 | RDMA channel flags without RDMA negotiated | 3.3.5.12 / 3.3.5.13 **(locate)** | Status per section | P3 |
| B8.6 | READ/WRITE above MaxReadSize/MaxWriteSize | 3.3.5.12 / 3.3.5.13 **(locate exact text)** | `STATUS_INVALID_PARAMETER` expected; confirm before asserting | P2 |
| B8.7 | UNLOCK of an unlocked range | 3.3.5.14.1 defers to [MS-FSA] 2.1.5.9 (not stated in MS-SMB2) | `STATUS_RANGE_NOT_LOCKED` | P2 |
| B8.8 | LOCK flags: unlock flags in a lock array (MUST INVALID_PARAMETER); shared/exclusive flag in an unlock element (MUST INVALID_PARAMETER); multiple elements without FAIL_IMMEDIATELY (SHOULD INVALID_PARAMETER); FAIL_IMMEDIATELY conflict | 3.3.5.14.1/.2; MS-FSA 2.1.5.9 | `STATUS_LOCK_NOT_GRANTED` for conflict; lock overflow `STATUS_INVALID_LOCK_RANGE`; lock on a directory INVALID_PARAMETER | P2 |
| B8.9 | READ without FILE_READ_DATA; FLUSH on a directory without FILE_ADD_FILE/FILE_ADD_SUBDIRECTORY | 3.3.5.12; 3.3.5.11 | `STATUS_ACCESS_DENIED` | P2 |

### B9. QUERY_DIRECTORY / QUERY_INFO
| ID | Scenario | Spec | Pass criteria | Pri |
|---|---|---|---|---|
| B9.1 | SMB2_INDEX_SPECIFIED with FileIndex | 3.3.5.18 (server MAY support; Windows ignores it, Appendix A `<410>`) | Optional: gate; log only on Windows | P3 |
| B9.2 | QUERY_DIRECTORY invalid info class (`STATUS_INVALID_INFO_CLASS`), unsupported class (`STATUS_NOT_SUPPORTED`), no FILE_LIST_DIRECTORY (`STATUS_ACCESS_DENIED`), OutputBufferLength > MaxTransactSize (SHOULD INVALID_PARAMETER) | 3.3.5.18 | See left | P2 |
| B9.3 | QUERY_INFO `SMB2_0_INFO_SECURITY` per AdditionalInformation; unknown flag bits | 3.3.5.20.3 | Unknown bits ignored; valid SD returned; small buffer: `STATUS_BUFFER_TOO_SMALL` with required size in ErrorData (3.1.1: ErrorContext, ByteCount 12; else ByteCount 4); never an incomplete SD | P2 |
| B9.4 | QUERY_INFO info class not in 2.2.37 but in [MS-FSCC] / undocumented | 3.3.5.20.1 | SHOULD `STATUS_NOT_SUPPORTED` / `STATUS_INVALID_INFO_CLASS`; FileIdInformation on non-3.x MUST NOT_SUPPORTED; FileNormalizedNameInformation NOT_SUPPORTED on 2.0.2, 2.1, 3.0.2 | P3 |

### B10. Compound requests (3.3.5.2.7, 3.3.5.2.7.2)
| ID | Scenario | Pass criteria | Pri |
|---|---|---|---|
| B10.1 | Related chain where an earlier op with a FileId failed | SHOULD fail the next op with the same error (Appendix A `<270>`) | P2 |
| B10.2 | First op carries RELATED flag (SHOULD fail the chain); previous op neither contains nor generates a FileId (MUST fail current and subsequent with `STATUS_INVALID_HANDLE`); SessionId/TreeId not created (INVALID_PARAMETER) | See left | P2 |
| B10.3 | 8-byte alignment violation | SHOULD disconnect; **Windows ignores it (Appendix A `<267>`)**: assert only on non-Windows, log on Windows | P3 |
| B10.4 | Mixing related and unrelated styles in one send | SHOULD fail each with `STATUS_INVALID_PARAMETER` | P3 |
| B10.5 | Compound with an async-completing op | Server MAY fail async ops (`<266>`); every response after the first has the RELATED flag set in a related chain | P3 |

### B11. Oplock (3.3.5.9, 3.3.4.6, 3.3.5.22)
| ID | Scenario | Pass criteria | Pri |
|---|---|---|---|
| B11.1 | Level II and exclusive oplock grant | Granted level per request/availability | P2 |
| B11.2 | Break to none | Notification NewOplockLevel = NONE | P2 |
| B11.3 | Invalid break-ack level transition (3.3.5.22.1): Exclusive to anything but II/NONE; Batch to anything but II/NONE/EXCLUSIVE; II to anything but NONE | `STATUS_INVALID_OPLOCK_PROTOCOL` | P2 |
| B11.4 | Ack when Open.OplockState is not Breaking | `STATUS_INVALID_DEVICE_STATE` | P2 |
| B11.5 | Oplock ack carrying level LEASE | `STATUS_INVALID_PARAMETER` | P2 |
| B11.6 | Conflicting open before ack | `STATUS_REQUEST_NOT_ACCEPTED` (Windows only, Appendix A `<441>`) | P3 |
| B11.7 | ForceLevel2 share | 3.3.4.6 (leases: 3.3.5.9.8 clears WRITE_CACHING when ForceLevel2Oplock) | P3 |

## C. Corrections to existing tests
- `CompressionTest.cs` (~line 488): assert message cites 3.3.5.2.13; correct to 3.3.5.2.1.2 / 3.3.7.1.

## D. Out of scope
Optional features a server may lack, Windows-only behaviour, printer-share CREATE (not testable on a disk share).

## E. Totals
8 documented leasing tests (up to 16 methods with V2 variants; earlier audit counted 13, confirm per method against the
Test Design Spec) plus about 85 scenarios across B1–B11.

## F. Still to locate on MS Learn
B6.2–B6.5 (QFid/AlSi/ExtA/TWrp section numbers), B7.4/B7.5/B7.7 (3.3.5.15.x numbers and statuses), B8.5/B8.6 (READ/WRITE
size-limit wording), B8.3 section body, B11.7 ForceLevel2 text. Search the 3.3.5.9 / 3.3.5.15 child pages before implementing.
