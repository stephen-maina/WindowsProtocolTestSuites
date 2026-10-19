# FileServer SMB2 – Specification of Missing Tests

**Purpose.** Design specification for tests that [MS-SMB2] requires or that the Test Design Spec documents, but that the
test suite does not implement. These are **test suite gaps**, not SUT (ksmbd) defects. Nothing here is to be added to or
worked around in ksmbd. Each entry is implementable against any compliant server (Windows or non-Windows).

**Source.** Section 6 of `Analysis_KsmbdWorkgroup.md` (coverage audit). Section numbers are [MS-SMB2] unless stated;
sections not re-read on MS Learn are marked *(verify)*.

**Conventions for implementation.**
- Place in the existing test class for the area; name `[Category]_[Protocol]_[Scenario]`; add `// SPEC:` comment.
- Optional features: gate with `CheckCapabilities` / `CheckSigningAlgorithm` / `CheckCompressionAlgorithm` (Inconclusive).
- SHOULD or Windows-specific behaviour: assert only under `Platform.WindowsServer`, otherwise log.
- Update `FileServerTestDesignSpecification.md` and the User Guide when a test is added.
- Priority: **P1** = MUST with security/interop impact; **P2** = MUST, other; **P3** = SHOULD or low risk.

## A. Documented in the Test Design Spec, no method in code (13)

| ID | Test (V2 variant also needed unless noted) | Spec | Scenario / pass criteria | Pri |
|---|---|---|---|---|
| A1 | `BVT_Leasing_LeaseState_DowngradeNotAllowed` (+V2) | 3.3.5.9.8, 3.3.5.9.11 | Open with RWH lease; reopen same LeaseKey requesting a lower state. Server must not downgrade; response LeaseState remains the granted state. | P2 |
| A2 | `BVT_Leasing_PartialOverlapRequest_NotDowngrade` (+V2) | 3.3.5.9.8 | Hold RH; request RW (partial overlap). Granted state is the union permitted, never less than held. | P2 |
| A3 | `BVT_Leasing_UpgradeOnSupersetRequest` (+V2) | 3.3.5.9.8 | Hold R; request RWH on same key with no other opener. Server upgrades to the requested state. | P2 |
| A4 | `BVT_Leasing_CreateDuringLeaseBreak_SameLeaseKey_NotBlocked` (+V2) | 3.3.4.7, 3.3.5.9.8 | While a break is pending, a CREATE with the same LeaseKey must complete without waiting for the break ack. | P2 |
| A5 | `BVT_Leasing_WriteCache_BreakOnIncompatibleShareMode` (+V2) | 3.3.4.7 | Client A holds RWH; client B opens with an incompatible ShareAccess. A receives a break; B completes after ack. | P2 |
| A6 | `BVT_Leasing_WriteCache_BreakOnReadDataAccess` (+V2) | 3.3.4.7 | A holds RWH; B opens with FILE_READ_DATA. A is broken to remove Write caching. | P2 |
| A7 | `BVT_Leasing_WriteCache_BreakOnWriteDataAccess` (+V2) | 3.3.4.7 | A holds RWH; B opens with FILE_WRITE_DATA. A is broken. | P2 |
| A8 | `BVT_Leasing_WriteCache_NoBreakOnReadControl` (+V2) | 3.3.4.7 | A holds RWH; B opens with READ_CONTROL only. No break is sent to A (wait timeout, assert none). | P2 |

## B. Spec requirements with no test

### B1. NEGOTIATE (3.3.5.4)
| ID | Scenario | Pass criteria | Pri |
|---|---|---|---|
| B1.1 | Send a second NEGOTIATE on an established connection | Server disconnects the connection | P1 |
| B1.2 | DialectCount = 0 | `STATUS_INVALID_PARAMETER` | P2 |
| B1.3 | Dialect list with no common dialect | `STATUS_NOT_SUPPORTED` | P2 |
| B1.4 | Duplicate PREAUTH / ENCRYPTION / COMPRESSION / RDMA_TRANSFORM / SIGNING contexts | `STATUS_INVALID_PARAMETER` (or connection failure) | P2 |
| B1.5 | PREAUTH or ENCRYPTION context with too-short DataLength | `STATUS_INVALID_PARAMETER` | P2 |
| B1.6 | Unknown negotiate context type included | Ignored; NEGOTIATE succeeds | P3 |
| B1.7 | Response echoes ClientGuid semantics / SecurityMode signing flags consistent with config | Fields match ServerGuid/SecurityMode rules | P3 |

### B2. SESSION_SETUP (3.3.5.5)
| ID | Scenario | Pass criteria | Pri |
|---|---|---|---|
| B2.1 | Non-zero SessionId unknown to server in first SESSION_SETUP | `STATUS_USER_SESSION_DELETED` | P2 |
| B2.2 | Binding negatives: wrong dialect, mismatched ClientGuid, unsigned bind request, bad signature on bind | `STATUS_INVALID_PARAMETER` / `STATUS_REQUEST_NOT_ACCEPTED` / `STATUS_ACCESS_DENIED` per 3.3.5.5.2 *(verify)* | P1 |
| B2.3 | Signing required: unsigned final SESSION_SETUP | Rejected | P1 |
| B2.4 | SessionFlags result (GUEST/NULL) matches authenticated identity | Flags as per 3.3.5.5.3 | P3 |

### B3. Encryption and signing (3.3.5.2.1.1, 3.3.5.2.4)
| ID | Scenario | Pass criteria | Pri |
|---|---|---|---|
| B3.1 | Malformed TRANSFORM_HEADER (short, bad Flags, bad algorithm) | Connection disconnected | P1 |
| B3.2 | TRANSFORM_HEADER with unknown SessionId | Disconnect / `STATUS_USER_SESSION_DELETED` *(verify)* | P1 |
| B3.3 | Tampered ciphertext or Signature field | Disconnect (decrypt) / `STATUS_ACCESS_DENIED` (signature) | P1 |
| B3.4 | Unencrypted request to an EncryptData share/session | `STATUS_ACCESS_DENIED` | P1 |
| B3.5 | Unsigned request when signing is required | `STATUS_ACCESS_DENIED` | P1 |

### B4. Compression (3.3.5.2.1.2)
| ID | Scenario | Pass criteria | Pri |
|---|---|---|---|
| B4.1 | COMPRESSION_TRANSFORM_HEADER shorter than minimum | Disconnect | P2 |
| B4.2 | OriginalCompressedSegmentSize larger than limit | Disconnect / error | P2 |
| B4.3 | Corrupt compressed payload | Disconnect / error | P2 |
| B4.4 | Compressed message when compression not negotiated | Disconnect / error | P2 |

### B5. TREE_CONNECT / TREE_DISCONNECT / CLOSE
| ID | Scenario | Pass criteria | Pri |
|---|---|---|---|
| B5.1 | TREE_CONNECT to nonexistent share | `STATUS_BAD_NETWORK_NAME` | P2 |
| B5.2 | Request on a disconnected TreeId | `STATUS_NETWORK_NAME_DELETED` | P2 |
| B5.3 | CLOSE with SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB | Response attributes populated and match file | P2 |
| B5.4 | Operation using a closed FileId | `STATUS_FILE_CLOSED` | P2 |

### B6. CREATE contexts (2.2.13.2.x)
| ID | Scenario | Pass criteria | Pri |
|---|---|---|---|
| B6.1 | `MxAc` request | Response MxAc context with QueryStatus and MaximalAccess | P2 |
| B6.2 | `QFid` request | Response QFid context with a 32-byte disk file id | P2 |
| B6.3 | `AlSi` (allocation size) | Allocation size honoured or ignored per spec | P3 |
| B6.4 | `ExtA` (extended attributes) | EAs set on create and readable via QUERY_INFO | P3 |
| B6.5 | `TWrp` (timewarp) | Gate on snapshot support; open at token succeeds, bad token `STATUS_OBJECT_NAME_NOT_FOUND` | P3 |
| B6.6 | DesiredAccess = 0 | Server behaviour logged (SHOULD) | P3 |

### B7. IOCTL (3.3.5.15)
| ID | Scenario | Pass criteria | Pri |
|---|---|---|---|
| B7.1 | IOCTL without SMB2_0_IOCTL_IS_FSCTL | `STATUS_NOT_SUPPORTED` | P2 |
| B7.2 | Unknown FSCTL code | `STATUS_NOT_SUPPORTED` | P2 |
| B7.3 | Wrong FileId (must be 0xFFFFFFFFFFFFFFFF) for DFS referral, QUERY_NETWORK_INTERFACE_INFO, VALIDATE_NEGOTIATE_INFO | `STATUS_INVALID_PARAMETER` | P2 |
| B7.4 | COPYCHUNK / SRV_REQUEST_RESUME_KEY (limits, invalid key, zero chunks) | Statuses per 3.3.5.15.6 *(verify)* | P2 |
| B7.5 | Pipe FSCTLs (PIPE_TRANSCEIVE, PIPE_WAIT) | Behaviour per 3.3.5.15.x *(verify)* | P3 |
| B7.6 | MaxOutputResponse above MaxTransactSize | Server limits output (SHOULD) | P3 |
| B7.7 | FSCTL_LMR_REQUEST_RESILIENCY on non-durable open | Failure status per 3.3.5.15.9 *(verify)* | P3 |

### B8. ECHO / CANCEL / FLUSH / READ / WRITE / LOCK
| ID | Scenario | Pass criteria | Pri |
|---|---|---|---|
| B8.1 | Standalone ECHO | `STATUS_SUCCESS` | P3 |
| B8.2 | CANCEL of pending LOCK and pending IOCTL | Request completes `STATUS_CANCELLED` | P2 |
| B8.3 | Interim async response (STATUS_PENDING with AsyncId) | Final response follows with same AsyncId | P2 |
| B8.4 | WRITE with WRITE_THROUGH / UNBUFFERED flags | Success; data durable | P3 |
| B8.5 | RDMA channel flags without RDMA negotiated | `STATUS_INVALID_PARAMETER` *(verify)* | P3 |
| B8.6 | READ/WRITE above MaxReadSize/MaxWriteSize | `STATUS_INVALID_PARAMETER` | P2 |
| B8.7 | UNLOCK of an unlocked range | `STATUS_RANGE_NOT_LOCKED` | P2 |

### B9. QUERY_DIRECTORY / QUERY_INFO
| ID | Scenario | Pass criteria | Pri |
|---|---|---|---|
| B9.1 | QUERY_DIRECTORY with SMB2_INDEX_SPECIFIED and FileIndex | Enumeration resumes at index (gate: optional) | P3 |
| B9.2 | QUERY_INFO `SMB2_0_INFO_SECURITY` with each AdditionalInformation | Valid SECURITY_DESCRIPTOR returned | P2 |

### B10. Compound requests (3.3.5.2.7)
| ID | Scenario | Pass criteria | Pri |
|---|---|---|---|
| B10.1 | Related chain where first request fails | Subsequent responses carry the propagated failure status | P2 |
| B10.2 | Related request with invalid FileId | `STATUS_INVALID_PARAMETER` / `STATUS_FILE_CLOSED` | P2 |
| B10.3 | Compound padding/alignment (8-byte) violations | Disconnect / error | P2 |
| B10.4 | Compound containing an async-completing request | Responses returned per spec | P3 |

### B11. Oplock (3.3.5.9, 3.3.4.6)
| ID | Scenario | Pass criteria | Pri |
|---|---|---|---|
| B11.1 | Level II and exclusive oplock grant | Granted level per request/availability | P2 |
| B11.2 | Break to none | Break notification NewOplockLevel = NONE | P2 |
| B11.3 | Invalid break acknowledgement | `STATUS_INVALID_OPLOCK_PROTOCOL` | P2 |
| B11.4 | ForceLevel2 handling | Server breaks to Level II per 3.3.4.6 *(verify)* | P3 |

## C. Corrections to existing tests
- `CompressionTest.cs` (~line 488): assert message cites 3.3.5.2.13; correct to 3.3.5.2.1.2 / 3.3.7.1.

## D. Out of scope
Optional features a server may lack, Windows-only behaviour, printer-share CREATE (not testable on a disk share).

## E. Totals
8 documented leasing tests (up to 16 methods with V2 variants; the earlier audit counted 13, so confirm per method against
the Test Design Spec before implementing) plus about 70 scenarios across B1–B11.
