# Defect root-causing: RDMA channel / signing / multichannel tests (run 2)

Evidence: `full2.trx` (streamed; extracted to `TestResults\err2.txt`), per-test `rdma.pcap` decoded with `files\pcapsmb.ps1`, source under `TestSuites\MS-SMBD\src`.
Note: trx line numbers (e.g. Signing:76/90/128/197) are from the built binary; current source has shifted a few lines (edited after build) — method names are authoritative.

## Common root cause A — ksmbd does not implement RDMA transform (optional feature)
Run-2 negotiate: `SelectedRdmaTransformIds = []` (ksmbd omits/answers NONE for SMB2_RDMA_TRANSFORM_CAPABILITIES).
Spec is satisfied by ksmbd:
- MS-SMB2 3.3.5.4: "If IsRDMATransformSupported is FALSE, the server MUST ignore the context." / "If the server does not support any of the RDMA transforms provided by the client, Connection.RDMATransformIds MUST be set to an empty list."
- Response build: "If Connection.RDMATransformIds is empty, set TransformCount to 1 and set RDMATransformIds to SMB2_RDMA_TRANSFORM_NONE."
- MS-SMB2 3.3.5.13: "If Connection.Dialect is "3.1.1" and Channel is equal to SMB2_CHANNEL_RDMA_TRANSFORM, the server MUST return STATUS_INVALID_PARAMETER to the client in the following conditions: Connection.RDMATransformIds is empty."

So the tests that *require* the feature are test defects (assert instead of Assume). Classification: **test bug (optional feature treated as mandatory) + ksmbd-optional-feature-absent**, confidence **high**.

## Per-test results

| Test | Real exception (trx) | Failing step | Classification | Conf. |
|---|---|---|---|---|
| BVT_Smb2OverRdmaChannel_WriteLargeFile | Assert.IsTrue, `Smb2OverRdmaChannel.cs:605` in `WriteOverRdma` (called :49): "Server MUST return SMB2_RDMA_TRANSFORM_SIGNING…" | assert on `SelectedRdmaTransformIds` | test bug + ksmbd optional absent | High |
| Smb2OverRdmaChannel_WriteMultipleOperation | same assert :605 (called :72) | same | same | High |
| Smb2OverRdmaChannel_ReadWriteMultipleBufferDescriptorList | same-style assert :100 (also asserts SelectedSigningAlgorithm==AES_CMAC) | same | same | High |
| Smb2OverRdma_Write/Read_SMB2_CHANNEL_RDMA_V1 | Assert.IsTrue `Smb2OverRdmaChannelRemoteInvalidation.cs:515` (now ~547) in `EstablishSignedRdmaConnectionAndOpenFile` (called :232/:277) | same; tests named RDMA_V1 but use CHANNEL_RDMA_TRANSFORM | test bug (wrong channel + hard assert) | High |
| BVT_Smb2OverRdma_Smb302_Write_…_INVALIDATE | `TimeoutException: SMBD ReceiveMessage failed with status 0xC0000005` ExpectPacket:129 ← Smb2Client.WriteResponse:2049 ← Smb2WriteOverRdmaChannel | see B | SDK/provider limitation (env HW) + adapter misleading exception | High (pcap-proved server side; client-side cause by code inspection) |
| BVT_Smb2OverRdma_Smb302_Read_…_INVALIDATE | same 0xC0000005 via Smb2Client.Read:1933 ← Smb2ReadOverRdmaChannel:763 | see B | same | Medium-High (pcap truncated, see D) |
| 4× InvalidBufferDescriptor_* | PASS | see C | weak test (not vacuous in run 2) | High |
| Smb2Multichannel_2Channels_DiffTransport | PASS | weak asserts (write not sliced, stale `status` re-asserted) | test weakness | Medium |
| Signing_ReadLargeFile_AES_GMAC/CMAC | NotExecuted: Assume failed, RDMATransformIds [] (:197) | correct behaviour | ksmbd optional absent (correctly Inconclusive) | High |
| Signing_WriteLargeFile_AES_GMAC / AES_CMAC | Assert.AreEqual SUCCESS vs STATUS_INVALID_PARAMETER (:76/:90) | WRITE with Channel RDMA_TRANSFORM and empty RDMATransformIds → spec-mandated INVALID_PARAMETER | test bug: `WriteOverRdma_Signing` lacks the Assume present in `ReadOverRdma_Signing` | High |
| Signing_WriteLargeFile_InvalidSignature_Fails | expected INVALID_SIGNATURE got INVALID_PARAMETER (:128) | same; INVALID_SIGNATURE unreachable without SIGNING negotiated | test bug (same) | High |
| Signing_FlagsSignedNotSet_Fails, SigningStructure_EncryptionId_Fails | `TimeoutException … 0xC0000120` (STATUS_CANCELLED) from `Smb2TreeConnect` (SmbdAdapter:368 → Smb2Client:1616) | enableEncryption=true: encrypted TREE_CONNECT never answered until teardown (~125 s) | env/SDK-or-ksmbd encryption issue, UNRESOLVED (same as Encryption_* failures); additionally these tests can't reach the intended check | Medium (unresolved cause) |
| Signing_NoTransformIds_Fails, ZeroTransformCount_Fails | PASS | ZeroTransformCount passes vacuously (INVALID_PARAMETER already due to empty RDMATransformIds) | weak test | High |

## B. Smb302 INVALIDATE — 0xC0000005 (STATUS_ACCESS_VIOLATION)
Pcap (Smb302_Write, 1149 pkts): WRITE_REQ msgId=5 Channel=RDMA_V1_INVALIDATE; ksmbd RDMA-READs 1 MiB (rkey 0x4a6fa), client answers; ksmbd then sends SEND_ONLY_WITH_INVALIDATE (opcode 0x17) carrying WRITE_RESP SUCCESS with IETH rkey=0x4a6fa — exactly the token the client supplied. The client's receive completion then fails with 0xC0000005 and ksmbd sends CM_DREQ ~6 ms later. **ksmbd behaved correctly** (MS-SMBD 3.1.4.2: "the token SHOULD be provided … If sending of remote invalidation is not supported by the RDMA provider, the token MAY be ignored." — ksmbd supports it, which is allowed).
Client-side cause: Mellanox NDSPI v2 has no memory windows (`RDMANdv2.h:90`, `CreateMemoryWindow` → ND_NOT_SUPPORTED). `SmbdConnectionEndpoint.RegisterMemoryWindow` (~898–910) falls back to `BuildMemoryRegionDescriptor` (~1096) advertising the plain MR rkey, while the test still sets CHANNEL_RDMA_V1_INVALIDATE. A remote invalidate of a non-MW rkey faults the HCA receive → ACCESS_VIOLATION. (Not directly proven in a client log; inferred from code + pcap.)
Classification: **environment (HW/provider lacks MW) + SDK bug (advertises INVALIDATE with MR fallback)**. Fixes:
- SDK: expose `smbdAdapter.MemoryWindowSupported`; test: `BaseTestSite.Assume.IsTrue(smbdAdapter.MemoryWindowSupported, "NDSPI provider has no memory windows; remote invalidation cannot be exercised")` at the start of the Smb302 tests.
- Adapter `Smb2OverSmbdTestClient.ExpectPacket` (~100–130): throws `TimeoutException` for ANY failing status (disconnect, 0xC0000120, 0xC0000005). Before: `throw new TimeoutException(...)` for all. After: throw `TimeoutException` only for the timeout status (STATUS_IO_TIMEOUT/0x102), otherwise `IOException`/`InvalidOperationException` carrying the status. This also stops `catch (TimeoutException)` in the Invalid* tests from swallowing disconnects.
- The final "connection MUST be terminated on token reuse" assert has no spec basis (test header TODO says so).
Smb300_*_INVALIDATE pass with INVALID_PARAMETER: correct per MS-SMB2 3.3.5.13 (RDMA_V1_INVALIDATE requires dialect 3.0.2+).

## C. InvalidBufferDescriptor_* (pass)
Not vacuous in run 2: pcaps show ksmbd issuing a 4 MiB RDMA WRITE with VA=0x400001 (Offset), Length+1 (Length), token+1 (Token), stale rkey (Deregistered); client HCA NAKs (syndrome 0x62, remote access error); ksmbd sends CM_DREQ; client receive fails fast (~13 ms) and the test passes in `catch (TimeoutException){ Assert.Pass }`. Defects (test weakness, High): `Assert.Pass` in catch; unchecked reconnect; log says "SMB2 WRITE" for READ; Offset test uses a bogus VA instead of an in-bounds-wrong one; the `AreNotEqual(SUCCESS)` branch is not what passes. Fix: in catch assert the specific disconnect (after the ExpectPacket fix above, catch `IOException` / check status is a disconnect code) instead of `Assert.Pass`; after reconnect do an SMB2 echo/negotiate and assert SUCCESS.

## D. Smb302_Read seeding slowness / credit ping-pong (adapter/SDK)
The test spent ~9 min (03:56:17→04:05:22) seeding 1 MiB with `WriteInlineContent` (~1,680 WRITEs of ~1,252 bytes: chunk = MaxReceiveSize 1364 minus headers; SMBD allows fragmented sends up to MaxFragmentedSize, so chunks can be much larger — test inefficiency). The pcap (2.59 M packets) shows empty 20-byte SMBD data-transfer messages (credits granted, DataLength 0, flags 0) exchanged continuously in both directions (client→server then server→client, each ACKed, ~4 ms cadence) between WRITE exchanges. Cause not provable client-side: each peer answers an empty credit-grant with another empty message. SMBD 3.1.5.x only requires sending when the peer's receive credits are low or on keepalive; the SDK's credit-return path should not reply to a zero-length message that has no `RequestResponse` flag. **SDK bug suspected (Medium)** — check `SmbdConnectionEndpoint` receive-completion handler: only post a credit-grant message when `CreditsGranted` to peer < threshold, never in response to DataLength==0 messages. The pcap ends at WRITE msgId=501 (log shows ~1,680) so the sniffer capture was truncated and the READ itself could not be inspected; the Read 0xC0000005 conclusion rests on the Write pcap and test header (previously observed ACCESS_VIOLATION).

## E. Fix snippets (test side)
`Smb2OverRdmaChannel.cs:605` (and :100) and `RemoteInvalidation.cs:~547`:
```csharp
// before
BaseTestSite.Assert.IsTrue(smbdAdapter.SelectedRdmaTransformIds.Contains(Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_SIGNING), "Server MUST return SMB2_RDMA_TRANSFORM_SIGNING ...");
// after
BaseTestSite.Assume.IsTrue(smbdAdapter.SelectedRdmaTransformIds.Contains(Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_SIGNING),
    "Server does not support SMB2_RDMA_TRANSFORM_SIGNING (optional, MS-SMB2 3.3.5.4); RDMATransformIds=[{0}]", string.Join(",", smbdAdapter.SelectedRdmaTransformIds));
```
(Alternative for the BVT write tests: fall back to plain `CHANNEL_RDMA_V1`, which the else-branch/`expectRdmaTransform` already support, so the BVT still verifies write over RDMA on ksmbd.) For `Smb2OverRdma_Write/Read_SMB2_CHANNEL_RDMA_V1`: the names say RDMA_V1; use `Channel_Values.CHANNEL_RDMA_V1` (no transform) or rename them.
`WriteOverRdma_Signing` (Signing.cs, before building the request, same as lines ~234–238 in `ReadOverRdma_Signing`): add the same `Assume.IsTrue(...Contains(SIGNING))`. For `InvalidSignature_Fails`/`FlagsSignedNotSet`/`ZeroTransformCount` the Assume also removes the vacuous pass.
Other test-code defects: GMAC write sends NonceLength 0 with 16-byte signature (prior run-1 finding; GMAC nonce must be 12 bytes — verify `SignByteArray`); `FlagsSignedNotSet` never clears SMB2_FLAGS_SIGNED (adapter WriteRequest always sets it); `ReadOverRdma` leftover "DIAGNOSTIC BUILD" log; `DeleteFile.ps1` cleanup runs on the Windows driver against `TestDrive:\` so files on the Linux share leak.

## F. Open items / possible ksmbd deviation
- Possible ksmbd deviation (Medium, from run 1, not re-verified): SIGNING_CAPABILITIES omitted when only AES-GMAC offered (3.3.5.4 expects selecting a common algorithm or CMAC fallback). Does not change the classification above.
- Encrypted TREE_CONNECT hang (0xC0000120): root cause not established from client-side evidence; need ksmbd-side logs or an encrypted-transform decode of the client's TRANSFORM_HEADER (key derivation / nonce) to distinguish SDK from ksmbd.
