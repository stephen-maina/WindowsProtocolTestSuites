# Defects: Smb2OverRdmaChannelTransform_Encryption_* (second full run, full2.trx)

Caveat: Smb2OverRdmaChannelTransformEncryption.cs was edited (06:06) after full2.trx was produced (05:45). The line numbers in the trx stacks (e.g. 987, 686, 409) no longer match the file. Line numbers below refer to the CURRENT file unless marked "trx".
Evidence is client-side only (full2.trx, ptf-log.ndjson, rdma.pcap, SDK source, upstream ksmbd source, local spec text). I did not run tests or edit the repo.

## 1. Real exception (identical for all 24 Encryption tests)

```
System.TimeoutException: SMBD ReceiveMessage failed with status 0xC0000120 while waiting for the SMB2 response.
  at Smb2OverSmbdTestClient.ExpectPacket[T]            (Adapter\Smb2OverSmbdTestClient.cs:129, trx)
  at Smb2Client.SendPacketAndExpectResponse            (ProtoSDK\MS-SMB2\Client\Smb2Client.cs:648)
  at Smb2Client.TreeConnect                            (Smb2Client.cs:1616)
  at Smb2OverSmbdTestClient.Smb2TreeConnect wrapper    (Smb2OverSmbdTestClient.cs:555, trx)
  at Smb2OverRdmaChannelTransformEncryption.InitSmbdConnectionForTestCases (:987, trx)
  at ...WriteOverRdma_Encryption (:686, trx) / ...ReadOverRdma_Encryption (:409, trx) -> test method
```

- 0xC0000120 is STATUS_CANCELLED. The test fails after ~130 s with no TREE_CONNECT response.
- Every test dies in setup, before any test-specific logic (transform builder, status assertion) runs.
- Per-test pcap (WriteLargeFile_AES256GCM): NEGOTIATE and SESSION_SETUP succeed. The encrypted TREE_CONNECT (0xFD transform header, flags=1, 254 B) gets no reply.
- The lead is investigating that cause. The per-test findings below are therefore STATIC, from reading the code. None was observed at runtime.
- The Signing test `..._SigningStructure_EncryptionId_Fails` fails the same way, so the cause is shared and not Encryption-specific.

## 2. Server capability observed

- The NEGOTIATE response in the pcap contains PREAUTH (SHA-512) and ENCRYPTION (selected cipher) contexts, and NO RDMA_TRANSFORM_CAPABILITIES (0x0007) context.
- Upstream ksmbd `decode_rdma_ctx` (smb2pdu.c ~1698) ignores the context when `!ksmbd_rdma_enabled()`. It echoes it only if `conn->rdma_transform_negotiated`.
- So on the SUT, Connection.RDMATransformIds is empty.
- Per MS-SMB2 3.3.5.13, any WRITE with Channel=SMB2_CHANNEL_RDMA_TRANSFORM then returns STATUS_INVALID_PARAMETER first. That makes every negative test expecting AUTH_TAG_MISMATCH unreachable. It also makes the INVALID_PARAMETER tests pass for the wrong reason.
- Confidence: medium. I did not verify why the SUT omits the context (SUT build or config).

## 3. Spec quotes (local smb2.txt; Learn GUIDs in spec-citations.md)

**2.2.43 SMB2_RDMA_TRANSFORM**
- "The SMB2_RDMA_TRANSFORM is optional and only valid for the SMB 3.1.1 dialect when connection supports RDMA transform."
- TransformCount: "This value MUST be greater than 0."
- The structure is 16 bytes: RdmaDescriptorOffset 2, RdmaDescriptorLength 2, Channel 4, TransformCount 2, Reserved1 2, Reserved2 4.

**2.2.43.1 SMB2_RDMA_CRYPTO_TRANSFORM**
- Fixed part: TransformType 2, SignatureLength 2, NonceLength 2, Reserved 2, then Signature, Nonce, Padding.
- Signature "MUST be less than or equal to 16 bytes".
- Nonce "MUST NOT be reused for an SMB2 message within a session".
- Padding: an optional field "present after Nonce field so the channel information, if any, after this structure starts at the first 8-byte aligned offset".

**3.3.5.13 (SMB2 WRITE)**

Server MUST return STATUS_INVALID_PARAMETER if, with Dialect 3.1.1 and Channel = RDMA_TRANSFORM, any of these hold:
- "Connection.RDMATransformIds is empty."
- "WriteChannelInfoLength is less than the size of SMB2_RDMA_TRANSFORM structure."
- "TransformCount is 0 in SMB2_RDMA_TRANSFORM structure."
- "More than one SMB2_RDMA_CRYPTO_TRANSFORM structures with TransformType equal to ... ENCRYPTION ... are present."
- "Two SMB2_RDMA_CRYPTO_TRANSFORM structures with TransformType equal to SMB2_RDMA_TRANSFORM_TYPE_ENCRYPTION and SMB2_RDMA_TRANSFORM_TYPE_SIGNING are present."
- "SIGNING is present and SMB2_FLAGS_SIGNED bit is not set..."
- "An array of SMB_DIRECT_BUFFER_DESCRIPTOR_V1 structures does not begin at the first 8-byte aligned offset after SMB2_RDMA_CRYPTO_TRANSFORM structure from the beginning of the Buffer field."

For the ENCRYPTION branch (when RDMATransformIds includes ENCRYPTION):
- "The server MUST fail the request with STATUS_AUTH_TAG_MISMATCH if one of the following is TRUE: SignatureLength field is greater than 16. Connection.CipherId is AES-128-CCM or AES-256-CCM and NonceLength field is not equal to 11. Connection.CipherId is AES-128-GCM or AES-256-GCM and NonceLength field is not equal to 12."
- Wrong decrypted size gives STATUS_BAD_DATA. The SIGNING branch gives STATUS_INVALID_SIGNATURE.

**3.2.4.7 (client WRITE)**
- TransformCount = 1.
- Nonce is 11 bytes for CCM and 12 for GCM.
- RdmaDescriptorOffset = sizeof(RDMA_TRANSFORM) + sizeof(CRYPTO_TRANSFORM).

**3.1.4.2 and 3.1.4.3**
- KDF: SP800-108 counter mode, r=32, PRF HMAC-SHA256, L=128 for AES-128 and 256 for AES-256 ciphers.
- Encrypt: "OriginalMessageSize is set to the size of the SMB2 message... SessionId... EncryptionAlgorithm/Flags is set to 0x0001. Nonce ... not used for any other encrypted message within the session. ... The SMB2 TRANSFORM_HEADER, excluding the ProtocolId and Signature fields, as the optional authenticated data. ... Session.EncryptionKey as the key".

**3.2.5.1.x (client session setup, 3.1.1)**
- Encryption key: key-derivation key is FullSessionKey for AES-256, else SessionKey.
- Label "SMBC2SCipherKey" (16 bytes with NUL) and "SMBS2CCipherKey". Context is Session.PreauthIntegrityHashValue.

## 4. Per-test analysis (code does vs claims)

Test names are abbreviated; all are `Smb2OverRdmaChannelTransform_Encryption_*`.

| Test | Code does | Name/spec claims | Spec | Verdict (confidence) |
|---|---|---|---|---|
| Read AES128CCM/AES128GCM/AES256CCM/AES256GCM (+ BVT, ReadMultipleOperation) | `ReadOverRdma_Encryption` calls `InitSmbdConnectionForTestCases(..., encryptionAlgorithms: ...)` with the default `addDefaultEncryption=true`. `Smb2Negotiate` (Adapter\Smb2OverSmbdTestClient.cs:328-330) then replaces `encryptionAlgs` with {AES128_CCM, AES128_GCM}. | The test should restrict the negotiated cipher to the named one. | 3.1.4.3 uses Connection.CipherId, which is chosen by the server from the client's list. | **TEST/ADAPTER bug**: AES-256 is never offered, so the AES256CCM/GCM read tests do not test AES-256 and the "GCM" test offers CCM and GCM. The 5 read tests ignore their cipher parameter. High (code read). pcap shows identical 212-byte negotiates for the read tests. |
| Write AES128CCM/GCM, AES256CCM/GCM, WriteMultipleOperation | `addDefaultEncryption: false` (line 795). The pcap shows one cipher offered (0x0004 for AES256GCM), and the server selects it. | Matches the name. | n/a | OK for cipher. **WriteMultipleOperation**: the same ciphertext, nonce and signature are reused for all writes. This violates the 2.2.43.1 nonce uniqueness rule (TEST bug, medium-high). |
| NoTransformIds | `smb2RdmaTransformIds=null`, so no 0x0007 context is sent. `channel` = RDMA_TRANSFORM. Expects INVALID_PARAMETER. | "Connection.RDMATransformIds is empty". | 3.3.5.13: "Connection.RDMATransformIds is empty." | The expectation is spec-correct. The test also needlessly enables session encryption (`enableEncryption: encryptionAlgorithms != null`), which forces the encrypted TREE_CONNECT that hangs. The check itself needs no encryption. TEST inefficiency (medium). It cannot isolate the failure from a non-supporting server, because every server returns INVALID_PARAMETER here. |
| ZeroTransformCount | `setZeroTransformCount` makes TransformCount=0 (line 787). A real crypto struct is still sent. | "TransformCount is 0". | 3.3.5.13 and 2.2.43. | Spec-correct. On the SUT (RDMATransformIds empty) it passes or fails for the same reason as NoTransformIds, so it is not isolated. No capability gate. TEST gap (medium). |
| MultipleEncryptionStructure | `addEncryptionTransform` gives TransformCount=2 and appends 2 ENCRYPTION structs. `descriptorOffset` counts both. | "More than one ... ENCRYPTION". | 3.3.5.13. | Consistent and correct. ksmbd rejects any TransformCount != 1 with EINVAL (`smb2_parse_rdma_write_transform`), which matches the expected status. OK (high). |
| EncryptionAndSigningStructure | (lines 291, 862-882) Passes both `addEncryptionTransform:true` AND `addSigningTransform:true`. Result: TransformCount = 1 + 1 + 1 = 3 (line 881). The "signing" struct is built with TransformType = ENCRYPTION. `descriptorOffset` counts 3 structs (line 882). `signingTransformBytes` is never appended to the payload, so only 2 structs are on the wire. enableSigning is false, so FLAGS_SIGNED is not meaningful for the signing branch. | "Two structures, ENCRYPTION and SIGNING". | 3.3.5.13: "Two SMB2_RDMA_CRYPTO_TRANSFORM structures with ... ENCRYPTION and ... SIGNING are present." | **TEST bug** (high). The request is malformed (TransformCount=3 but 2 structs, descriptor offset past the real data, no SIGNING type on the wire). It would return INVALID_PARAMETER for the wrong reasons. The test comment at line 280 already admits this. Prior-report label TEST_INACCURATE confirmed. |
| BufferNotAligned | `shouldAlignBuffer=false` skips Align8. With GCM the struct is 8+16+12=36 bytes, unpadded, and `descriptorOffset` is consistent. | Descriptors do not begin at an 8-byte aligned offset. | 3.3.5.13 alignment condition. | Spec-correct, with CCM (8+16+11=35) also unaligned. ksmbd compares `desc_offset != ALIGN(...)` and returns EINVAL. OK (high). |
| IncreaseSignatureLength | Signature becomes 17 bytes (a duplicate of byte 0 is prepended). The struct is padded and offsets stay consistent. Expects AUTH_TAG_MISMATCH. | "SignatureLength greater than 16". | 3.3.5.13: "SignatureLength field is greater than 16" gives AUTH_TAG_MISMATCH. ksmbd gives -EBADMSG for len > 16 (smb2pdu.c ~8935). | Spec-correct. It is reachable only if the server advertises ENCRYPTION in RDMATransformIds. On the SUT the first check (RDMATransformIds empty) returns INVALID_PARAMETER, so FAIL is expected without a gate. TEST gap + KSMBD/SUT (medium). |
| IncreaseNonce_x4 / DecreaseNonce_x4 | The nonce is changed by ±1 byte, with a consistent alignment recompute. Expects AUTH_TAG_MISMATCH. | NonceLength != 11 (CCM) / != 12 (GCM). | 3.3.5.13 ENCRYPTION branch. ksmbd returns -EBADMSG when `nonce_len` is wrong. | Spec-correct. The CCM tests pass `channel` explicitly, the GCM tests rely on the default (same value). The "AES256" names depend on the negotiated Connection.CipherId. Same reachability gate problem as above. TEST gap + KSMBD/SUT (medium). |

Other helper defects in `WriteOverRdma_Encryption`:
- `transformCount` is declared outside the per-operation loop (line 787) and accumulates across iterations. It is harmless with one operation, wrong for multi-operation use. (TEST, high.)
- `ValidateFileContent` (line 1011) opens a second connection with all defaults (`addDefaultEncryption=true`), so it silently depends on the same adapter behaviour.
- There is no capability gate (no `Assume`/`Assert.Inconclusive`) when the server omits RDMA_TRANSFORM_CAPABILITIES. Negative tests therefore report the wrong status.

## 5. SDK review (encrypted TREE_CONNECT construction)

Read: ProtoSDK\MS-SMB2\Common\Smb2Crypto.cs (Encrypt, EncryptByteArray), Smb2CryptoInfo.cs, PreauthIntegrityContext.cs, Client\Smb2Client.cs (GenerateCryptoKeys 947-1020, Negotiate ~1150-1340), and SMB2Message.cs structs `SMB2_RDMA_TRANSFORM` (7356+) and `SMB2_RDMA_CRYPTO_TRANSFORM`.

I found NO demonstrable SDK bug:
- **Transform header**:
  - ProtocolId is the transform-header constant.
  - OriginalMessageSize = the plaintext length.
  - SessionId is set.
  - Flags = 0x0001 for 3.1.1, else AES128_CCM.
  - Nonce is 11 bytes (CCM) or 12 (GCM), random, zero-padded in the 16-byte field. The AES-256 constants are used for AES-256.
  - The tag is written into Signature after encryption.
  - Matches 3.1.4.3.
- **AAD** = transform header bytes after offset 20 (4 ProtocolId + 16 Signature). Matches.
- **Key choice**: client uses ServerInKey (the C2S key), not ServerOutKey. Correct.
- **KDF labels and contexts** (3.1.1):
  - "SMBSigningKey\0", "SMBC2SCipherKey\0", "SMBS2CCipherKey\0", "SMBAppKey\0".
  - Context is the session preauth hash.
  - L is 128 for AES-128 and 256 for AES-256. The key-derivation key is FullSessionKey for AES-256, else the first 16 bytes of the session key.
  - Pre-3.1.1 labels "SMB2AESCCM\0", "ServerIn \0", "ServerOut\0" are correct.
  - Matches the spec 3.2.5.3.1 text above.
- **Preauth hash**: session hash starts from the connection hash after the NEGOTIATE response, then the SESSION_SETUP requests and the intermediate MORE_PROCESSING_REQUIRED responses are chained. The hash is applied to the final SUCCESS response only for signing verification. Matches spec.
- **Encryption trigger**: with `EnableSessionEncryption`, the TREE_CONNECT is encrypted, which is allowed by the spec.
- **`SMB2_RDMA_CRYPTO_TRANSFORM` marshalling**: Signature and Nonce arrays are sized by SignatureLength and NonceLength. Fixed part is 8 bytes. `SMB2_RDMA_TRANSFORM` is 16 bytes. Matches 2.2.43.

Adapter quirk (not hit in this run, medium): if the server returns no ENCRYPTION context and `addDefaultEncryption:false`, the client `cipherId` stays ENCRYPTION_NONE (Smb2Client.cs:384) and `Smb2Crypto.Encrypt` throws InvalidOperationException instead of failing negotiation clearly.

The unanswered TREE_CONNECT is not explained by anything I found in the SDK. Whether the packet is rejected by the server is the lead's question.

## 6. Defect classification summary

| # | Defect | Class | Confidence |
|---|---|---|---|
| D1 | ReadOverRdma_Encryption ignores the cipher parameter (Smb2Negotiate overrides `encryptionAlgs`) | TEST/ADAPTER | high |
| D2 | EncryptionAndSigningStructure builds a malformed request (extra ENCRYPTION struct, TransformCount=3, SIGNING struct typed ENCRYPTION and never appended) | TEST | high |
| D3 | No capability gate. When the server returns no RDMA_TRANSFORM context, negative AUTH_TAG_MISMATCH tests (Increase/Decrease Nonce/Signature) can only fail with INVALID_PARAMETER, and the INVALID_PARAMETER tests pass vacuously | TEST gap; SUT/ksmbd config | medium |
| D4 | NoTransformIds needlessly enables session encryption | TEST | medium |
| D5 | WriteMultipleOperation reuses nonce/ciphertext/signature across writes | TEST | medium-high |
| D6 | `transformCount` not reset per loop iteration | TEST | high |
| D7 | ZeroTransformCount, MultipleEncryption, BufferNotAligned, Increase/Decrease expectations | spec-correct; ksmbd behaviour matches the spec | high |
| D8 | Encrypted TREE_CONNECT unanswered (all 24 tests) | lead's investigation; no SDK bug demonstrated | n/a |

## 7. Minimal fixes (current file lines)

1. D1: `Smb2OverRdmaChannelTransformEncryption.cs:513`, the `InitSmbdConnectionForTestCases(` call in `ReadOverRdma_Encryption`.
   - Before: `InitSmbdConnectionForTestCases(..., encryptionAlgorithms: encryptionAlgorithms ...)`
   - After: add `addDefaultEncryption: false,` (as the write path does at line 795).
   - Alternative at `Adapter\Smb2OverSmbdTestClient.cs:328-330`:
     - Before: `if (addDefaultEncryption) { encryptionAlgs = new[]{AES128_CCM, AES128_GCM}; }`
     - After: `if (addDefaultEncryption && encryptionAlgs == null) { ... }`.
   - The alternative changes behaviour for other suites, so prefer the first option.
2. D2: line 291 and the builder at ~862-885.
   - Before: `WriteOverRdma_Encryption(smb2RdmaTransformIds: ..., addEncryptionTransform: true, addSigningTransform: true, signingAlgorithms: ...)`
   - After: drop `addEncryptionTransform: true`. In the builder, set the signing struct's `TransformType = Smb2RDMATransformType.SMB2_RDMA_TRANSFORM_TYPE_SIGNING` (SignatureLength 16, NonceLength 12 for AES-GMAC). Append `signingTransformBytes` to the buffer after the encryption struct. Set TransformCount to 2 and `descriptorOffset` to match the appended bytes.
   - Pass `enableSigning: true` so FLAGS_SIGNED is set.
3. D3: before the negative status assertion, add a gate such as `Assume.IsTrue(smbdAdapter.SelectedRdmaTransformIds.Contains(Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_ENCRYPTION), ...)` or `Assert.Inconclusive`, except in NoTransformIds, ZeroTransformCount, MultipleEncryption and BufferNotAligned. Those four assert INVALID_PARAMETER, which is valid whether or not RDMATransformIds is empty.
4. D4: NoTransformIds (test body, line ~178 trx; see ZeroTransformCount at 249 for the layout): call `WriteOverRdma_Encryption(... encryptionAlgorithm: EncryptionAlgorithm.ENCRYPTION_NONE)` so `enableEncryption` is false. The check does not require an encrypted TREE_CONNECT. The SDK still derives keys, so `EncryptByteArray` still works.
5. D5: generate ciphertext, nonce and signature inside the per-operation loop (call `smbdAdapter.EncryptByteArray` per iteration).
6. D6: move `var transformCount = setZeroTransformCount ? 0 : 1;` (line 787) inside the per-operation loop.

Not verified: fixes 1-6 have not been compiled or run, since the tool was read-only.
