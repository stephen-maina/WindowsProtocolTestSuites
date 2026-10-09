# Audit: Smb2OverRdmaChannelTransformEncryption (24 tests) — rpt-encryption

Run: C:\WPTS-Diagnostics\session-20261008-102557 (client 192.168.10.11, ksmbd SUT 192.168.10.12). Source of results: fullrun-console.txt (full.trx did not exist yet when this report was written), per-test ptf-log.ndjson, rdma.pcap (decoded by hand from RoCEv2 SEND payloads).

## Key finding (applies to every test)

**All 24 tests FAILED identically** after ~2m10s with
`System.TimeoutException: SMBD ReceiveMessage failed with status 0xC0000120 while waiting for the SMB2 response.`
raised in `Smb2OverSmbdTestClient.ExpectPacket` <- `Smb2Client.TreeConnect` <- `SmbdAdapter.Smb2TreeConnect` (SmbdAdapter.cs:368) <- `Smb2EstablishSessionAndOpenFile` (SmbdAdapter.cs:485) <- `InitSmbdConnectionForTestCases` (test .cs:987). No test reached any RDMA_TRANSFORM-specific step. ptf-log.ndjson of each ends with `TestFailed` right after `The select DialectRevsion is Smb311` (e.g. ReadLargeFile_AES128CCM: 10:43:53 -> TestFailed 10:46:04).

pcap decode (same in all 24 folders, checked ReadLargeFile_AES128CCM in detail):
- Client NEGOTIATE (212 B payload): dialect 3.1.1, contexts PREAUTH(0001), ENCRYPTION(0002, 1 cipher = AES128_CCM), **RDMA_TRANSFORM_CAPABILITIES (0007, one id = 0x0001 ENCRYPTION)**.
- ksmbd NEGOTIATE response (308 B): dialect 0x0311, contexts **only PREAUTH + ENCRYPTION (cipher AES128_CCM)**. **No SMB2_RDMA_TRANSFORM_CAPABILITIES (0x0007) context -> ksmbd does not advertise/support RDMA transform.** Hence `Connection.RDMATransformIds` is empty / IsRDMATransformSupported FALSE on this connection.
- SESSION_SETUP (NTLM, 2 legs) succeeds; final response has SessionFlags = 0.
- Client then sends TREE_CONNECT as a *transform-header-encrypted* message (ProtocolId FD 53 4D 42, OriginalMessageSize 0x78, Flags 0x0001, SessionId 2; header layout is well-formed; test sets `enableEncryption=true` so all requests are encrypted). ksmbd answers with only an SMBD credit-only/keep-alive message (20-byte SMBD header, no SMB2 payload) and **never sends a TREE_CONNECT response nor a STATUS_DATA_ERROR/ACCESS_DENIED**. 125 s later the test times out.
- Not cipher dependent: identical for CCM/GCM, 128/256 (ksmbd negotiated the single cipher offered in every run), and identical in the "negative" tests.

Root cause of the non-reply is **unverified**: either (a) ksmbd silently drops a transform-header request it cannot decrypt/does not accept (server side), or (b) client key derivation/cipher mismatch (ProtoSDK `GenerateCryptoKeys` for 3.1.1 using preauth hash) — I could not decrypt the packet (no session key). Evidence favours (a)/(b) being independent of RDMA transform: the failing step is plain SMB3 encrypted TREE_CONNECT, before any RDMA_TRANSFORM field is used. A control (same flow with `enableEncryption=false`, or Smb2OverRdmaChannelTransformSigning with signing only) would separate (a) from (b); I was not allowed to run tests.

Independent of that failure, the capability gap would break the suite anyway: ksmbd lacks RDMA transform, and the test class has **no capability gating** (hard `Assert` instead of `Assume.Inconclusive`).

## Spec basis (Learn)

- [MS-SMB2] 2.2.3.1.6 / 2.2.4.1.6 SMB2_RDMA_TRANSFORM_CAPABILITIES — client lists transforms in request; response context "indicates RDMA transforms the server supports of the set offered". Optional feature (2.2.43: "optional and only valid for SMB 3.1.1 when connection supports RDMA transform", product note <88>). https://learn.microsoft.com/openspecs/windows_protocols/ms-smb2/52b74a74-9838-4f51-b2b0-efeb23bd79d6 , .../e2e68435-26bb-40be-a825-ef29bdc981c6 , .../5cf594dd-6fc7-4c13-bb48-585069efc285
- [MS-SMB2] 3.3.5.4 NEGOTIATE (context 10): server processes RDMA_TRANSFORM context only if it supports it; absent context = no transform. https://learn.microsoft.com/openspecs/windows_protocols/ms-smb2/b39f253e-4963-40df-8dff-2f9040ebbeb1 (item-level wording of step 10.x only partially retrieved; unverified beyond 10.2.1 DataLength check).
- [MS-SMB2] 3.3.5.13 WRITE (https://learn.microsoft.com/openspecs/windows_protocols/ms-smb2/829f93f5-ed10-4f12-8347-42d235019459):
  - Dialect 3.1.1: if IsRDMATransformSupported is FALSE (or TRUE with other value) and Channel is not RDMA_V1_INVALIDATE/RDMA_V1/NONE -> **MUST STATUS_INVALID_PARAMETER**; for Channel=RDMA_TRANSFORM with `Connection.RDMATransformIds` empty -> STATUS_INVALID_PARAMETER.
  - STATUS_INVALID_PARAMETER also MUST be returned for: WriteChannelInfoLength < sizeof(SMB2_RDMA_TRANSFORM); TransformCount == 0; ENCRYPTION type present while RDMATransformIds lacks ENCRYPTION; ENCRYPTION type present and Request.IsEncrypted FALSE; more than one ENCRYPTION structure; ENCRYPTION + SIGNING pair; SIGNING present without SMB2_FLAGS_SIGNED; descriptor array not at first 8-byte aligned offset after the crypto transform.
  - With encryption transform: **MUST fail with STATUS_AUTH_TAG_MISMATCH if SignatureLength > 16, or CipherId CCM and NonceLength != 11, or GCM and NonceLength != 12**; decrypted size != RemainingBytes -> STATUS_BAD_DATA.
- [MS-SMB2] 3.3.5.12 READ (https://learn.microsoft.com/openspecs/windows_protocols/ms-smb2/ — search hit "3.3.5.12", items 7.2-7.4): with RDMA transform response, DataLength = sum of sizes of SMB2_RDMA_TRANSFORM + SMB2_RDMA_CRYPTO_TRANSFORM; Flags has SMB2_READFLAG_RESPONSE_RDMA_TRANSFORM; encryption tag in SMB2_RDMA_CRYPTO_TRANSFORM.
- [MS-SMBD] 3.1.4.6 (RDMA read of data) is referenced by WRITE processing; not re-read (local PDF not parsed).

Consequence for a server that does **not** advertise the capability (ksmbd): it correctly returns INVALID_PARAMETER for *any* WRITE with Channel=RDMA_TRANSFORM, so (1) positive tests cannot pass, they should be Inconclusive; (2) "INVALID_PARAMETER" negative tests pass for the wrong reason; (3) "AUTH_TAG_MISMATCH" tests fail against a spec-conformant non-supporting server (it must answer INVALID_PARAMETER).

## Summary table

| # | Test | Result | Verdict | Conf. | Reason |
|---|------|--------|---------|-------|--------|
| 1 | BVT_..._ReadLargeFile_AES128CCM | FAIL (TreeConnect timeout) | KSMBD_FAILURE (sec: TEST_INACCURATE) | med | ksmbd lacks RDMA transform + drops encrypted TREE_CONNECT; test has no capability gate |
| 2 | ..._ReadLargeFile_AES128GCM | FAIL (same) | KSMBD_FAILURE | med | same |
| 3 | ..._ReadLargeFile_AES256CCM | FAIL (same) | KSMBD_FAILURE | med | same |
| 4 | ..._ReadLargeFile_AES256GCM | FAIL (same) | KSMBD_FAILURE | med | same |
| 5 | ..._ReadMultipleOperation | FAIL (same) | KSMBD_FAILURE | med | same (64 ops, AES128CCM) |
| 6 | BVT_..._WriteLargeFile_AES128CCM | FAIL (same) | KSMBD_FAILURE (sec: TEST_INACCURATE) | med | same |
| 7 | ..._WriteLargeFile_AES128GCM | FAIL (same) | KSMBD_FAILURE | med | same |
| 8 | ..._WriteLargeFile_AES256CCM | FAIL (same) | KSMBD_FAILURE | med | same |
| 9 | ..._WriteLargeFile_AES256GCM | FAIL (same) | KSMBD_FAILURE | med | same |
| 10 | ..._WriteMultipleOperation | FAIL (same) | KSMBD_FAILURE | med | same |
| 11 | ..._WriteLargeFile_NoTransformIds_Fails | FAIL (same) | TEST_INACCURATE | med | needlessly requires SMB3 encryption to reach the check; expected value itself is spec-correct |
| 12 | ..._ZeroTransformCount_Fails | FAIL (same) | KSMBD_FAILURE (sec: TEST_INACCURATE) | low | spec-correct expectation; blocked at TREE_CONNECT; would pass for wrong reason on ksmbd |
| 13 | ..._MultipleEncryptionStructure_Fails | FAIL (same) | KSMBD_FAILURE (sec: TEST_INACCURATE) | low | same |
| 14 | ..._EncryptionAndSigningStructure_Fails | FAIL (same) | TEST_INACCURATE | high | "signing" struct built with TYPE_ENCRYPTION and never added to payload; TransformCount/offset inconsistent |
| 15 | ..._BufferNotAligned_Fails | FAIL (same) | KSMBD_FAILURE (sec: TEST_INACCURATE) | low | spec-correct; blocked at TREE_CONNECT |
| 16 | ..._IncreaseSignatureLength_Fails | FAIL (same) | TEST_INACCURATE (sec: KSMBD_FAILURE) | med | expects AUTH_TAG_MISMATCH; non-supporting server must return INVALID_PARAMETER; no gate |
| 17 | ..._IncreaseNonceLength_AES128CCM_Fails | FAIL (same) | TEST_INACCURATE (sec: KSMBD_FAILURE) | med | same |
| 18 | ..._IncreaseNonceLength_AES128GCM_Fails | FAIL (same) | TEST_INACCURATE (sec: KSMBD_FAILURE) | med | same |
| 19 | ..._IncreaseNonceLength_AES256CCM_Fails | FAIL (same) | TEST_INACCURATE (sec: KSMBD_FAILURE) | med | same |
| 20 | ..._IncreaseNonceLength_AES256GCM_Fails | FAIL (same) | TEST_INACCURATE (sec: KSMBD_FAILURE) | med | same |
| 21 | ..._DecreaseNonceLength_AES128CCM_Fails | FAIL (same) | TEST_INACCURATE (sec: KSMBD_FAILURE) | med | same |
| 22 | ..._DecreaseNonceLength_AES128GCM_Fails | FAIL (same) | TEST_INACCURATE (sec: KSMBD_FAILURE) | med | same |
| 23 | ..._DecreaseNonceLength_AES256CCM_Fails | FAIL (same) | TEST_INACCURATE (sec: KSMBD_FAILURE) | med | same |
| 24 | ..._DecreaseNonceLength_AES256GCM_Fails | FAIL (same) | TEST_INACCURATE (sec: KSMBD_FAILURE) | med | same |

Counts: KSMBD_FAILURE 13 (tests 1-10, 12, 13, 15), TEST_INACCURATE 11 (tests 11, 14, 16-24), ACCURATE 0, WINDOWS_BEHAVIOUR 0 (one secondary tag on reads), ENV_CONFIG 0. All 24 FAIL; none passed, none inconclusive.
Caveat: the shared immediate failure (encrypted TREE_CONNECT unanswered) is of unverified origin (ksmbd vs client crypto); where verdict is "KSMBD_FAILURE" that is the best-supported reading, confidence capped at med/low accordingly.

## Common code facts (helpers)

- `ReadOverRdma_Encryption`: Assert IsTrue(ids contains ENCRYPTION); `InitSmbdConnectionForTestCases(file, ids, encryptionAlgorithms:[alg])` (enableEncryption defaults true, enableSigning false, addDefaultEncryption true -> overridden by encryptionAlgs only when addDefaultEncryption=false; see below); Assert `SelectedRdmaTransformIds` contains ENCRYPTION ("Server must select SMB2_RDMA_TRANSFORM_ENCRYPTION") — hard Assert, should be Assume/Inconclusive; then registers buffer, Smb2ReadOverRdmaChannel, asserts STATUS_SUCCESS, DataRemaining==length, DataOffset==80, Flags==SMB2_READFLAG_RESPONSE_RDMA_TRANSFORM, one transform, TransformType==ENCRYPTION, SignatureLength==16, NonceLength>0, DataLength == 16 + align8(8+sig+nonce); reads the registered buffer; **never decrypts/authenticates the payload** (a comment says "Decrypt and authenticate ... here" — not implemented). Passing would not prove the data was actually encrypted correctly.
- Read-path note: ReadOverRdma_Encryption passes `addDefaultEncryption` default (true) via InitSmbdConnectionForTestCases, and `Smb2Negotiate` then **overwrites `encryptionAlgs` with {AES128_CCM, AES128_GCM}** (Smb2OverSmbdTestClient.cs:309-312). So the AES256_CCM/AES256_GCM read tests do **not** negotiate AES256 (and GCM read test offers CCM+GCM, not GCM alone). The pcap for ReadLargeFile_AES256CCM confirms the same-size negotiate (212 B). Write tests pass addDefaultEncryption:false, so they really offer the single cipher. => Read AES* variants are mislabeled (TEST_INACCURATE secondary for tests 1-4; also description "AES128_CCM" for test 5 is accurate only by default).
- `DataLength` assertion includes 8-byte padding; spec 3.3.5.12 7.2 only says "sum of sizes of structures" -> padding assumption is a mild Windows-behaviour assumption (WINDOWS_BEHAVIOUR secondary, unverified against spec text on padding).
- `WriteOverRdma_Encryption` negative branches assert exact status; non-negative branch asserts SUCCESS & Count; success path validates content by re-connecting without encryption (`ValidateFileContent`) — a good check. `isFailedTest` skips content validation for negative cases (no check that nothing was written).
- Negotiate/sessions: capability result is never asserted in the write tests, and `smb2RdmaTransformIds` non-null still proceeds to send Channel=RDMA_TRANSFORM even when the server returned no RDMA context.

## Per-test sections

### 1-4. ReadLargeFile_AES128CCM (BVT) / AES128GCM / AES256CCM / AES256GCM
- Purpose: server returns READ data over RDMA with an RDMA encryption transform; metadata (signature/nonce) returned inline.
- Spec: [MS-SMB2] 3.3.5.12 items 7.x (DataLength = sizes of transform structs; Flags RESPONSE_RDMA_TRANSFORM; encryption tag), and 3.3.5.4 context 10 (server must have offered the capability in negotiate response for the client to use it). Server not advertising the capability is spec-valid.
- Does: see "Common code facts".
- Observed: FAIL, TimeoutException at TREE_CONNECT (see Key finding). ptf-log: `Assert.IsTrue succeeded. The test must advertise ...` ... `The select DialectRevsion is Smb311` -> `TestFailed`. Negotiate response in pcap has no 0x0007 context. Run time 2m10s-2m20s.
- Verdict: KSMBD_FAILURE (med). Even once tree connect is fixed, ksmbd lacks the feature and the test would fail at "Server must select SMB2_RDMA_TRANSFORM_ENCRYPTION". Secondary TEST_INACCURATE: no Assume/Inconclusive on missing capability; payload never decrypted/verified; AES256 / GCM-only variants do not actually restrict the offered cipher (Smb2Negotiate overrides encryptionAlgs because addDefaultEncryption=true).
- Fix: `Assume`/`Assert.Inconclusive` if `SelectedRdmaTransformIds` lacks ENCRYPTION; pass `addDefaultEncryption:false` for reads; verify tag/decrypt with `Smb2Crypto` using the Signature/Nonce; assert negotiated `SelectedCipherID == encryptionAlgorithm` (Inconclusive otherwise); relax DataLength padding check or cite spec.

### 5. ReadMultipleOperation (64 ops, AES128CCM)
Same as above, loop of 64 reads. Observed: FAIL same TimeoutException at TREE_CONNECT (2m11s). Verdict KSMBD_FAILURE (med), same secondary notes. Fix: same as 1-4.

### 6-9. WriteLargeFile_AES128CCM (BVT) / AES128GCM / AES256CCM / AES256GCM
- Purpose: client sends WRITE with Channel=SMB2_CHANNEL_RDMA_TRANSFORM, encrypted payload in an RDMA-readable buffer; server MUST RDMA-read, decrypt, write; verify via re-read.
- Spec: [MS-SMB2] 3.3.5.13 (encryption branch, MS-SMBD 3.1.4.6). Requires Request.IsEncrypted == TRUE (test encrypts requests via enableEncryption) and Connection.RDMATransformIds containing ENCRYPTION.
- Does: addDefaultEncryption:false so the single requested cipher is offered; builds SMB2_RDMA_TRANSFORM + SMB2_RDMA_CRYPTO_TRANSFORM (8-aligned) + descriptor; asserts SUCCESS and Count; then validates content.
- Observed: FAIL at TREE_CONNECT (2m11s-2m29s) with the same TimeoutException; negotiate response lacks RDMA_TRANSFORM context.
- Verdict: KSMBD_FAILURE (med); secondary TEST_INACCURATE (no capability gate; no check that negotiated cipher == requested; if the server picks a different cipher the encryption would be wrong -> misleading failure).
- Fix: gate on `SelectedRdmaTransformIds`/`SelectedCipherID` with Inconclusive.

### 10. WriteMultipleOperation (64 ops, AES128CCM)
As above, 64 WRITEs. Observed FAIL same. Verdict KSMBD_FAILURE (med). Note each iteration reuses the same `encrypted`/nonce for every operation (same nonce reused with the same key; spec-wise OK for test but unrealistic), and writeSize used for all registered buffers.

### 11. WriteLargeFile_NoTransformIds_Fails
- Purpose: server returns INVALID_PARAMETER if no RDMA transform ids were negotiated but Channel=RDMA_TRANSFORM.
- Spec: 3.3.5.13: "Connection.RDMATransformIds is empty" -> MUST STATUS_INVALID_PARAMETER (also generic rule: Channel RDMA_TRANSFORM invalid when transform unsupported).
- Does: no RDMA context in NEGOTIATE (pcap shows 188 B negotiate request, no 0007), but still encryptionAlgorithm default CCM + enableEncryption true; sends RDMA_TRANSFORM write; expects INVALID_PARAMETER.
- Observed: FAIL at TREE_CONNECT (same). Expectation itself matches spec for *any* server, including ksmbd.
- Verdict: TEST_INACCURATE (med): the check does not need SMB3 encryption; enabling it adds an unrelated dependency that causes this test (which a conformant ksmbd would pass) to fail. Secondary KSMBD_FAILURE (encrypted TREE_CONNECT unanswered, unverified).
- Fix: call with `encryptionAlgorithm: ENCRYPTION_NONE` (helper supports it: enableEncryption=false) — but then the helper's flow must still register/send a valid structure.

### 12. ZeroTransformCount_Fails
- Spec 3.3.5.13: TransformCount == 0 -> MUST STATUS_INVALID_PARAMETER. Test: `setZeroTransformCount` -> transformCount=0 in header; asserts INVALID_PARAMETER. Expectation correct. Observed: FAIL at TREE_CONNECT. Verdict KSMBD_FAILURE (low; origin of drop unverified); secondary TEST_INACCURATE: on a non-supporting server INVALID_PARAMETER is returned for an unrelated reason, so the test cannot isolate TransformCount; add gate (Inconclusive if capability absent).

### 13. MultipleEncryptionStructure_Fails
- Spec: more than one ENCRYPTION crypto transform -> INVALID_PARAMETER. Test builds TransformCount=2 with two identical encryption structs; expects INVALID_PARAMETER. Structure looks valid per layout. Observed FAIL at TREE_CONNECT. Verdict KSMBD_FAILURE (low), secondary TEST_INACCURATE (same gate issue).

### 14. EncryptionAndSigningStructure_Fails
- Spec: ENCRYPTION and SIGNING structs together -> INVALID_PARAMETER.
- Code defect: `signingTransform` is created with `TransformType = SMB2_RDMA_TRANSFORM_TYPE_ENCRYPTION` (copy/paste) and `signingTransformBytes` is never appended to `totalBytes`, while `transformCount`/`descriptorOffset` include it; additionally `addEncryptionTransform:true` also appends the encryption struct twice. Result: TransformCount=3 with two actual structures and a descriptor offset that points past the real data — it actually tests "multiple encryption + malformed", not enc+signing; INVALID_PARAMETER would be returned for malformed layout. Also SMB2_FLAGS_SIGNED not set (enableSigning false), another independent reject reason.
- Observed: FAIL at TREE_CONNECT. Verdict TEST_INACCURATE (high, code inspection). Fix: build one encryption + one SIGNING (TransformType_SIGNING, SigningAlgorithm GMAC sizes) struct, append both, `addEncryptionTransform:false`, enableSigning true so SIGNED flag is set so only the combination is invalid.

### 15. BufferNotAligned_Fails
- Spec: descriptor array not at first 8-byte aligned offset after crypto transform -> INVALID_PARAMETER. Test skips `Align8`, giving 8+16+12=36-byte struct (GCM), RdmaDescriptorOffset computed consistently. Correct expectation. Observed FAIL at TREE_CONNECT. Verdict KSMBD_FAILURE (low), secondary TEST_INACCURATE (gate).

### 16-24. IncreaseSignatureLength / IncreaseNonceLength (x4 ciphers) / DecreaseNonceLength (x4 ciphers) _Fails
- Spec 3.3.5.13: **MUST fail with STATUS_AUTH_TAG_MISMATCH** if SignatureLength > 16, CCM and NonceLength != 11, GCM and NonceLength != 12 — but only reached when the server supports RDMA transform and Channel=RDMA_TRANSFORM is valid for the connection. For a server without RDMA transform (ksmbd) the earlier rule requires INVALID_PARAMETER, so asserting AUTH_TAG_MISMATCH is wrong without a capability gate.
- Test: mutates nonce/signature after `EncryptByteArray`; expects AUTH_TAG_MISMATCH. Variants for tests 17/19/21/23 rely on `Smb2Crypto` returning 11-byte CCM nonces (not asserted) and GCM 12 (tests 18/20/22/24). For `IncreaseSignatureLength` the 17-byte signature is built from the 16-byte tag, correct.
- Observed: all FAIL at TREE_CONNECT (2m10s-2m11s). Even after fixing that, ksmbd would answer INVALID_PARAMETER and the tests would fail on the status assertion.
- Verdict: TEST_INACCURATE (med; no Assume on capability; asserts a status reachable only with support) with secondary KSMBD_FAILURE. Fix: gate on negotiated RDMA transform + cipher; assert negotiated cipher matches variant name.

## Other observations
- Test descriptions for negative tests ("Verify SMB2 can write ... fails if ...") are misleading wording but not wrong.
- The class relies on `Smb2OverSmbdTestClient.Smb2TreeConnect` using `FLAGS_SIGNED` while session signing is disabled; with encryption the flag is overridden by transform header — unverified whether ksmbd rejects/ignores this combination (could be related to the unanswered TREE_CONNECT; worth a control run).
- full.trx not available at report time; outcomes taken from fullrun-console.txt (authoritative text identical for all 24).
- Final in-flight sibling class (Signing) was still running when this report was finalised; not part of this audit.
