# Audit: Smb2OverRdmaChannelTransformSigning (9 tests) – Windows client vs Linux ksmbd

Evidence: `C:\WPTS-Diagnostics\session-20261008-102557\tests\<test>__<guid>\` (ptf-log.ndjson, rdma.pcap). Outcomes come from the ptf-log terminal kinds. `full.trx` did not exist when I finished, so they are NOT confirmed from the trx. All 9 tests ran between 11:36:53 and 11:41:45.

Spec used (Learn, [MS-SMB2]): 3.3.5.4 (NEGOTIATE, steps 10/11), 3.3.5.12 (READ), 3.3.5.13 (WRITE), 2.2.43 / 2.2.43.1, 3.2.4.7, 3.2.5.11.
URLs:
- https://learn.microsoft.com/openspecs/windows_protocols/ms-smb2/b39f253e-4963-40df-8dff-2f9040ebbeb1 (3.3.5.4)
- .../829f93f5-ed10-4f12-8347-42d235019459 (3.3.5.13)
- .../5cf594dd-6fc7-4c13-bb48-585069efc285 (2.2.43)
- .../49dce94d-71fd-4fdf-b730-a60d6b27fbba (3.2.4.7)
- .../7f74256a-dd82-48b7-ba04-ec91aa6aa916 (3.2.5.11)
- .../e2e68435-26bb-40be-a825-ef29bdc981c6 (2.2.4.1.6)

3.3.5.12 and 2.2.43.1 were read through Learn search results only. I did not fetch [MS-SMBD] pages.

## Summary

| Test | Result | Verdict | Conf. | Reason |
|---|---|---|---|---|
| Signing_ReadLargeFile_AES_GMAC | Inconclusive | ACCURATE (2nd: KSMBD lacks feature) | high | The Assume on a negotiated SIGNING transform is correct. 3.3.5.4 step 10.1 lets a server ignore the optional context. |
| Signing_ReadLargeFile_AES_CMAC | Inconclusive | ACCURATE (2nd: KSMBD lacks feature) | high | Same as the GMAC read test. |
| Signing_WriteLargeFile_AES_GMAC | Failed (INVALID_PARAMETER) | TEST_INACCURATE (2nd: KSMBD lacks feature) | med-high | There is no Assume on the negotiated transform, unlike the Read tests. The server's INVALID_PARAMETER is spec-conformant. |
| Signing_WriteLargeFile_AES_CMAC | Failed (INVALID_PARAMETER) | TEST_INACCURATE (2nd: KSMBD lacks feature) | med-high | Same as the GMAC write test. |
| FlagsSignedNotSet_Fails | Failed (TimeoutException at TREE_CONNECT) | ENV_CONFIG / KSMBD_FAILURE (unresolved); 2nd: TEST_INACCURATE | low | An encrypted TREE_CONNECT gets no reply, and the test never reaches its write. The test also never clears SMB2_FLAGS_SIGNED. |
| SigningStructure_EncryptionId_Fails | Failed (same timeout) | ENV_CONFIG / KSMBD_FAILURE (unresolved) | low | Same hang as FlagsSignedNotSet_Fails. |
| InvalidSignature_Fails | Failed (got INVALID_PARAMETER, expected INVALID_SIGNATURE) | TEST_INACCURATE (2nd: KSMBD lacks feature) | med | The expectation is spec-correct only if SIGNING was negotiated, and the test never checks that. |
| NoTransformIds_Fails | Passed | ACCURATE (weak message) | med-high | INVALID_PARAMETER with empty RDMATransformIds matches 3.3.5.13. |
| ZeroTransformCount_Fails | Passed | TEST_INACCURATE (vacuous pass) | med-high | It passes because RDMATransformIds is empty, not because TransformCount=0. |

Counts: ACCURATE 3 (2 Inconclusive, 1 Pass), TEST_INACCURATE 4 (Write GMAC, Write CMAC, InvalidSignature, ZeroTransformCount), ENV_CONFIG/KSMBD_FAILURE unresolved 2.

## Key facts about ksmbd (pcap)

- The client offers RDMA_TRANSFORM_CAPABILITIES [SIGNING] (ctx type 7) and SIGNING_CAPABILITIES (type 8). ksmbd's 3.1.1 NEGOTIATE response contains **no type 7 context**, so Connection.RDMATransformIds is empty.
- That is allowed. 3.3.5.4 step 10.1 says a server with IsRDMATransformSupported=FALSE MUST ignore the context. The feature is optional.
- **GMAC deviation.** When the client offers only AES-GMAC, ksmbd also omits SIGNING_CAPABILITIES. 3.3.5.4 step 11.3 / step 5 says that if no common algorithm exists the server MUST select AES-CMAC and return the context. With CMAC offered, ksmbd returns [CMAC]. This is a medium-confidence ksmbd deviation, and no test checks it.
- **WRITE with Channel=RDMA_TRANSFORM.** The WRITE was well-formed: Channel=3, flags 0x8 (SIGNED), ChannelInfoLength 56, with RDMA_TRANSFORM, CRYPTO_TRANSFORM(type 2) and a descriptor. ksmbd answered 0xC000000D. Per 3.3.5.13, a server that does not support the transform, or has empty RDMATransformIds, MUST return STATUS_INVALID_PARAMETER for this channel. This is conformant behaviour.
- **Cleanup.** The `DeleteFile.ps1` cleanup logs CheckFailed "Cannot find path 'TestDrive:\<guid>.txt'". The Linux SUT has no such path, so this is an environment and infrastructure problem. It shows up even in passing tests.

## Test details

### 1–2. Signing_ReadLargeFile_AES_GMAC / AES_CMAC
- **Purpose:** The server returns SMB2_RDMA_TRANSFORM + SMB2_RDMA_CRYPTO_TRANSFORM(SIGNING) on an RDMA read.
- **Spec (3.3.5.12):** For Channel RDMA_V1 or RDMA_V1_INVALIDATE, dialect 3.1.1, non-empty RDMATransformIds and a SIGNED request with SIGNING in the IDs, the server builds the transform structures. GMAC uses a 12-byte nonce, CMAC uses none. The response sets SMB2_READFLAG_RESPONSE_RDMA_TRANSFORM.
- **Test:** `InitSmbdConnectionForTestCases` negotiates with the transform and signing algorithm offered. It then calls `Assume.IsTrue(SelectedRdmaTransformIds.Contains(SIGNING))`. The post-assume asserts check status, DataOffset=80, the flag, readData length 56 (GMAC) or 40 (CMAC), TransformCount=1, type SIGNING and NonceLength.
- **Observed:** TestInconclusive. The log says "Server MUST return SMB2_RDMA_TRANSFORM_SIGNING … Connection.RDMATransformIds is []". The pcap shows no type 7 context in the response.
- **Verdict:** ACCURATE, high confidence. The Assume correctly separates "feature absent" from "wrong behaviour".
- **Weaknesses:**
  - The signature value is never verified.
  - The TransformType assert message prints TransformCount.
  - The NonceLength assert messages say "DataLength".
  - The log wording "Server MUST return…" overstates the requirement, because support is optional.
  - A Windows-specific note about the registry value `SmbDirectDataPlacementSecurity` only describes Windows product configuration.

### 3–4. Signing_WriteLargeFile_AES_GMAC / AES_CMAC
- **Purpose:** A signed RDMA write succeeds and the file content is validated.
- **Spec (3.3.5.13, 3.2.4.7):** The write is valid only if the transform was negotiated. With empty RDMATransformIds the server MUST return STATUS_INVALID_PARAMETER.
- **Test:** `WriteOverRdma_Signing` has no Assume on the negotiated IDs. It builds the transforms and expects SUCCESS with Count==writeSize.
- **Observed:** TestFailed. "Status of SMB2 Write File offset 0 is STATUS_INVALID_PARAMETER" (line 481). The pcap shows WRITE pkt 48 answered by pkt 52 with 0xC000000D. The CMAC cleanup logged CheckFailed.
- **Verdict:** TEST_INACCURATE, med-high confidence. The server did what the spec requires. The test should be Inconclusive when SIGNING was not negotiated. Secondary tag: KSMBD lacks the feature.
- **Fix:** Add the same `Assume.IsTrue(SelectedRdmaTransformIds.Contains(SIGNING), …)` as the Read test, in `WriteOverRdma_Signing` before sending, for positive cases.
- **Additional unverified concerns:**
  - The GMAC test sends NonceLength 0 and a 16-byte signature. The adapter's `SignByteArray` output is used as-is, so GMAC is probably not really exercised. A GMAC signature needs a 12-byte nonce.
  - The signature is computed from the current messageId before `RequestCreditsFromSmb2Server`, which might shift messageIds. This is unverified.

### 5. FlagsSignedNotSet_Fails
- **Purpose:** A write with a SIGNING transform but SMB2_FLAGS_SIGNED not set must fail.
- **Spec (3.3.5.13):** A SIGNING transform present while FLAGS_SIGNED is not set means STATUS_INVALID_PARAMETER.
- **Test:** It uses enableSigning=false and enableEncryption=true. `WriteRequest` in the adapter **always sets FLAGS_SIGNED**, so the scenario in the name is never produced. `enableSigning=false` only suppresses signing-key generation.
- **Observed:** TestFailed with no assertion message. The test hangs about 2m10s, then a TimeoutException: "SMBD ReceiveMessage failed with status 0xC0000120" from `ExpectPacket` (Smb2OverSmbdTestClient.cs:129), via `Smb2TreeConnect` (line 555).
- **Pcap:** The encrypted TREE_CONNECT is sent as a TRANSFORM_HEADER (origSize=120, alg 0x1, session 1) at t=2.219s. ksmbd sends nothing back until the connection is torn down at t≈125s. The same hang affects all Encryption suite tests, which are all TestFailed.
- **Root cause:** Unverified. Candidates are a client key-derivation or encryption mismatch with ksmbd, or ksmbd not decrypting the request. It is not caused by the signing logic.
- **Verdict:** ENV_CONFIG / KSMBD_FAILURE, low confidence. Secondary: TEST_INACCURATE, because the flag-clear scenario is not built and the Assert message is wrong.
- **Fix:** The test needs a request with the SIGNED bit explicitly cleared, and an Assume on the negotiated transform.

### 6. SigningStructure_EncryptionId_Fails
- **Purpose:** The IDs are [ENCRYPTION] but a SIGNING crypto transform is sent, so the server must reject it.
- **Spec (3.3.5.13):** A SIGNING transform not covered by RDMATransformIds means STATUS_INVALID_PARAMETER.
- **Observed:** The same encrypted TREE_CONNECT timeout as test 5 (2m09s), and the same cleanup error. The test never reaches its write.
- **Verdict:** ENV_CONFIG / KSMBD_FAILURE, low confidence. The root cause is the same unresolved encrypted-session issue. An Assume is also missing for the negotiated ENCRYPTION transform.

### 7. InvalidSignature_Fails
- **Purpose:** A corrupted signature (bytes 2 and 3 swapped) must be rejected with STATUS_INVALID_SIGNATURE.
- **Spec (3.3.5.13):** The server MUST fail the write with STATUS_INVALID_SIGNATURE if the signature does not verify.
- **Observed:** TestFailed. Expected STATUS_INVALID_SIGNATURE, got STATUS_INVALID_PARAMETER (line 440). The pcap shows the same WRITE answered with 0xC000000D.
- **Cause:** RDMATransformIds is empty on ksmbd, so the server rejects the channel before signature verification is reachable.
- **Verdict:** TEST_INACCURATE, med confidence (secondary KSMBD lacks the feature). The expected value is correct, but only given the negotiated SIGNING transform.
- **Fix:** Add the Assume on the negotiated SIGNING transform.

### 8. NoTransformIds_Fails
- **Purpose:** A write with RDMA_TRANSFORM and no IDs must fail.
- **Spec (3.3.5.13):** Empty RDMATransformIds means STATUS_INVALID_PARAMETER.
- **Observed:** TestPassed, with INVALID_PARAMETER. Cleanup logged CheckFailed (file not found).
- **Verdict:** ACCURATE, med-high confidence. The expected status matches the spec and is not Windows-specific.
- **Weakness:** The assertion message wrongly mentions the SIGNED bit.

### 9. ZeroTransformCount_Fails
- **Purpose:** TransformCount=0 must be rejected.
- **Spec (2.2.43, 3.3.5.13):** TransformCount MUST be greater than 0, otherwise STATUS_INVALID_PARAMETER.
- **Observed:** TestPassed with INVALID_PARAMETER. The server returns that status because RDMATransformIds is empty, not because TransformCount=0.
- **Verdict:** TEST_INACCURATE, med-high confidence. It is a false positive on ksmbd. The test cannot distinguish the two causes.
- **Fix:** Add the Assume on the negotiated SIGNING transform.

## Cross-cutting recommendations
1. Add the Assume on the negotiated transform to every Write test. The Read tests already have it.
2. Fix misleading assert messages: TransformType prints TransformCount, NonceLength says "DataLength", and the INVALID_PARAMETER branch message mentions the SIGNED bit for cases that have nothing to do with it.
3. Make `FlagsSignedNotSet` actually clear FLAGS_SIGNED, and make the GMAC write test use a 12-byte nonce.
4. Make DeleteFile cleanup tolerant of the Linux path, or skip it on non-Windows SUTs.
5. Investigate the encrypted TREE_CONNECT hang. It affects every encryption-based test in the suite.
