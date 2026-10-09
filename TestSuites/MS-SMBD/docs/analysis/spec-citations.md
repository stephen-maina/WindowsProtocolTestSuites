# Spec citations for TEST_INACCURATE / WINDOWS_BEHAVIOUR verdicts

## Result: no prior verdict is CONTRADICTED by the spec

Nuances and corrections to the prior reports:

1. **credit.md, ConsumeAllSendCredits.** The claim "design spec says CreditsGranted MUST be 10" is **not in MS-SMBD**. 3.1.5.3 says only "CreditsGranted MUST be set to Connection.ReceiveCredits", and 3.1.5.7 requires only >0. The value 10 appears only as an example (MS-SMBD 4, Example). The test's `>0` check is spec-consistent. If the "design spec" is the repo's Test Design Spec, that is a repo document, not MS-SMBD. The TEST_INACCURATE label rests on the missing assertions, not on a spec number.
2. **datatransfer.md, trailing bytes "weakly specified".** This is understated. MS-SMBD 2.2 says padding inserted after a message for alignment "MUST be ignored when received". The test cannot require trailing bytes to be absent.
3. **datatransfer.md, IdleConnection_Client.** A literal reading of 3.1.5.1 allows the reply to carry SMB_DIRECT_RESPONSE_REQUESTED (if KeepaliveRequested is PENDING), and CreditsGranted may be 0. So `Flags==NONE` and `CreditsGranted>0` are not mandated.
4. **encryption.md, DataLength padding.** The padding assumption is UNVERIFIED. MS-SMB2 3.3.5.12 says "sum of the sizes" and mentions no padding.
5. **channel.md, token-reuse disconnect.** UNVERIFIED. MS-SMB2 3.3.5.13 / MS-SMBD 3.1.4.2 are silent on terminating the connection after token reuse. This is neither supported nor contradicted. The label WINDOWS_BEHAVIOUR is a hypothesis that is not spec-backed.
6. **Section numbering.** The reports cite "step 10.1 / 4.1.1 / 11.3" for 3.3.5.4. The Learn page is a bullet tree under "Processing the SMB2_RDMA_TRANSFORM_CAPABILITIES negotiate context". Cite it by heading and bullet text.
7. **Page ambiguity in MS-SMB2 3.3.5.13.** The second 3.1.1 Channel-check bullet ("Channel is not equal to RDMA_V1_INVALIDATE, RDMA_V1, or NONE") lacks an explicit IsRDMATransformSupported=FALSE qualifier. It is likely an editorial slip.

## Sources and method

- MS-SMB2 was read from Learn, `https://learn.microsoft.com/openspecs/windows_protocols/ms-smb2/<guid>`, plus the official docx (MS-SMB2 260928) for Appendix A.
- MS-SMBD pages (3.1.2.x, 3.1.5.6/7, 3.1.6.x, 3.1.7.2, Appendix B, 2.2.x) could not be surfaced by Learn search/fetch. They were verified from the official docx `[MS-SMBD]-250811.docx` (rev 16.0, 8/11/2025), downloaded from winprotocoldoc.z19.web.core.windows.net and extracted locally. Section numbers are derived from the spec's own cross-references.
- MS-SMBD pages confirmed on Learn: 3.1.5.8 `https://learn.microsoft.com/openspecs/windows_protocols/ms-smbd/c860aa40-cf59-4020-adf3-4fd587d23c89`, 3.1.5.1 `.../eaf8ad73-3c14-4777-9b64-617ac25edfb7`, 3.1.5.9 `.../40c3ed31-8ae8-42f5-9c4b-f51fabdffacb`, 3.1.4.2 `.../73412f19-a712-493b-b89e-c678e21bf91f`, 3.1.4.5 `.../c8a3df70-3c52-4ac3-9cb9-acbe2886130a`, 3.1.4.6 `.../b9251da1-ef25-4188-bc33-0a0358bb2667`. Where a row says "docx", the Learn GUID was not retrieved.
- MS-SMB2 URLs (base `https://learn.microsoft.com/openspecs/windows_protocols/ms-smb2/`):
  - 3.3.5.4 `b39f253e-4963-40df-8dff-2f9040ebbeb1`
  - 3.3.5.13 `829f93f5-ed10-4f12-8347-42d235019459`
  - 3.3.5.12 `21e8b343-34e9-4fca-8d93-03dd2d3e961e`
  - 2.2.21 `e7046961-3318-4350-be2a-a8d69bb59ce8`
  - 2.2.43 `5cf594dd-6fc7-4c13-bb48-585069efc285`
  - 2.2.43.1 `dd590f6e-14a4-4f62-bc66-2a177005df7c`
  - Appendix A `a64e55aa-1152-48e4-8206-edd96444e7f7`
- A row marked "N/A (test-code defect)" means the verdict is about how the test is written (vacuous, wrong flag, stale assertion) and not about a spec requirement. No spec quote is needed or invented.

## Key quotes reused below

| ID | Doc / section | Quote |
|---|---|---|
| Q1 | MS-SMB2 2.2.43 (SMB2_RDMA_TRANSFORM) | "The SMB2_RDMA_TRANSFORM is optional and only valid for the SMB 3.1.1 dialect when connection supports RDMA transform." |
| Q2 | MS-SMB2 2.2.43.1 | "The SMB2_RDMA_CRYPTO_TRANSFORM is optional and only valid for the SMB 3.1.1 dialect." |
| Q3 | MS-SMB2 3.3.5.4, RDMA transform context | "If IsRDMATransformSupported is FALSE, the server MUST ignore the context." / "If the server does not support any … Connection.RDMATransformIds MUST be set to an empty list." |
| Q4 | MS-SMB2 3.3.5.4 | "If Connection.RDMATransformIds is empty, set TransformCount to 1 and set RDMATransformIds to SMB2_RDMA_TRANSFORM_NONE." |
| Q5 | MS-SMB2 3.3.5.13, WRITE, Channel == SMB2_CHANNEL_RDMA_TRANSFORM | The server MUST fail with STATUS_INVALID_PARAMETER if Connection.RDMATransformIds is empty, TransformCount is 0, an ENCRYPTION transform is present but RDMATransformIds lacks it (same for SIGNING), more than one ENCRYPTION or SIGNING transform is present, one ENCRYPTION plus one SIGNING is present, or the descriptor array "does not begin at the first 8-byte aligned offset after SMB2_RDMA_CRYPTO_TRANSFORM". |
| Q6 | MS-SMB2 3.3.5.13 | "The server MUST fail the request with STATUS_AUTH_TAG_MISMATCH if … SignatureLength field is greater than 16 … CipherId is AES-128-CCM or AES-256-CCM and NonceLength … not equal to 11 … AES-128-GCM or AES-256-GCM and NonceLength … not equal to 12." This sits in the ENCRYPTION branch, which is reachable only when RDMATransformIds includes ENCRYPTION. |
| Q7 | MS-SMB2 3.3.5.13 | "If the signature verification fails, the server MUST fail the request with STATUS_INVALID_SIGNATURE." (SIGNING branch, same reachability condition) |
| Q8 | MS-SMB2 3.3.5.12, READ | "If the underlying object store returns fewer bytes than specified by the MinimumCount field of the request, the server MUST fail the request with STATUS_END_OF_FILE." |
| Q9 | MS-SMB2 3.3.5.4 | "Connection.SigningAlgorithmId MUST be set to 1 (AES-CMAC)" when the server supports none of the offered signing algorithms. |
| Q10 | MS-SMB2 2.2.21 | RDMA_TRANSFORM: "This flag is not valid for SMB 3.0 and 3.0.2 dialects." RDMA_V1_INVALIDATE: "This flag is not valid for the SMB 3.0 dialect." |
| Q11 | MS-SMBD 3.1.5.8 | The receiver MUST verify: length ≥ 20, CreditsRequested ≥ 1, DataOffset 8-byte aligned, DataOffset+DataLength within the message, DataLength+RemainingDataLength not above the maximum fragment size (the spec text says "Connection.MaxFragmentSize"). Otherwise "MUST terminate the connection". |
| Q12 | MS-SMBD 3.1.5.8 | "If the number of new credits returned is greater than zero, the receiver MUST promptly send a newly constructed Data Transfer message with its CreditsGranted field set" (empty credit-grant message). |
| Q13 | MS-SMBD 2.2.3 | "If no data payload is associated with this message, [DataOffset] MUST be 0." |
| Q14 | MS-SMBD 3.1.6.2 | The local peer "SHOULD check whether Connection.KeepaliveRequested is set to 'NONE', and if not, the local peer SHOULD terminate the connection… Otherwise… SHOULD be set to 'PENDING', and a Send of a Data Transfer message with the SMB_DIRECT_RESPONSE_REQUESTED flag set SHOULD be initiated." |
| Q15 | MS-SMBD Appendix B <2> (3.1.2.2) | "set this timer to a default value of 120 seconds" (Windows Server 2012+ / Windows 10+). Product behaviour, not normative. |
| Q16 | MS-SMBD 3.1.2 | Only two timers are defined: Negotiation Timer (3.1.2.1) and Idle Connection Timer (3.1.2.2). No "Send Credit Grant Timer" exists. |

## negotiate.md

| Test | Claimed defect | Spec section | URL | Verbatim quote | Verdict |
|---|---|---|---|---|---|
| SmbdNegotiate_PreferredSendSizeMaxValue | Description says the server terminates; the platform branch (2012R2/2016 only) is stale and sends 8136 | MS-SMBD Appendix B <6> (3.1.5.6) | docx (MS-SMBD 250811) | "Windows Server 2012 R2 operating system and later fail the request with STATUS_INSUFFICIENT_RESOURCES if the PreferredSendSize field is greater than 8136." | SUPPORTS. The behaviour is "and later". 8136 is not above 8136, so success is expected. |
| SmbdNegotiate_DisconnectAfterNegotiate | "Server still available" proves only the RDMA CM accept; no spec requirement for a re-negotiate | MS-SMBD 3.1.5.6 / 3.1.5.5 | docx | No requirement on disconnect-then-reconnect exists. 3.1.5.5 covers only message receipt in the ESTABLISHED state. | UNVERIFIED (the spec is silent, so the claim "no spec requirement" is consistent but cannot be quoted) |
| SmbdNegotiate_VersionRangeNotCover0x0100_LessThanMinVersion | The server returns 0xC00000BB (STATUS_NOT_SUPPORTED); the test swallows a TimeoutException | MS-SMBD 3.1.5.6 | docx | The range "MUST include 0x0100" otherwise the receiver sends a failure response with STATUS_NOT_SUPPORTED. Otherwise Min/Max "SHOULD <5> be ignored". | SUPPORTS for the status. The swallowed timeout is N/A (test-code defect). |
| SmbdNegotiate_VersionRangeNotCover0x0100_LargerThanMaxVersion | Same | MS-SMBD 3.1.5.6; Appendix B <5> | docx | Appendix B <5>: Windows 2012 and later fail with STATUS_NOT_SUPPORTED if MinVersion or MaxVersion is not 0x0100. | SUPPORTS |
| SmbdNegotiate_NegativeParameter_MaxReceiveSize (KSMBD_FAILURE + "TEST_INACCURATE labels") | The test sends MaxReceiveSize=128, which is valid, but ksmbd terminates | MS-SMBD 3.1.5.6 | docx | The receiver MUST verify "MaxReceiveSize ≥ 128" (and CreditsRequested > 0, MaxFragmentedSize ≥ 131,072), otherwise "MUST terminate". The test's boundary value 128 is valid. | SUPPORTS (ksmbd's termination is non-conformant; the test's boundary value is correct) |
| SmbdNegotiate_NegativeParameter_MaxFragmentedSize | The test sends 131072, which is valid, but ksmbd terminates | MS-SMBD 3.1.5.6 | docx | Same rule: MaxFragmentedSize ≥ 131,072. | SUPPORTS |
| (negotiate.md claim) 1 MiB MaxReadWriteSize floor is a Windows value | MaxReadWriteSize ≥ 1 MiB not spec-mandated | MS-SMBD 3.1.5.7, Appendix B <7>; MS-SMB2 3.3.5.4 and <285>/<286> | docx; `.../ms-smb2/b39f253e-4963-40df-8dff-2f9040ebbeb1` | 3.1.5.7: the smaller of "an implementation-specific value <7> and the received MaxReadWriteSize". MS-SMB2 3.3.5.4: MaxReadSize/MaxWriteSize "SHOULD be greater than or equal to 65536". | SUPPORTS. 1 MiB and 8 MiB appear only in Appendix B and the examples. |
| Negotiation Timer tests (5 s / 120 s) | Timer values | MS-SMBD 3.1.7.2, 3.1.4.1, 3.1.6.1 | docx | 3.1.7.2: passive side starts "a Negotiation Timer interval of 5 seconds". 3.1.4.1: active side "Negotiation Timer of 120 seconds". 3.1.6.1: "the local peer SHOULD terminate the connection." | SUPPORTS (termination is SHOULD, not MUST) |

## credit.md

| Test | Claimed defect | Spec section | URL | Verbatim quote | Verdict |
|---|---|---|---|---|---|
| SmbdCreditMgmt_OperationWithLimitedCredits | Weak assertions only | N/A (test-code defect) | – | – | N/A |
| SmbdCreditMgmt_ConsumeAllSendCredits | The design spec says CreditsGranted must be 10; the code checks only >0 | MS-SMBD 3.1.5.3, 3.1.5.7, 4 (example) | docx | 3.1.5.3: "CreditsGranted MUST be set to Connection.ReceiveCredits". 3.1.5.7 requires only CreditsGranted > 0. | CONTRADICTS the "MUST be 10" part. No MS-SMBD text mandates 10. `>0` is spec-consistent. The test is still weak for other reasons. |
| SmbdCreditMgmt_ConsumeAllReceiveCredits | The test treats the server's empty credit-grant message as the READ data | MS-SMBD 3.1.5.8 | `.../ms-smbd/c860aa40-cf59-4020-adf3-4fd587d23c89` | Q12: "the receiver MUST promptly send a newly constructed Data Transfer message with its CreditsGranted field set". | SUPPORTS |
| SmbdCreditMgmt_ConsumeAllCreditServer_Timeout | The "Send Credit Grant Timer" does not exist; the disconnect expectation is Windows behaviour | MS-SMBD 3.1.2 | docx | Q16: only the Negotiation Timer (3.1.2.1) and the Idle Connection Timer (3.1.2.2) are defined. | SUPPORTS for the missing timer. The disconnect expectation is UNVERIFIED because the spec has no credit-exhaustion termination rule. |
| SmbdCreditMgmt_NegativeParameter_CreditRequested | Title and description mention Negotiate but the code sends Data Transfer; a mandatory termination was not done by ksmbd | MS-SMBD 3.1.5.8 | `.../c860aa40-cf59-4020-adf3-4fd587d23c89` | Q11: the receiver MUST verify CreditsRequested ≥ 1, else "MUST terminate the connection". | SUPPORTS (ksmbd non-conformant) |
| SmbdTestBase.TestCleanup swallowing | Infra | N/A (test-code defect) | – | – | N/A |

## datatransfer.md

| Test | Claimed defect | Spec section | URL | Verbatim quote | Verdict |
|---|---|---|---|---|---|
| VariableLengthSegment | Stall at 0 send credits (root cause unverified); test inaccurate secondary | MS-SMBD 3.1.5.9 | `.../ms-smbd/40c3ed31-8ae8-42f5-9c4b-f51fabdffacb` | Credit growth is largely SHOULD-level: the receiver "SHOULD" increase credits up to min(ReceiveCreditTarget, ReceiveCreditMax). | UNVERIFIED. The spec gives no MUST that would classify the stall. |
| SmallLengthSegment | 65536 one-byte messages exceed any credit window | MS-SMBD 3.1.5.9 | same | Same. | UNVERIFIED |
| ReceiveMaxReceiveSize | The first message received is a 0-length credit grant or keepalive | MS-SMBD 3.1.5.8 | `.../c860aa40-cf59-4020-adf3-4fd587d23c89` | Q12. | SUPPORTS |
| NegativeParameter_DataLength_AgainstMaxReceiveSize | Part 1 is not a 3.1.5.8 check; part 2 setup got ACCESS_DENIED | MS-SMBD 3.1.5.8 | same | Q11 lists the checks (length, credits, alignment, offset+length, DataLength+RemainingDataLength vs max fragment size). DataLength vs MaxReceiveSize is not among them. | SUPPORTS. The part-1 assertion has no basis in 3.1.5.8. The ACCESS_DENIED part is ENV_CONFIG, N/A. |
| NegativeParameter_RemainingDataLength_AgainstFragmentReassemblyRemaining | Vacuous pass | MS-SMBD 3.1.5.8 | same | "If RemainingDataLength is 0 and FragmentReassemblyRemaining > 0" the receiver MUST terminate. | SUPPORTS that the check is real. The vacuous pass is a test-code defect (config flag off). |
| Padding / trailing bytes (caveat) | "Weakly specified" | MS-SMBD 2.2 | docx | Padding after any message for alignment "MUST be ignored when received". | The spec is stronger than the report implies. Report understated. |
| Empty message with DataOffset 24 (quirk) | ksmbd sends DataOffset=24 on an empty message | MS-SMBD 2.2.3 | docx | Q13. | SUPPORTS that this deviates (DataOffset MUST be 0 with no payload). |
| IdleConnection_Client | Asserts CreditsGranted>0 and Flags==NONE within 5 s | MS-SMBD 3.1.5.1, 3.1.5.8, 3.1.5.5 | `.../ms-smbd/eaf8ad73-3c14-4777-9b64-617ac25edfb7` | 3.1.5.1: "If Connection.KeepaliveRequested is 'PENDING', the Flags field … MUST be set to SMB_DIRECT_RESPONSE_REQUESTED… Otherwise … 0x0000." On RESPONSE_REQUESTED, 3.1.5.8: "KeepaliveRequested MUST be set to PENDING … promptly send a Data Transfer message". | SUPPORTS. Neither assertion is mandated. The 5 s window is unsupported (see IdleConnection_Server_Timeout). |
| IdleConnection_Server | Expects a 120 s keepalive twice; the 2nd arrived with Flags=NONE | MS-SMBD 3.1.2.2, 3.1.6.2, Appendix B <2>, <3> | docx | Q14. Appendix B <2> (Q15): 120 seconds is a Windows default. | SUPPORTS. The behaviour is SHOULD plus product default. |
| IdleConnection_Server_Timeout | Asserts a ~5 s timeout and a 120 s timer; ksmbd matched | MS-SMBD 3.1.6.2; Appendix B <4> | docx | 3.1.6.2 (Q14): termination is SHOULD. Appendix B <4> (3.1.5.1): after a keepalive is sent the Idle Connection Timer is set "to a default value of 5". | SUPPORTS. Values come from Windows product notes. |

## channel.md

| Test | Claimed defect | Spec section | URL | Verbatim quote | Verdict |
|---|---|---|---|---|---|
| Smb2OverRdmaChannel.BVT_ReadLargeFile | READ returned STATUS_END_OF_FILE (data file empty/missing); Smb2Create uses FILE_OPEN_IF, masking it | MS-SMB2 3.3.5.12 | `.../ms-smb2/21e8b343-34e9-4fca-8d93-03dd2d3e961e` | Q8. | SUPPORTS as a plausible cause, but only when MinimumCount > 0. The cause is ENV_CONFIG; the spec cannot confirm the file's state. |
| BVT_WriteLargeFile | Asserts the server MUST return SMB2_RDMA_TRANSFORM_SIGNING; optional | MS-SMB2 3.3.5.4; 2.2.43 | `.../ms-smb2/b39f253e-4963-40df-8dff-2f9040ebbeb1`, `.../5cf594dd-6fc7-4c13-bb48-585069efc285` | Q1, Q3, Q4. 3.3.5.4 contains no requirement to select SIGNING. | SUPPORTS TEST_INACCURATE |
| WriteMultipleOperation | Same | Same | Same | Same. | SUPPORTS |
| ReadWriteMultipleBufferDescriptorList | Same | Same | Same | Same. | SUPPORTS |
| BVT_WriteLargeFile secondary WINDOWS_BEHAVIOUR | Windows Server 2022+ only | MS-SMB2 Appendix A <88>, <89>, <62> | `.../ms-smb2/a64e55aa-1152-48e4-8206-edd96444e7f7` | <88> (2.2.43): "Windows 10 operating system and prior and Windows Server v20H2 operating system and prior do not send or process RDMA transforms." <62> (2.2.21): "do not send or process SMB2_CHANNEL_RDMA_TRANSFORM flag." | SUPPORTS |
| InvalidBufferDescriptor_Offset / _Length / _Token / _DeregisteredBuffer | The pass is vacuous: READ hit EOF, so `AreNotEqual(SUCCESS)` holds without exercising the bad descriptor | MS-SMB2 3.3.5.12 | `.../ms-smb2/21e8b343-34e9-4fca-8d93-03dd2d3e961e` | Q8. The spec defines no status or disconnect for an invalid descriptor, token or deregistered buffer on these pages. | SUPPORTS that EOF can occur. The expected failure mode is UNVERIFIED (the spec is silent). |
| Smb2Multichannel_2Channels_DiffTransport | Weak asserts; stale `status` | N/A (test-code defect) | – | – | N/A |
| RemoteInvalidation Write_..._INVALIDATE | Final assertion requires the connection to terminate after token reuse | MS-SMB2 3.3.5.13; MS-SMBD 3.1.4.2 | `.../ms-smb2/829f93f5-ed10-4f12-8347-42d235019459`, `.../ms-smbd/73412f19-a712-493b-b89e-c678e21bf91f` | The Token in the first element "MUST additionally be supplied, as specified in [MS-SMBD] section 3.1.4.2" for V1_INVALIDATE. There is no statement mandating disconnect on token reuse. | UNVERIFIED (spec silent). It neither supports nor contradicts WINDOWS_BEHAVIOUR. |
| RemoteInvalidation Read_..._INVALIDATE | Same | MS-SMB2 3.3.5.12 | `.../ms-smb2/21e8b343-34e9-4fca-8d93-03dd2d3e961e` | Same absence. | UNVERIFIED |
| RemoteInvalidation SMB 3.0.2 context | RDMA_V1_INVALIDATE validity by dialect | MS-SMB2 2.2.21, 3.3.5.13 | `.../ms-smb2/e7046961-3318-4350-be2a-a8d69bb59ce8` | Q10. For 3.0.2, Channel must be V1_INVALIDATE, V1 or NONE. | SUPPORTS that V1_INVALIDATE is valid on 3.0.2 (and invalid on 3.0) |
| Write_SMB2_CHANNEL_RDMA_V1 | The name says RDMA_V1 but the code requires the RDMA_TRANSFORM+SIGNING capability | MS-SMB2 3.3.5.4; 2.2.43 | as above | Q1, Q3, Q4. | SUPPORTS |
| Read_SMB2_CHANNEL_RDMA_V1 | Same | Same | Same | Same. | SUPPORTS |
| Cleanup (DeleteFile.ps1 on Windows driver) | Infra leak | N/A (test-code defect) | – | – | N/A |

## encryption.md

All 24 tests failed at TREE_CONNECT. The reachability of the 3.3.5.13 branches depends on the server advertising RDMA transform support.

| Test | Claimed defect | Spec section | URL | Verbatim quote | Verdict |
|---|---|---|---|---|---|
| 1-5 ReadLargeFile_* (CCM/GCM, 128/256) (sec: TEST_INACCURATE) | No capability gate; asserts "Server must select SMB2_RDMA_TRANSFORM_ENCRYPTION" | MS-SMB2 3.3.5.4; 2.2.43 | `.../ms-smb2/b39f253e-4963-40df-8dff-2f9040ebbeb1` | Q1, Q3, Q4. | SUPPORTS (selection is optional) |
| 1-4 AES256 / GCM-only variants mislabeled (Smb2Negotiate overrides encryptionAlgs) | Test code | N/A (test-code defect) | – | – | N/A |
| 6-10 WriteLargeFile_* (sec: TEST_INACCURATE) | Same | Same | Same | Same. | SUPPORTS |
| 11 WriteLargeFile_NoTransformIds_Fails | Needlessly requires SMB3 encryption; the expected status itself is spec-correct | MS-SMB2 3.3.5.13 | `.../ms-smb2/829f93f5-ed10-4f12-8347-42d235019459` | Q5: INVALID_PARAMETER "if Connection.RDMATransformIds is empty". | SUPPORTS (the expectation is spec-correct; the encryption dependency is a test-code defect) |
| 12 ZeroTransformCount_Fails (sec: TEST_INACCURATE) | Cannot isolate TransformCount; ksmbd returns INVALID_PARAMETER for another reason | MS-SMB2 3.3.5.13; 2.2.43 | as above | Q5: TransformCount is 0; 2.2.43 "TransformCount … MUST be greater than 0". Q5 also lists the empty-RDMATransformIds condition, which gives the same status. | SUPPORTS (the two conditions are indistinguishable) |
| 13 MultipleEncryptionStructure_Fails (sec: TEST_INACCURATE) | Gate issue | MS-SMB2 3.3.5.13 | as above | Q5: "more than one ENCRYPTION … transform is present". | SUPPORTS the expectation. The gate issue is a test-code defect. |
| 14 EncryptionAndSigningStructure_Fails | The "signing" struct is built with TYPE_ENCRYPTION and never added; TransformCount/offset inconsistent | MS-SMB2 2.2.43.1; 3.3.5.13 | `.../ms-smb2/dd590f6e-14a4-4f62-bc66-2a177005df7c` | 2.2.43.1: TransformType "MUST be set to one of": ENCRYPTION 0x0001, SIGNING 0x0002. Q5: one ENCRYPTION plus one SIGNING is present gives INVALID_PARAMETER. | SUPPORTS (the combination needs a SIGNING TransformType). The construction defect is N/A (test code). |
| 15 BufferNotAligned_Fails (sec: TEST_INACCURATE) | Gate issue | MS-SMB2 3.3.5.13; 2.2.43.1 | as above | Q5 (8-byte alignment). 2.2.43.1 Padding: "present after Nonce so the channel information, if any, after this structure starts at the first 8-byte aligned offset." | SUPPORTS the expectation |
| 16 IncreaseSignatureLength_Fails | Expects AUTH_TAG_MISMATCH; a non-supporting server returns INVALID_PARAMETER | MS-SMB2 3.3.5.13 | as above | Q6 (ENCRYPTION branch) and Q5 (INVALID_PARAMETER when RDMATransformIds lacks ENCRYPTION). | SUPPORTS |
| 17-20 IncreaseNonceLength_* (CCM/GCM, 128/256) | Same | Same | Same | Q6: CCM NonceLength 11, GCM NonceLength 12. | SUPPORTS |
| 21-24 DecreaseNonceLength_* | Same | Same | Same | Q6. | SUPPORTS |
| Read path DataLength includes 8-byte padding (WINDOWS_BEHAVIOUR secondary) | Padding assumption | MS-SMB2 3.3.5.12 | `.../ms-smb2/21e8b343-34e9-4fca-8d93-03dd2d3e961e` | DataLength is set to the "sum of the sizes of SMB2_RDMA_TRANSFORM and SMB2_RDMA_CRYPTO_TRANSFORM structures". There is no padding statement on this page. | UNVERIFIED (the spec is silent on padding at this point) |

## signing.md

| Test | Claimed defect | Spec section | URL | Verbatim quote | Verdict |
|---|---|---|---|---|---|
| Signing_WriteLargeFile_AES_GMAC | No Assume on the negotiated transform; INVALID_PARAMETER is spec-conformant | MS-SMB2 3.3.5.13; 3.3.5.4 | `.../ms-smb2/829f93f5-ed10-4f12-8347-42d235019459` | Q5 (INVALID_PARAMETER if RDMATransformIds is empty or lacks SIGNING) and Q3. | SUPPORTS |
| Signing_WriteLargeFile_AES_CMAC | Same | Same | Same | Same. | SUPPORTS |
| Signing GMAC deviation (secondary: ksmbd lacks feature) | The server must still return a signing context | MS-SMB2 3.3.5.4 | `.../ms-smb2/b39f253e-4963-40df-8dff-2f9040ebbeb1` | Q9. | SUPPORTS |
| FlagsSignedNotSet_Fails | The test never clears SMB2_FLAGS_SIGNED; the encrypted TREE_CONNECT gets no reply (ENV_CONFIG/KSMBD, unresolved) | MS-SMB2 3.3.5.13 | `.../ms-smb2/829f93f5-ed10-4f12-8347-42d235019459` | Q5: INVALID_PARAMETER if a SIGNING transform is present and SMB2_FLAGS_SIGNED is not set. | SUPPORTS that the intended scenario is valid. The test not clearing the flag is a test-code defect. The TREE_CONNECT drop is UNVERIFIED. |
| InvalidSignature_Fails | Expects INVALID_SIGNATURE; got INVALID_PARAMETER; correct only if SIGNING was negotiated | MS-SMB2 3.3.5.13 | same | Q7. | SUPPORTS |
| ZeroTransformCount_Fails | Vacuous pass: RDMATransformIds is empty, not TransformCount=0 | MS-SMB2 3.3.5.13 | same | Q5: both "TransformCount is 0" and "RDMATransformIds is empty" give INVALID_PARAMETER. | SUPPORTS |
| Read tests (secondary tag) | They have an Assume gate | N/A (test-code defect) | – | – | N/A |
