# MS-SMBD server suite - test team report

Scope: tests that fail or pass incorrectly because of test, adapter or SDK defects (not the SUT). Control: Windows Server 2025 (see ksmbd report for run table).

## Fixed in this change
| Test(s) | Defect | Fix |
|---|---|---|
| `Smb2OverRdmaChannel_WriteLargeFile/WriteMultipleOperation/ReadWriteMultipleBufferDescriptorList` (`Smb2OverRdmaChannel.cs`) | Hard `Assert` that the server selects SIGNING RDMA transform; optional per [MS-SMB2] 3.3.5.4 / 2.2.43 | `Assume` |
| `Signing_Write_AES_GMAC/CMAC/InvalidSignature` (`Smb2OverRdmaChannelTransformSigning.cs`) | Missing the `Assume` the Read variants have; with no transform negotiated server correctly returns INVALID_PARAMETER ([MS-SMB2] 3.3.5.13) | `Assume` only when the test offers SIGNING (negative tests that omit it still run) |
| `BVT_Smb2OverRdma_Smb302_Write/Read_SMB2_CHANNEL_RDMA_V1_INVALIDATE` and `EstablishSignedRdmaConnectionAndOpenFile` (`...RemoteInvalidation.cs`) | Fail on Windows Server 2025 over RoCE (WRITE: STATUS_INVALID_PARAMETER from the server; READ: client 0xC0000005). Upstream main already guards both; our first commit commented the guards out. Signing assertion hard-failed | Guards restored; `Assume` on SIGNING |
| `ReadOverRdma_Encryption` AES-256 tests (`...TransformEncryption.cs`) | `Smb2Negotiate` overwrote the requested cipher list with CCM+GCM when `addDefaultEncryption` is true, so AES-256 tests never offered AES-256 | `addDefaultEncryption: false`; `Assume` on ENCRYPTION selected |

Control run after fixes: 86 passed, 0 failed, 6 skipped on Windows Server 2025.

## Fixed in the spec-based fix round (validated on Windows Server 2025: 84 passed, 0 failed, 8 skipped)
Every change carries a WHAT/WHY/SPEC comment in the code.

| # | Defect | Fix |
|---|---|---|
| 1 | Credit tests misread empty credit-grant messages; idle tests asserted Windows-only timers/flags | `ValidateReadResponse` skips empty Data Transfer messages ([MS-SMBD] 3.1.5.4/3.1.5.8); idle tests accept Flags NONE or RESPONSE_REQUESTED; Windows 5 s/repeat timing gated by platform ([MS-SMBD] 3.1.6.2, Appendix B <4>, <8>) |
| 2 | Windows-only negotiate expectations | Already gated by `IsWindowsPlatform` / `WindowsMaxPreferredSendSize` |
| 3 | Vacuous passes | `InvalidBufferDescriptor_*` now reconnect and assert success; version-range tests no longer `Assert.Pass`; `AgainstFragmentReassemblyRemaining` is Inconclusive when its flag is off |
| 4 | Malformed requests | Real SIGNING structure and per-iteration `transformCount` in `EncryptionAndSigningStructure`; `FlagsSignedNotSet` really clears SMB2_FLAGS_SIGNED (`SetWriteRequestSigned`, [MS-SMB2] 3.3.5.13); V1 write test uses `CHANNEL_RDMA_V1` on 3.0.2 |
| 5 | `NegativeParameter_CreditRequested` description | Corrected |
| 6 | Reconnect race | `Initialize_SendSmbdDataTransferTestCase` retries connect/negotiate/session up to 3 times with a 5 s settle |
| 7 | `ExpectPacket` hides real status | Message carries the NTSTATUS (type kept as `TimeoutException`, which callers catch) |
| 8 | Large file not provisioned | READ-init reports Inconclusive on STATUS_OBJECT_NAME_NOT_FOUND |

New platform finding: Windows Server 2025 over RoCE rejects every V1-family WRITE (V1 and V1_INVALIDATE, 3.0.2 and 3.1.1) with STATUS_INVALID_PARAMETER, although [MS-SMB2] 3.3.5.13 allows V1. `Smb2OverRdma_Write_SMB2_CHANNEL_RDMA_V1` is gated Inconclusive on 2025 and runs on other platforms.

## Fixed after the Ubuntu (ksmbd) runs
| # | Defect | Fix |
|---|---|---|
| 9 | `SMB2_FLAGS_SIGNED` was set on every request, even for encryption-only sessions (zero signature) | Flag is set only when the session signs ([MS-SMB2] 2.2.1, 3.3.5.2.4) |
| 10 | Client kept crypto state across reconnects. A server that reuses a SessionId on a new connection (ksmbd does, Windows does not) made `GenerateCryptoKeys` treat it as re-authentication with the old key, giving "bad smb2 signature" / ACCESS_DENIED | `cryptoInfoTable` is cleared in `ConnectToServerOverRDMA` ([MS-SMB2] 3.2.4.2). Fixes the multi-scenario `SmbdDataTransfer_NegativeParameter_DataLength_AgainstMessageLength`, `DataLength_AgainstMaxReceiveSize` and `DataOffset_AgainstMessageLength` on ksmbd |

Both are spec-level client defects; neither is gated by Platform. Validate on Windows Server 2025 when it is reconnected.

## Still open
`SmallLengthSegment`/`VariableLengthSegment` and `OperationWithMinimumCredits` stall on ksmbd (SUT issue, see ksmbd report); retest on Ubuntu to confirm.