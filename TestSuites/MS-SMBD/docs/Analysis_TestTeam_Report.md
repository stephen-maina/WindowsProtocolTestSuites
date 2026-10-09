# MS-SMBD server suite - test team report

Scope: tests that fail or pass incorrectly because of test, adapter or SDK defects (not the SUT). Control: Windows Server 2025 (see ksmbd report for run table).

## Fixed in this change
| Test(s) | Defect | Fix |
|---|---|---|
| `Smb2OverRdmaChannel_WriteLargeFile/WriteMultipleOperation/ReadWriteMultipleBufferDescriptorList` (`Smb2OverRdmaChannel.cs`) | Hard `Assert` that the server selects SIGNING RDMA transform; optional per [MS-SMB2] 3.3.5.4 / 2.2.43 | `Assume` |
| `Signing_Write_AES_GMAC/CMAC/InvalidSignature` (`Smb2OverRdmaChannelTransformSigning.cs`) | Missing the `Assume` the Read variants have; with no transform negotiated server correctly returns INVALID_PARAMETER ([MS-SMB2] 3.3.5.13) | `Assume` only when the test offers SIGNING (negative tests that omit it still run) |
| `BVT_Smb2OverRdma_Smb302_Write/Read_SMB2_CHANNEL_RDMA_V1_INVALIDATE` and `EstablishSignedRdmaConnectionAndOpenFile` (`...RemoteInvalidation.cs`) | Fail on Windows Server 2025 over RoCE (provider has no memory windows; STATUS_INVALID_PARAMETER / 0xC0000005). Original `Inconclusive` guards had been commented out. Signing assertion hard-failed | Guards restored; `Assume` on SIGNING |
| `ReadOverRdma_Encryption` AES-256 tests (`...TransformEncryption.cs`) | `Smb2Negotiate` overwrote the requested cipher list with CCM+GCM when `addDefaultEncryption` is true, so AES-256 tests never offered AES-256 | `addDefaultEncryption: false`; `Assume` on ENCRYPTION selected |

Control run after fixes: 86 passed, 0 failed, 6 skipped on Windows Server 2025.

## Open test defects (not yet fixed; prioritised)
Details with line numbers and spec quotes: `docs/analysis/` (copies of the group reports).

1. **Credit tests misreading empty credit-grant messages** (`ConsumeAllReceiveCredits`, `ReceiveMaxReceiveSize`, `IdleConnection_Client/Server`): `ValidateReadResponse` treats ksmbd's legal empty credit grant ([MS-SMBD] 3.1.5.8) as the first READ data; idle tests assert `CreditsGranted > 0` and `Flags == NONE` although zero grant is legal, and read the second empty reply as the next keepalive. Also "exactly 10 credits" and the Send Credit Grant Timer are not in the spec; idle timers 120 s/5 s are Windows Appendix B defaults.
2. **Windows-only expectations**: `NegotiateBasicChecker` asserts `MaxReadWriteSize >= 1 MiB`; `PreferredSendSizeMaxValue` has a stale 8136 branch (Appendix B says "and later").
3. **Weak/vacuous passes**: version-range negotiate tests swallow `TimeoutException` with `Assert.Pass`; `InvalidBufferDescriptor_*` use `catch(TimeoutException){Assert.Pass}`; `ZeroTransformCount` and `AgainstFragmentReassemblyRemaining` (with `CheckDataLengthRemainingDataLength=false`) pass without assertions.
4. **Malformed requests**: `EncryptionAndSigningStructure` (two ENCRYPTION structs, TransformCount 3 with 2 appended); `WriteMultipleOperation` reuses nonce/ciphertext/signature; `transformCount` not reset per loop iteration; `FlagsSignedNotSet` never builds its scenario (adapter always sets SIGNED); `Smb2OverRdma_Write/Read_SMB2_CHANNEL_RDMA_V1` actually use CHANNEL_RDMA_TRANSFORM.
5. **Description errors**: `NegativeParameter_CreditRequested` says Negotiate Request but sends a data transfer.
6. **Setup race**: three `NegativeParameter_*` tests reconnect 50 ms after killing the first session; add a 6-10 s settle and tree-connect retry.
7. **Adapter**: `ExpectPacket` reports every bad status as `TimeoutException`; surface the real status. A credit ping-pong and inline writes chunked at ~1.25 KB observed in the SDK (medium confidence).
8. **Environment**: no script creates `testFile_ReadLargeFile.txt` on non-Windows SUTs; add a preflight check.
