# MS-SMBD channel tests audit (rpt-channel)

Scope: Smb2OverRdmaChannel (9), Smb2MultiChannelOverRdma (2), Smb2OverRdmaChannelRemoteInvalidation (6).
SUT: Linux ksmbd 192.168.10.12 (Platform=NonWindows); driver Windows 192.168.10.11.
Evidence: `C:\WPTS-Diagnostics\session-20261008-102557\tests\*\ptf-log.ndjson`; one pcap check (see below).

**Caveat:** `full.trx` had NOT appeared by 12:06 (about 100 min after the 10:26 start), so there is no authoritative exception text. Results come from PTF logs. Exceptions for 3 tests are "unverified".

## Summary

| Test | Result | Verdict | Conf. | Reason |
|---|---|---|---|---|
| Smb2OverRdmaChannel.BVT_ReadLargeFile | FAIL (READ -> STATUS_END_OF_FILE) | ENV_CONFIG (2nd: TEST_INACCURATE) | med | Pre-provisioned `testFile_ReadLargeFile.txt` appears empty/missing; `Smb2Create` uses FILE_OPEN_IF, masking this |
| ..._ReadMultipleOperation | FAIL (same EOF) | ENV_CONFIG | med | Same cause |
| ..._BVT_WriteLargeFile | FAIL (SIGNING assert) | TEST_INACCURATE (2nd: WINDOWS_BEHAVIOUR) | high | Asserts server MUST return SMB2_RDMA_TRANSFORM_SIGNING; optional per MS-SMB2 |
| ..._WriteMultipleOperation | FAIL (SIGNING assert) | TEST_INACCURATE (WINDOWS_BEHAVIOUR) | high | Same |
| ..._ReadWriteMultipleBufferDescriptorList | FAIL (SIGNING assert) | TEST_INACCURATE (WINDOWS_BEHAVIOUR) | high | Same |
| ..._InvalidBufferDescriptor_Offset | PASS (vacuous) | TEST_INACCURATE | high | READ hit EOF, so AreNotEqual(SUCCESS) holds without exercising the bad descriptor |
| ..._InvalidBufferDescriptor_Length | PASS (vacuous) | TEST_INACCURATE | high | Same |
| ..._InvalidBufferDescriptor_Token | PASS (vacuous) | TEST_INACCURATE | high | Same |
| ..._InvalidBufferDescriptor_DeregisteredBuffer | PASS (vacuous) | TEST_INACCURATE | high | Same |
| Smb2MultiChannelOverRdma.BVT_..._2Channels_DiffNicTypeDiffTransport | FAIL (no message in log) | ENV_CONFIG (likely; unverified) | low | Uses non-RDMA NIC pair 192.168.20.x; exception text unavailable |
| ..._Smb2Multichannel_2Channels_DiffTransport | PASS | TEST_INACCURATE (weak asserts) | med | Passes, but write does not slice data and the trailing asserts re-check a stale `status` |
| RemoteInvalidation.BVT_Smb302_Write_..._INVALIDATE | FAIL (no message) | WINDOWS_BEHAVIOUR (2nd: KSMBD_FAILURE) | low | Final assertion requires the connection to be terminated after token reuse; the spec does not mandate that; exception unverified |
| ..._BVT_Smb302_Read_..._INVALIDATE | FAIL (no message) | WINDOWS_BEHAVIOUR (2nd: KSMBD_FAILURE) | low | Same; the long runtime suggests slow 1 MiB inline seeding |
| ..._Write_SMB2_CHANNEL_RDMA_V1 | FAIL (SIGNING assert) | TEST_INACCURATE | high | Name says RDMA_V1 but the code requires the RDMA_TRANSFORM+SIGNING capability |
| ..._Read_SMB2_CHANNEL_RDMA_V1 | FAIL (SIGNING assert) | TEST_INACCURATE | high | Same |
| ..._Smb300_Write_..._INVALIDATE | PASS (STATUS_INVALID_PARAMETER) | ACCURATE | high | MS-SMB2 3.3.5.13 / 2.2.21 |
| ..._Smb300_Read_..._INVALIDATE | PASS (STATUS_INVALID_PARAMETER) | ACCURATE | high | MS-SMB2 3.3.5.12 |

Counts: ACCURATE 2, TEST_INACCURATE 11 (incl. 4 vacuous passes, 5 SIGNING asserts, 1 weak multichannel pass, and 1 where it is secondary), WINDOWS_BEHAVIOUR 2 (low), ENV_CONFIG 3 (2 med, 1 low).
Precisely: primary verdicts are ACCURATE 2, ENV_CONFIG 3, WINDOWS_BEHAVIOUR 2, TEST_INACCURATE 10. KSMBD_FAILURE 0 confirmed.

## Spec references (Learn)
- MS-SMB2 3.3.5.4 Negotiate: https://learn.microsoft.com/openspecs/windows_protocols/ms-smb2/b39f253e-4963-40df-8dff-2f9040ebbeb1
  - Step 10.1: if RDMA transforms are unsupported, the server MUST ignore the SMB2_RDMA_TRANSFORM_CAPABILITIES context.
  - Step 4.1.1: with an empty RDMATransformIds list the response carries TransformCount=1 with SMB2_RDMA_TRANSFORM_NONE.
- MS-SMB2 2.2.21 WRITE: https://learn.microsoft.com/openspecs/windows_protocols/ms-smb2/e7046961-3318-4350-be2a-a8d69bb59ce8
  - RDMA_V1_INVALIDATE is not valid for the SMB 3.0 dialect.
- MS-SMB2 3.3.5.13 Write: https://learn.microsoft.com/openspecs/windows_protocols/ms-smb2/829f93f5-ed10-4f12-8347-42d235019459
  - The server MUST fail with STATUS_INVALID_PARAMETER for an invalid channel on dialect 3.0.
- MS-SMB2 3.3.5.12 Read: https://learn.microsoft.com/openspecs/windows_protocols/ms-smb2/21e8b343-34e9-4fca-8d93-03dd2d3e961e
  - For RDMA channels without a transform, DataLength MUST be 0 and the data is sent via RDMA Write.
  - STATUS_END_OF_FILE applies at or past EOF.
- MS-SMB2 3.2.4.7 Client write: https://learn.microsoft.com/openspecs/windows_protocols/ms-smb2/49dce94d-71fd-4fdf-b730-a60d6b27fbba
- MS-SMBD 3.1.4.2 Send: https://learn.microsoft.com/openspecs/windows_protocols/ms-smbd/73412f19-a712-493b-b89e-c678e21bf91f
- MS-SMBD 3.1.5.8 Receive data transfer: https://learn.microsoft.com/openspecs/windows_protocols/ms-smbd/c860aa40-cf59-4020-adf3-4fd587d23c89
- MS-SMBD 3.1.4.5 RDMA Write: https://learn.microsoft.com/openspecs/windows_protocols/ms-smbd/c8a3df70-3c52-4ac3-9cb9-acbe2886130a
- MS-SMBD 3.1.4.6 RDMA Read: https://learn.microsoft.com/openspecs/windows_protocols/ms-smbd/b9251da1-ef25-4188-bc33-0a0358bb2667

Cross-cutting: MS-SMB2 defines no status for a bad, deregistered or reused token. Windows drops the connection. So those checks cannot be derived from the spec.

## Per-test details

### 1. BVT_ReadLargeFile / 2. ReadMultipleOperation
- **Purpose:** read a pre-provisioned file over SMB2_CHANNEL_RDMA_V1 and validate the content (MS-SMB2 3.3.5.12, MS-SMBD 3.1.4.5).
- **Does:** connect over RDMA, open `TestFile_ReadLargeFile` (`testFile_ReadLargeFile.txt`), issue a READ with readSize 4194304 (the ReadMultipleOperation test issues 64 of them), assert STATUS_SUCCESS (Smb2OverRdmaChannel.cs ~line 562).
- **Observed:** the READ response is STATUS_END_OF_FILE (DataRemaining=0, DataLength=0). The pcap for ReadLargeFile shows only the negotiate, session and tree-connect SENDs and create/read headers, with no RDMA WRITE/READ traffic. The DREQ comes at ~2.4 s.
- **Cause:** the file is empty or absent. `Smb2Create` uses FILE_OPEN_IF (Smb2OverSmbdTestClient.cs:589), so a missing file is silently created empty. An empty file -> EOF is spec-correct server behaviour. I did not read the SUT share (unverified, but this is the only consistent explanation).
- **Verdict:** ENV_CONFIG, med. Secondary TEST_INACCURATE: the test should open with FILE_OPEN, or write the content first.
- **Fix:** provision the file with LargeFileSizeInKB of data on the share, or seed it from the test.

### 3-5. BVT_WriteLargeFile, WriteMultipleOperation, ReadWriteMultipleBufferDescriptorList
- **Spec:** MS-SMB2 3.3.5.4 steps 10.1 and 4.1.1 make RDMA transform support an optional server capability. A server without it answers with SMB2_RDMA_TRANSFORM_NONE.
- **Test:** `WriteOverRdma` Assert.IsTrue(the negotiate context contains SIGNING) with the message "Server MUST return SMB2_RDMA_TRANSFORM_SIGNING…". It fails on ksmbd. The assert text claims a MUST that the spec does not state.
- **Further issues:** dead variables (`fileContent`, `totalSize`); `needsSigning` derives from CryptoInfoTable.Count.
- **Verdict:** TEST_INACCURATE, secondary WINDOWS_BEHAVIOUR (Windows Server 2022+ only), high. ksmbd is not at fault.
- **Fix:** make the transform optional, falling back to plain RDMA_V1 or reporting Inconclusive when the server returns NONE.

### 6-9. InvalidBufferDescriptor_Offset / _Length / _Token / _DeregisteredBuffer
- **Spec:** no mandated status. The only fact is that the RDMA operation result goes to the upper layer (MS-SMBD 3.1.4.5/3.1.4.6).
- **Observed:** all PASS, but the READ returned STATUS_END_OF_FILE because of the empty file. The corrupted descriptor was never used, so `AreNotEqual(SUCCESS)` holds vacuously. The pcap shows no RDMA WRITE.
- **Other defects:**
  - the TimeoutException path calls `Assert.Pass` inside the catch;
  - the availability re-connect does not check its status;
  - the log says "SMB2 WRITE" for a READ step;
  - the READ length is Smb2MaxReadSize rather than the effective plan size;
  - the "Offset" case sets Offset = bufferSize + 1, which is just a wrong virtual address.
- **Verdict:** TEST_INACCURATE, high.
- **Fix:** assert on the pre-condition (valid read succeeds with data) first. Accept the spec-agnostic outcomes explicitly (error status, or disconnect), and do not Assert.Pass on timeout.

### 10. BVT_Smb2MultipleChannel_2Channels_DiffNicTypeDiffTransport
- **Purpose:** multichannel with a TCP main channel on the non-RDMA NIC and an RDMA alternate (MS-SMB2 multichannel and session binding).
- **Observed:** FAIL after about 2 s. The log has only a DeleteFile.ps1 CheckFailed ("Cannot find path 'TestDrive:\<guid>.txt'") and then TestFailed. No assertion message.
- **Cause:** exception unverified. Probable cause: the 192.168.20.111/.112 non-RDMA network is unreachable or unconfigured on the ksmbd side.
- **Verdict:** ENV_CONFIG, low. The DeleteFile.ps1 error is cleanup noise (see Cross-cutting).

### 11. Smb2Multichannel_2Channels_DiffTransport
- **Result:** PASS. ksmbd handled TCP main + RDMA alternate binding.
- **Weaknesses:**
  - `WriteFromMainChannel` sends the whole `content` on every iteration instead of slicing it;
  - only the read over RDMA is verified;
  - the final TreeDisconnect/LogOff results are discarded and a stale `status` is re-asserted, so those asserts are vacuous.
- **Verdict:** TEST_INACCURATE (weak assertions), med. It does show multichannel working in practice.

### 12-13. BVT_Smb302_Write / Read_..._INVALIDATE
- **Spec:** RDMA_V1_INVALIDATE is valid on 3.0.2 (MS-SMB2 2.2.21). The server must supply the token for remote invalidation (MS-SMBD 3.1.4.2). Reuse of an invalidated token has no mandated status.
- **Test:** performs the invalidating write or read, then reuses the same descriptor and asserts `Assert.IsFalse(ClientConnection.Endpoint.IsConnected)`, i.e. a Windows-style connection kill. It also has `catch {}` blocks that swallow all errors.
- **Observed:** TestFailed with no message after the step "Write content to file over RDMA" (Write, at 10:26:53) or "Read content from file over RDMA at offset 0" (Read, at 10:34:11). The Read test spent ~7.5 min before this, probably on the 1 MiB inline seeding; the log shows ~1680 successful checks for the seed.
- **Exception text and pcap analysis:** unverified (no full.trx).
- **Verdict:** WINDOWS_BEHAVIOUR for the final assert, low confidence. Secondary KSMBD_FAILURE is possible if ksmbd does not do remote invalidation or mishandles the request.
- **Fix:** do not require disconnect. Verify that the first operation succeeded, then accept any error or disconnect on reuse. Remove `catch {}`.

### 14-15. Smb2OverRdma_Write / Read_SMB2_CHANNEL_RDMA_V1
- **Observed:** FAIL at the SIGNING assert in `EstablishSignedRdmaConnectionAndOpenFile` (line ~515). Same defect as the tests above.
- **Naming problem:** the names say CHANNEL_RDMA_V1 but the write uses CHANNEL_RDMA_TRANSFORM with SIGNING. The Read variant seeds with a TRANSFORM write and then reads with RDMA_V1 twice with the same descriptor (a non-invalidating channel).
- **Verdict:** TEST_INACCURATE, high. Rename, or make them conditional on the capability.

### 16. Smb2OverRdma_Smb300_Write_..._INVALIDATE
- **Spec:** MS-SMB2 2.2.21 and 3.3.5.13: RDMA_V1_INVALIDATE on dialect 3.0 -> the server MUST fail with STATUS_INVALID_PARAMETER.
- **Observed:** PASS with STATUS_INVALID_PARAMETER.
- **Verdict:** ACCURATE, high.

### 17. Smb2OverRdma_Smb300_Read_..._INVALIDATE
- **Spec:** MS-SMB2 3.3.5.12: dialect 3.0 with a channel other than RDMA_V1 or NONE -> STATUS_INVALID_PARAMETER.
- **Observed:** PASS. Log: "Assert.AreEqual succeeded. SMB2 READ over RDMA should fail with STATUS_INVALID_PARAMETER if set Channel CHANNEL_RDMA_V1_INVALIDATE on SMB 3.0 dialect." (10:43:49).
- **Verdict:** ACCURATE, high.

## Cross-cutting
- Cleanup (DeleteFile.ps1) runs on the Windows driver against `TestDrive:\`, so files created on the Linux share are never removed. `TestCleanup` swallows the errors. Result: leaked files on the SUT and CheckFailed noise (TEST_INACCURATE infra).
- The deployment config says Platform=NonWindows, so the Windows-only Inconclusive guards are never hit.
- Debug leftovers: a "DIAGNOSTIC BUILD" line in `ReadOverRdma`.
- Pcap: I only parsed the ReadLargeFile pcap fully (CM handshake, SMB2 over SMBD SENDs, no RDMA READ/WRITE, DREQ at 2.4 s). Other pcaps were not analysed.
