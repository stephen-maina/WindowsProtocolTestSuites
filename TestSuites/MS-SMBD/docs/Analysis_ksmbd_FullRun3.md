# MS-SMBD full run #3 against Ubuntu ksmbd

- SUT: Ubuntu, kernel 7.0.0-38-generic, ksmbd (in-kernel), ConnectX-4 Lx RoCE, 192.168.10.12 / 192.168.20.112.
- Driver: Windows, ConnectX-4 Lx, `Platform=NonWindows`, `DriverPlatform=WindowsServer2025`.
- Evidence per test: `C:\WPTS-Diagnostics\session-20261011-053501\tests\<test>\` (`rdma.pcap`, `sut-linux-dmesg.log` with ksmbd debug for smb/conn/rdma, `ptf-log.ndjson`).
- Result: **92 tests: 41 passed, 38 failed, 13 skipped/inconclusive** (1 h 46 m). Previous ksmbd run: 54 failed. **No test failed that did not already fail**; 7 previously failing tests now pass and 9 are now correctly inconclusive.

## What changed since run #2 (test fixes, each with a spec reference in the code)

| Change | Spec | Effect |
|---|---|---|
| `SMB2_FLAGS_SIGNED` set only when the session signs (`Smb2OverSmbdTestClient.SessionRequestFlags`) | [MS-SMB2] 3.3.5.2.4, 2.2.1 | no more `bad smb2 signature` on ksmbd |
| `cryptoInfoTable` cleared on every new RDMA connection | [MS-SMB2] 3.3.5.5.1 (a SessionId only has to be unique among *active* sessions, so reuse after free is legal) | `DataTransfer_NegativeParameter_DataLength_*` pass; ksmbd reuses SessionId 1, Windows does not, both compliant |
| RDMA transform tests gated as inconclusive when the server does not select `SMB2_RDMA_TRANSFORM_SIGNING` | [MS-SMB2] 3.3.5.4 (the transform is optional) | 9 tests went from fail to inconclusive; the wording of one remaining `Assume` message no longer says "MUST" |
| SMB 3.0 `READ` + `CHANNEL_RDMA_V1_INVALIDATE` negative test seeds a 4 KiB file instead of 1 MiB | [MS-SMB2] 3.3.5.12 (the dialect/channel check precedes any data access) | 1 MiB of inline writes was ~840 round trips at ksmbd's 1364-byte MaxSendSize; the run hung for 2 h on this test |

## Remaining 38 failures

All of them are ksmbd behaviour that contradicts the spec. None depends on Windows-specific behaviour.

### A. Encrypted SMB2 over SMB Direct (26 tests)
`Smb2OverRdmaChannelTransform_Encryption_*` (24) and `..._Signing_*_Fails` (2).

- All 26 fail in the shared setup (`InitSmbdConnectionForTestCases` / `Smb2EstablishSessionAndOpenFile`), at the **first encrypted TREE_CONNECT**, with `SMBD ReceiveMessage failed ... waiting for the SMB2 response`. The malformed-transform scenarios of the `_Fails` tests are never reached.
- SUT log, identical in all 26: ksmbd decrypts and processes the request (`Received smb2 tree connect request`, `tree connect request for tree smbdtest`), and then `ksmbd: Failed to send message: -22` instead of `smb_direct: Sending smb (RDMA)`. The response is dropped and the connection stays open.
- The same SDK client passes all 24 encryption tests on Windows Server 2025, and the decryption on ksmbd succeeds, so the keys, nonce and transform header are right.
- Conclusion: ksmbd defect in the SMB Direct send path for transform-encrypted responses (EINVAL from `smb_direct_writev`). Spec: [MS-SMB2] 3.3.4.1.4 (the server MUST encrypt the response and send it) and [MS-SMBD] 3.1.4.

### B. Credit management and negotiate (ksmbd defects)
| Tests | Observation | Spec |
|---|---|---|
| `SmbdCreditMgmt_ConsumeAllReceiveCredits` | every read fragment, including the one that uses the last credit, has `credits_granted=0` | [MS-SMBD] 3.1.5.1 |
| `SmbdCreditMgmt_NegativeParameter_CreditRequested` | connection not terminated | [MS-SMBD] 3.1.5.8 |
| `SmbdDataTransfer_NegativeParameter_AgainstMaxFragmentedSize`, `_DataOffset_Against8ByteAligned`, `_RemainingDataLength_Zero` | connection not terminated on an invalid data transfer header | [MS-SMBD] 3.1.5.8 |
| `SmbdNegotiate_NegativeParameter_MaxReceiveSize` / `_MaxFragmentedSize` | negotiate with the boundary values 128 / 131072 gets STATUS_CANCELLED | [MS-SMBD] 3.1.5.6, 3.1.5.7 |
| `SmbdNegotiate_PreferredSendSizeLessThan128` / `_WithZero` | negotiate response `MaxFragmentedSize` 16192 / 0, below the 131072 minimum | [MS-SMBD] 3.1.5.6 |
| `SmbdDataTransfer_SmallLengthSegment` / `_VariableLengthSegment`, `BVT_SmbdCreditMgmt_OperationWithMinimumCredits` | ksmbd stops granting credits until its ~120 s keepalive (255 one-byte fragments, or 1 credit) | [MS-SMBD] 3.1.5.1, 3.1.5.8 |

Details and packet evidence for each row are in `Analysis_ksmbd_Report.md`.

## New observation: credit-only message storm (not yet attributed)
While a `WRITE` response was pending on the 1364-byte MaxSendSize connection, the SUT log shows ~1500 empty data-transfer messages (`data_length=0 credits_granted=1 credits_requested=255`) between consecutive SMB2 requests, i.e. the client and ksmbd answer each other's credit-only messages. Both sides grant a single credit per message, so the exchange does not settle until the SMB2 response is delivered. ksmbd debug logging amplifies the cost, and the effect was only a slowdown (about 1 s per request), so it is not a pass/fail issue today. Which side should stop replying is not yet established; [MS-SMBD] 3.1.5.1 only requires a credit grant when the last send credit is about to be used. Follow-up: compare with the same sequence on Server 2025 (pcap) before changing the client policy in `SmbdClient.ReceiveMessage`.

## Next
1. Reconnect Server 2025 (`Platform=WindowsServer2025`) and run the full suite; the baseline is 84 passed, 0 failed, 8 skipped. Expected differences are only the test changes listed above.
2. Report A and B to the ksmbd owners.
