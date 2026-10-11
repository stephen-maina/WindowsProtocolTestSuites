# MS-SMBD server suite - ksmbd team report

Prepared from three full-suite runs on Mellanox ConnectX-4 Lx (RoCEv2), driver Windows 192.168.10.11.

| Run | SUT | Passed | Failed | Skipped/NotExecuted |
|---|---|---|---|---|
| 1 | Linux ksmbd | 32 | 58 | 2 |
| 2 | Linux ksmbd (after test file and 2nd NIC fixed) | 36 | 54 | 2 |
| 3 (control) | Windows Server 2025 | 86 | 2 | 4 |
| 4 (control, after test fixes) | Windows Server 2025 | 86 | 0 | 6 |

The two control failures (RDMA remote-invalidation tests) are a NIC/provider limitation and are now guarded as Inconclusive; they are not SUT issues.
Evidence: per-test `rdma.pcap` (Mellanox sniffer), `ptf-log.ndjson`, trx files; ksmbd source reviewed from upstream `torvalds/linux` `fs/smb/server` (`af32da41b0`). SUT-side logs were not available (no SSH).

## Confirmed ksmbd deviations

### 1. SMB Direct negotiate minimums ([MS-SMBD] 3.1.5.6 / 3.1.5.7)
- Client sends `PreferredSendSize` 0 and 127: ksmbd replies `MaxReceiveSize` < 128 and `MaxFragmentedSize` 0 / 16192.
- ksmbd rejects the valid boundary values `MaxReceiveSize` = 128 and `MaxFragmentedSize` = 131072, where the spec states they must be "at least" these values.
- Tests: `SmbdNegotiate_*` (4 failures). Windows control passes.

### 2. Invalid data-transfer messages not terminating the connection ([MS-SMBD] 3.1.5.8)
ksmbd keeps the connection open for: unaligned `DataOffset`; `DataLength + RemainingDataLength > MaxFragmentedSize`; `RemainingDataLength = 0` with reassembly pending; `CreditsRequested = 0`. Spec requires the connection to be terminated. Windows terminates.
Tests: `SmbdDataTransfer_NegativeParameter_*`, `SmbdCreditMgmt_NegativeParameter_CreditRequested`.

### 3. Credit stall with a small credit window
With 1 client credit (`BVT_..._OperationWithMinimumCredits`) and with reassembly of many small segments (`SmallLengthSegment`, `VariableLengthSegment`), ksmbd stops granting credits once receive buffers are held in reassembly. Client bookkeeping verified correct (263 sent against 263 granted). Windows control passes. (Mechanism medium confidence.)

### 4. Encrypted SMB2 over SMB Direct never answered (24 + 2 tests)
- Encrypted TREE_CONNECT (transform header, 254 bytes) receives no SMB2 reply; ksmbd sends only an empty SMBD credit-grant and does not disconnect. Client times out after ~120 s.
- Pcap: ksmbd selected cipher AES-128-CCM; SessionFlags 0; transform header well-formed (session id 2, 11-byte nonce, OriginalMessageSize 120, Flags 1).
- Control: Windows client to the same ksmbd over TCP with `/REQUIREPRIVACY` works and reads the 8 MB file. **Windows Server 2025 passes all 24 encryption tests with the same SDK client**, so the client framing/keys are correct.
- Upstream source: on decrypt failure `__handle_ksmbd_work` aborts the connection; older versions set `STATUS_DATA_ERROR` and drop the request silently when `response_buf` is NULL. Please check the SUT kernel version and `dmesg`/ksmbd logs for the decrypt path over `transport_rdma`.
- Not yet isolated whether the failure is specific to SMB Direct (RDMA path) or cipher/key derivation for this session; server-side trace needed.

### 5. RDMA transform capability not offered (informational)
ksmbd does not return `SMB2_RDMA_TRANSFORM_CAPABILITIES` (0x0007). Allowed by [MS-SMB2] 3.3.5.4 / 2.2.43 (optional); tests now `Assume` instead of asserting. Consider implementing: it is needed for signing/encryption transform over RDMA.

### 6. STATUS_ACCESS_DENIED on re-connect after a deliberate disconnect (unconfirmed)
Three `NegativeParameter_*` tests re-open a session 50 ms after killing the first connection; session setup succeeds but tree connect returns ACCESS_DENIED. Likely a teardown race in ksmbd; the test will wait/retry (see test report). Medium-low confidence.

## Not ksmbd issues (for context)
- `BVT_Smb2OverRdma_Smb302_*_INVALIDATE` fail on Windows Server 2025 too. Upstream `origin/main` already guards them as Inconclusive on Server 2025 and on RoCE with a Windows driver; the guards had been commented out in this branch. On 2025 the WRITE is rejected with STATUS_INVALID_PARAMETER before any RDMA transfer (well-formed request, Channel=2). Product behaviour of 2025, not a ksmbd issue.
- Empty credit-grant messages are legal ([MS-SMBD] 3.1.5.8); tests that treated them as data were fixed.

## Confirmed on kernel 7.0.0-38 with ksmbd debug (rdma/conn/smb): PreferredSendSizeWithZero
Client sent PreferredSendSize 0, MaxRecvSize 8192, MaxFragmentedSize 262144. ksmbd log: `MaxSendSize: 0 ... MaxFragmentedSize: 262144`, then it replied with MaxFragmentedSize 0.
Cause (ksmbd negotiate code): `sp->max_recv_size = min(sp->max_recv_size, preferred_send_size)` = 0, then `sp->max_fragmented_recv_size = (recv_credit_max * sp->max_recv_size) / 2` = 0, and that value is sent as the response MaxFragmentedSize. The server's own receive limit is derived from the peer's preferred send size, so a client sending 0 makes the server advertise it cannot receive any fragmented payload. Per [MS-SMBD] 2.2.2 the response fields describe the server's own receive capability; the test (floor on MaxFragmentedSize) is correct. Defect: ksmbd.

## Confirmed on kernel 7.0.0-38 with ksmbd debug: encrypted TREE_CONNECT over SMB Direct (issue 4)
Test `BVT_Smb2OverRdmaChannelTransform_Encryption_ReadLargeFile_AES128CCM`, per-test log `sut-linux-dmesg.log`:
1. Negotiate (3.1.1, AES-128-CCM) and session setup succeed. The encrypted TREE_CONNECT (SMB Direct payload 172 bytes = 52 transform header + 120 SMB2) is received and decrypted: `SMB2 len 120`.
2. `ksmbd: bad smb2 signature` follows. The decrypted header has SMB2_FLAGS_SIGNED set (the test client sets it on TREE_CONNECT even when only encryption is enabled, so the signature field is zero). ksmbd verifies the signature of an **encrypted** request. [MS-SMB2] 3.3.5.2.4: the server verifies a signature only when SMB2_FLAGS_SIGNED is set *and the message is not encrypted*. Windows Server 2025 accepts the same request. Defect A (ksmbd): do not check the signature when `work->encrypted`; result is STATUS_ACCESS_DENIED.
3. ksmbd then tries to send the (encrypted) response and the kernel logs `WARNING: fs/smb/server/transport_rdma.c:1637 at smb_direct_writev+0x41f/0x460 [ksmbd]` with the call trace `ksmbd_crypt_message -> ksmbd_conn_write -> smb_direct_writev`, then `ksmbd: Failed to send message: -22` (EINVAL). No SMB2 response reaches the client, which times out after ~120 s (0xC0000120). Defect B (ksmbd): sending an encrypted response over SMB Direct fails in `smb_direct_writev` (check the WARN_ON at that line in kernel 7.0.0-38; it is hit for the encrypted response's iov layout). This is why every encrypted test fails, independent of A, because even a successful TREE_CONNECT response would be encrypted.
Test-side note: setting SMB2_FLAGS_SIGNED without a signature on an encrypted request is unnecessary; the test client should only set it when signing is enabled. This does not remove defect B.
