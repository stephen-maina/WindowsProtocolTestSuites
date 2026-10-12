# MS-SMBD full runs against Tuxera SMB

- SUT: Tuxera `tsmb-server` 3026.4.1 (evaluation build, user-space daemon), Ubuntu kernel 7.0.0-38-generic, ConnectX-4 Lx RoCE, 192.168.10.12 / 192.168.20.112.
- Driver: Windows, ConnectX-4 Lx, `Platform=NonWindows`, `DriverPlatform=WindowsServer2025`.
- Evidence per test: `C:\WPTS-Diagnostics\session-20261012-061056\tests\<test>\` (`rdma.pcap`, `sut-linux-dmesg.log`, `ptf-log.ndjson`). Daemon log: `/home/administrator/Tuxera/tsmb.log` (`log_level = 4 rdma:100 transport:10`).

## Results

| Run | Test-suite state | Passed | Failed | Skipped / inconclusive | Time |
|---|---|---|---|---|---|
| #1 | after the MaxReceiveSize change (`854ef43d3`) | 55 | **0** | 37 | 25 m 48 s |
| #2 | after removing the unnecessary signing-transform gates (this report) | 58 | **0** | 34 | 25 m 51 s |

Evidence that the pass is real, not hidden by skips:

- Kernel log (`sut-linux-dmesg.log`) of all 92 tests of run #2: only the `WPTS-BEGIN/END` markers, no mlx5/RDMA errors, no oops or call trace.
- All 92 `rdma.pcap` captures were produced (an old Mellanox sniffer left running on `Ethernet 3` had been blocking this and was stopped).
- Daemon log errors in run #2 are limited to the negative tests that provoke them:
  - `Received RDMA data message is invalid` / `too small` / `local length error`: the data-transfer negative-parameter tests. Tuxera terminates the connection, as [MS-SMBD] 3.1.5.x requires.
  - `SEND DONE len=8388608 status=10 (remote access error)`, 3 times: the SMB2 invalid buffer descriptor tests (offset/length/token). The server tried the RDMA WRITE into a descriptor the client made invalid, the NIC rejected it, and the READ failed as expected ([MS-SMB2] 3.3.5.12).
  - `Domain is not specified`, `Failed to bind socket`, `msgq`: daemon start/stop noise, not test related.

## Tuxera configuration needed

| Key (`[global]` of `tsmb.conf`) | Value | Why |
|---|---|---|
| `listen = ANY,0.0.0.0,RDMA_IPv4,445,SMBD` | | enable the SMB Direct listener (also needs `librdmacm1t64`) |
| `network_interface_info = [{addr=192.168.10.12,speed=100000000000,index=3,rdma,rss}]` | | mark the NIC RDMA-capable |
| `rdma_max_receive_size = 1364` | | see "MaxReceiveSize" below; default 8192 |

## Test-suite findings (test defects, fixed)

| # | Finding | Evidence | Spec | Fix |
|---|---|---|---|---|
| 1 | `SmbdNegotiate_*` tests asserted that the server clamps `MaxReceiveSize` to the client's `PreferredSendSize` | Tuxera returns its configured fixed size (8192 default). 10 negotiate tests failed. | [MS-SMBD] 3.1.5.6: only the floor (>= 128) is a MUST; the clamp is a SHOULD (Appendix A `<6>`) | `VerifyMaxReceiveSize`: floor always asserted; clamp asserted on Windows, warning elsewhere (`854ef43d3`) |
| 2 | Encrypted WRITE helper failed with `STATUS_INVALID_PARAMETER` when the server did not select the RDMA transform | Tuxera never selects any RDMA transform | [MS-SMB2] 2.2.3.1.7, 3.3.5.4: the transform is optional | `Assume` gate, same as the read helper (`2f5e4e7db`) |
| 3 | Plain RDMA channel tests were skipped when the optional **signing** transform was not selected: `BVT_Smb2OverRdmaChannel_WriteLargeFile`, `Smb2OverRdmaChannel_WriteMultipleOperation`, `Smb2OverRdma_Read_SMB2_CHANNEL_RDMA_V1` | They exercise plain `SMB2_CHANNEL_RDMA_V1`, which every server must support, and the code already had a no-transform path | [MS-SMB2] 3.3.5.13, 3.3.5.12 (RDMA_V1); 3.3.5.4 (transform selection optional) | gate removed; the transform is used only when selected, plain V1 otherwise. Windows behaviour unchanged. Now 3 more passes on Tuxera |

Windows Server 2025 behaviour is unchanged by these edits, because the signing path is taken whenever the server selects the transform. Re-verify on Server 2025 with the next regression run.

## Skips that remain in run #2 (34), all justified

| Count | Reason | Why this is not a test defect |
|---|---|---|
| 23 | Server does not select `SMB2_RDMA_TRANSFORM_ENCRYPTION` | optional per [MS-SMB2] 3.3.5.4; every scenario needs the transform |
| 5 | `Smb2OverRdmaChannelTransform_Signing_WriteLargeFile_*` (AES_CMAC, AES_GMAC, InvalidSignature, FlagsSignedNotSet, ZeroTransformCount) | optional signing transform not selected; the tests exercise the signing structure itself |
| 2 | `Smb2OverRdmaChannelTransform_Signing_ReadLargeFile_*` | same |
| 1 | `Smb2OverRdmaChannel_ReadWriteMultipleBufferDescriptorList` | built around the signing transform; a plain-V1 variant is a possible future addition |
| 2 | `*_Smb302_*_RDMA_V1_INVALIDATE` BVTs, "does not support RoCE" | remote invalidation is gated off for RoCE in this suite |
| 1 | `RemainingDataLength_AgainstFragmentReassemblyRemaining` | implementation-specific check disabled by `CheckDataLengthRemainingDataLength` |
## Implementation observations for Tuxera

These do not fail tests; they are what an implementer should know.

1. `MaxReceiveSize` is static (`rdma_max_receive_size`). Conformant, since the clamp is a SHOULD. Values below the client's message size break data transfer (tested with 128: `STATUS_DATA_ERROR`).
2. No SMB2 RDMA transform capabilities are selected (signing or encryption). This is optional, but it means 25+ spec scenarios in the suite cannot be exercised.
3. The SMBD negotiate and data-transfer negative cases are handled correctly (connection terminated).

## Compared with the other runs

| SUT | Passed | Failed | Skipped | Failure class |
|---|---|---|---|---|
| Windows Server 2025 | 84 | 0 | 8 | none |
| Tuxera (run #2) | 58 | 0 | 34 | none; skips are the optional RDMA transforms |
| ksmbd | see `Analysis_ksmbd_FullRun3.md` and the post-Tuxera ksmbd run below | | | defects in negotiate minimums, credits, encrypted responses |
