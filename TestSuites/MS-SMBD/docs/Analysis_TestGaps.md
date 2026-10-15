# MS-SMBD Server Test Suite – Gap Analysis and Implementation

## 1. Method

1. Inventory of the existing tests (explore agent over `TestSuite\SMBD` and `TestSuite\SMB2overSMBD`).
2. Requirement extraction from [MS-SMBD] (101 requirements) and the RDMA parts of [MS-SMB2] (69 requirements) from Microsoft Learn.
3. Requirement-by-requirement comparison with the tests. Anything not clearly covered was a gap.
4. Each gap was implemented from the spec text, not from observed product behaviour.
5. Every new test was run against **Windows Server 2025** (control) and the traces/logs were checked
   (`C:\WPTS-Diagnostics\...\ptf-log.ndjson`, `rdma.pcap`). Windows is used only to prove the test is
   runnable; where it differs from the spec the test is gated and the difference is recorded below.

Because the tests assert the specification, a failure on ksmbd, Tuxera or another implementation points
at that implementation. Run them there for the interoperability result.

## 2. Tests added (51)

| File | Tests | Spec sections |
|---|---|---|
| `SMB2overSMBD\Smb2OverRdmaNegotiateContext.cs` | 6 | [MS-SMB2] 3.3.5.4, 2.2.3.1.6, 2.2.4.1.6 |
| `SMB2overSMBD\Smb2OverRdmaChannelValidation.cs` | 23 | [MS-SMB2] 3.3.5.12, 3.3.5.13, 2.2.19, 2.2.21, [MS-FSA] 2.1.5.2 |
| `SMB2overSMBD\Smb2OverRdmaTransformEdge.cs` | 6 | [MS-SMB2] 3.3.5.12, 3.3.5.13, 2.2.43, 2.2.43.1 |
| `SMBD\SmbdProtocolGaps.cs` | 9 | [MS-SMBD] 2.2.1, 2.2.3, 3.1.4.5, 3.1.4.6, 3.1.5.3, 3.1.5.4, 3.1.5.6, 3.1.5.8, 3.1.5.9 |
| `SMB2overSMBD\Smb2MultiChannelGaps.cs` | 7 | [MS-SMB2] 3.3.5.5, 3.3.5.15.11, 3.3.7.1, 3.3.1.2, [MS-SMBD] 3.1.5.1, 3.1.5.8, 3.1.5.9 |

Gap groups covered:

- **RDMA transform capabilities negotiate context** – duplicate contexts, `DataLength` too small, `TransformCount` 0,
  no common transform (response carries `SMB2_RDMA_TRANSFORM_NONE`), unknown IDs not echoed, context ignored on 3.0.2.
- **Channel / field validation** – `RDMA_TRANSFORM` on 3.0 and 3.0.2, undefined `Channel`, zero `ChannelInfoOffset`/`Length`,
  first descriptor length 0, descriptor sum below `RemainingBytes`, `RemainingBytes` over `MaxWriteSize`,
  RDMA channel over a TCP connection, READ at / past EOF and `MinimumCount`.
- **Transform edge cases** – encryption transform on an unencrypted request, unknown `TransformType`, READ without a transform,
  READ response crypto-transform field layout for AES-GMAC and AES-CMAC.
- **SMBD protocol** – Reserved/Padding ignored, second Negotiate Request terminates, Data Transfer before negotiation,
  credit cap and credit growth, server-sent fragment headers, exact `MaxReadWriteSize` transfers.
- **Multichannel** – `FSCTL_QUERY_NETWORK_INTERFACE_INFO` over RDMA, session-bind negatives, RDMA failover,
  8 concurrent connections, more requests than initial credits.

## 3. Gaps not implemented, and why

| Gap | Reason |
|---|---|
| `STATUS_BAD_DATA` on decrypted-size mismatch | Status is not defined in the SDK `NtStatus` enum and the server may legitimately return `STATUS_AUTH_TAG_MISMATCH` first. |
| Compression over RDMA READ | The adapter cannot set the compress flag on `Smb2ReadOverRdmaChannel` and negotiates no compression context. Needs an adapter change. |
| Same `IfIndex` for several IPs, failover across two distinct RDMA NICs | The configuration describes one RDMA NIC pair. |
| `MaxReadWriteSize + 1` transfers | Removed: the spec does not say a server must accept them, so the expectation would not be spec-based. |
| Scenarios already covered | Signed WRITE without `SMB2_FLAGS_SIGNED`, empty `RDMATransformIds`, boundary values for `MaxReceiveSize` / `MaxFragmentedSize` / `CreditsRequested`. |

## 4. Windows Server 2025 validation (control)

New tests, final run: **40 passed, 0 failed, 11 inconclusive** (51 tests; the `+1` tests were removed beforehand).

Inconclusive (documented, not hidden):

| Tests | Reason |
|---|---|
| 8 × `Smb2OverRdmaChannel_Write_RdmaV1_*` and `Smb2OverRdmaChannel_Write_ExactMaxReadWriteSize` | Windows Server 2025 over RoCE rejects **every** RDMA_V1 WRITE with `STATUS_INVALID_PARAMETER`, so an expected `STATUS_INVALID_PARAMETER` cannot show that the rule under test was applied. Gated by `Platform >= WindowsServer2025` only. |
| `Smb2OverRdmaTransform_Encryption_WriteUnknownTransformType_Fails`, `..._Signing_...` | Windows answers with an 8-byte ERROR body under header Status 0. [MS-SMB2] 2.2.2 requires a 9-byte ERROR body and a failure status, so the required `STATUS_INVALID_PARAMETER` cannot be observed. Recorded as a **Windows deviation from 2.2.2**; the test stays spec-based and is inconclusive on this product. |

## 5. Corrections made while validating (test/harness defects, not product defects)

| Finding | Fix | Spec |
|---|---|---|
| Two transform tests opened an unsigned, unencrypted session; the SUT dropped the connection at tree connect. | Sessions are signed. Whether signing is required is server policy and has no bearing on the rule under test. | [MS-SMB2] 3.3.5.5 |
| 8-connection test timed out on random connections. | Connection set-up is serialised (client-side NDSPI limit); the connections stay open together and do I/O in parallel. | [MS-SMBD] 3.1.5.1 |
| `MaxReadWriteSize + 1` tests asserted behaviour the spec does not define. | Tests removed. | [MS-SMBD] 3.1.4.5 |
| Undecodable replies gave an opaque "unexpected end of stream". | `Smb2Decoder` and the adapter now report the command, status and first bytes of the reply. | – |

## 6. Spec-compliance notes for implementers

- `SMB2_RDMA_TRANSFORM_CAPABILITIES` is [MS-SMB2] 2.2.3.1.6 (request) and 2.2.4.1.6 (response); the crypto transform is 2.2.43.1.
- READ has no `Channel=RDMA_TRANSFORM` on dialects below 3.1.1; it must fail `STATUS_INVALID_PARAMETER`.
- Tests that need raw malformed packets use reflection on the adapter's private client; if that field is renamed they become inconclusive, not failed.

## 7. Result on other implementations

Not yet run in this change. Run `Smb2OverRdmaNegotiateContext`, `Smb2OverRdmaChannelValidation`,
`Smb2OverRdmaTransformEdge`, `SmbdProtocolGaps` and `Smb2MultiChannelGaps` against ksmbd and Tuxera with
`Platform=NonWindows`; failures there are implementation findings unless the log shows a harness problem.
