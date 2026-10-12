# MS-SMBD full run #4 against Ubuntu ksmbd (after the Tuxera work)

- SUT: Ubuntu, kernel 7.0.0-38-generic, in-kernel ksmbd (`systemctl start ksmbd`, Tuxera stopped with `pkill -x tsmb-server`), ConnectX-4 Lx RoCE.
- Driver: Windows, `Platform=NonWindows`, `DriverPlatform=WindowsServer2025`.
- Test-suite commit: `513fdf9ff`.
- Evidence: `C:\WPTS-Diagnostics\session-20261012-*\tests\<test>\` (`rdma.pcap`, `sut-linux-dmesg.log`, `ptf-log.ndjson`).
- Result: **92 tests: 44 passed, 38 failed, 10 skipped** (1 h 32 m). Run #3 was 41 / 38 / 13.

## What changed versus run #3

Only three tests changed outcome, all from inconclusive to **pass**:

| Test | Why it was skipped before | Spec |
|---|---|---|
| `BVT_Smb2OverRdmaChannel_WriteLargeFile` | the plain RDMA WRITE helper required the optional signing transform, which ksmbd does not select | [MS-SMB2] 3.3.5.13; transform optional per 3.3.5.4 |
| `Smb2OverRdmaChannel_WriteMultipleOperation` | same | same |
| `Smb2OverRdma_Read_SMB2_CHANNEL_RDMA_V1` | its seeding WRITE required the transform | [MS-SMB2] 3.3.5.12, 3.3.5.13 |

This is a test-suite improvement, not a ksmbd improvement. The kernel and ksmbd are the same as in run #3, and **no test regressed**: the set of 38 failures is identical. It also shows that ksmbd handles plain `SMB2_CHANNEL_RDMA_V1` reads and writes of large files correctly.

The `MaxReceiveSize` change (`854ef43d3`) has no visible effect here because ksmbd's negotiate tests already fail for a different, real reason (below): `MaxFragmentedSize`, not the clamp.

## The 38 remaining failures (unchanged; all ksmbd defects)

See `Analysis_ksmbd_FullRun3.md` for the evidence. Summary:

| Group | Count | Observation (run #4 message) | Spec |
|---|---|---|---|
| Encrypted SMB2 over SMBD (`Smb2OverRdmaChannelTransform_*`) | 26 | encrypted responses are dropped: `smb_direct_writev` returns -22, `Failed to send message: -22` | [MS-SMB2] 3.3.4.1.4, [MS-SMBD] 3.1.4 |
| Negotiate minimums (`PreferredSendSizeWithZero`, `PreferredSendSizeLessThan128`) | 2 | `MaxFragmentedSize` 0 / 16192, below the 131072 minimum (the `MaxReceiveSize` 0 / 127 seen in run #3 is also below 128) | [MS-SMBD] 3.1.5.6 |
| Negotiate negative parameters (`NegativeParameter_MaxReceiveSize`, `_MaxFragmentedSize`) | 2 | server answers `STATUS_CANCELLED` instead of completing the negotiate exchange | [MS-SMBD] 3.1.5.6 |
| Connection not terminated on an invalid data-transfer message (`AgainstMaxFragmentedSize`, `RemainingDataLength_Zero`, `DataOffset_Against8ByteAligned`) | 3 | `Connection should be terminated` | [MS-SMBD] 3.1.5.8 |
| Credit management (`ConsumeAllReceiveCredits`, `NegativeParameter_CreditRequested`, `OperationWithMinimumCredits`) | 3 | last-credit message has `CreditsGranted` 0; invalid `CreditsRequested` does not terminate; timeout with minimum credits | [MS-SMBD] 3.1.5.1, 3.1.5.6, 3.1.5.8 |
| Data-transfer segments (`VariableLengthSegment`, `SmallLengthSegment`) | 2 | timeout waiting for the response | [MS-SMBD] 3.1.5.8 |

Total 26 + 2 + 2 + 3 + 3 + 2 = 38. Per-test traces and SUT logs for the non-encryption groups are in `Analysis_ksmbd_FullRun3.md` (unchanged results).
## Three-way comparison

| SUT | Passed | Failed | Skipped | Failure class |
|---|---|---|---|---|
| Windows Server 2025 | 84 | 0 | 8 | none |
| Tuxera 3026.4.1 (`rdma_max_receive_size=1364`) | 58 | 0 | 34 | none; skips are the optional RDMA transforms (`Analysis_Tuxera_FullRun.md`) |
| ksmbd (kernel 7.0.0-38) | 44 | 38 | 10 | genuine ksmbd defects against [MS-SMBD] / [MS-SMB2] |

The suite now distinguishes the cases: Tuxera passes every test it implements the feature for, Windows passes everything, and ksmbd fails only where it breaks a MUST.
