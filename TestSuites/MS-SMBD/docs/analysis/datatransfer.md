# SmbdDataTransfer audit (18 tests) — Windows driver vs Linux ksmbd over RoCE

Evidence: `C:\WPTS-Diagnostics\session-20261008-102557\tests\*DataTransfer*\ptf-log.ndjson`. Results come from the PTF log terminal kinds; `full.trx` did not exist when I finished (the run was still going), so exception text is from the PTF log only. The pcaps were not parsed, so every pcap-level statement below is unverified.
Config: Platform=NonWindows, MaxSendSize=1364, MaxReceiveSize=8192, MaxFragmentedSize=262144, SendCreditTarget=ReceiveCreditMax=255, KeepAliveInterval=120, CheckDataLengthRemainingDataLength=false.

Spec (Learn, base `https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smbd/`, reached via GUIDs from the TOC; `microsoft_docs_search` does not index this spec):
- 3.1.5.8 Receiving a Data Transfer Message `c860aa40-cf59-4020-adf3-4fd587d23c89`. The receiver MUST verify the following and MUST terminate the connection if any check fails:
  - length >= 20 bytes
  - CreditsRequested >= 1
  - DataOffset 8-byte aligned
  - DataOffset+DataLength <= message length
  - DataLength+RemainingDataLength <= Connection.MaxFragmentSize
  - RemainingDataLength=0 while FragmentReassemblyRemaining>0 → terminate
  - RESPONSE_REQUESTED → promptly send a Data Transfer message
  - new credits → promptly send a credit grant
- 2.2.3 Data Transfer Message `9e388bd3-1556-4273-b726-e8310daa1f6a`. DataOffset must be 8-byte aligned; with no payload DataOffset and DataLength MUST be 0; padding and Reserved are ignored.
- 3.1.5.1 `eaf8ad73-3c14-4777-9b64-617ac25edfb7`; 3.1.5.4 `53c6365d-905f-4361-8112-409c89f87cd7`; 3.1.5.9 `40c3ed31-8ae8-42f5-9c4b-f51fabdffacb` (credits).
- 3.1.6.2 Idle Connection Timer `78c243e7-dd37-4edd-9b45-7c16c4f04985`; 3.1.2.2 `1a5eb72a-863b-4554-ad6b-cdb9c1bbc59e`. Keepalive and termination are SHOULD, and the timer values are implementation-specific.
- Appendix B `91d0c998-25b6-4dd1-8ffb-b836c1d47bad`. Windows uses a 120 s idle timer and a 5 s keepalive response timer (<2>, <4>).
- MS-SMB2 2.1 Transport `https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/1dfacde4-b5c7-4494-8a14-a09d3ab4cc83`.

## Summary

| Test | Result | Verdict | Conf | Reason |
|---|---|---|---|---|
| BVT_SmbdDataTransfer_Basic_SendSmallBytesOfData | PASS | ACCURATE | high | 500-byte write over SMBD verified by response and file content |
| BVT_SmbdDataTransfer_Basic_SendModerateBytesData | PASS | ACCURATE | med | Multi-segment reassembly verified; the zero-length-segment quirk is minor |
| SmbdDataTransfer_VariableLengthSegment | FAIL | KSMBD_FAILURE (+TEST_INACCURATE) | low | Stalls with 0 send credits and no credit grant (2 min); the root cause is unverified |
| SmbdDataTransfer_SmallLengthSegment | FAIL | KSMBD_FAILURE (+TEST_INACCURATE) | low | Same stall at 0 send credits; 65536 one-byte messages exceed any credit window |
| SmbdDataTransfer_Redundancy | PASS | ACCURATE | med | Trailing padding is ignored per 2.2.3, but the "redundancy" claim is only loosely defined |
| SmbdDataTransfer_ReceiveMaxReceiveSize | FAIL | TEST_INACCURATE (+KSMBD) | med | The first message received is a 0-length message (credit grant or keepalive), but the test assumes it is the read data |
| SmbdDataTransfer_UncompletedMessage | PASS | ACCURATE | med | A 19-byte send leads to disconnect (3.1.5.8) |
| NegativeParameter_DataOffset_Against8ByteAligned | FAIL | KSMBD_FAILURE | high | ksmbd does not terminate on an unaligned DataOffset (offset 23, 15 s wait) |
| NegativeParameter_DataOffset_AgainstMessageLength | FAIL | ENV_CONFIG (+KSMBD) | med | Scenario 1 was terminated; scenario 2 setup got STATUS_ACCESS_DENIED |
| NegativeParameter_DataLength_AgainstMessageLength | FAIL | ENV_CONFIG (+KSMBD) | med | Scenario 1 was terminated; scenario 2 setup got STATUS_ACCESS_DENIED |
| NegativeParameter_DataLength_AgainstMaxReceiveSize | FAIL | ENV_CONFIG (+TEST_INACCURATE) | med | Part 1 was terminated; part 2 setup got STATUS_ACCESS_DENIED; part 1 is not a 3.1.5.8 check |
| NegativeParameter_AgainstMaxFragmentedSize | FAIL | KSMBD_FAILURE | high | MaxFragmentedSize+1 is accepted; the spec requires termination |
| NegativeParameter_RemainingDataLength_AgainstMaxFragmentedSize | PASS | ACCURATE | high | Both scenarios terminated; scenario titles in the code are duplicated |
| NegativeParameter_RemainingDataLength_AgainstFragmentReassemblyRemaining | PASS (vacuous) | TEST_INACCURATE | high | Skipped via the config flag, "Test case ... is off" Warning, zero assertions |
| NegativeParameter_RemainingDataLength_Zero | FAIL | KSMBD_FAILURE | high | The 2nd message with RemainingDataLength=0 did not terminate the connection |
| IdleConnection_Client | FAIL | WINDOWS_BEHAVIOUR (+KSMBD) | med | Response asserted CreditsGranted>0 and Flags NONE within 5 s; the spec does not require either |
| IdleConnection_Server | FAIL | WINDOWS_BEHAVIOUR | med | Expects a 120 s keepalive twice; the 2nd message arrived with Flags=NONE |
| IdleConnection_Server_Timeout | PASS | WINDOWS_BEHAVIOUR (passed) | med | Asserts a ~5 s timeout and a 120 s timer that are not mandated; ksmbd happened to match |

Counts: ACCURATE 5, WINDOWS_BEHAVIOUR 3, KSMBD_FAILURE 4 (incl. low-confidence 2 stall tests), TEST_INACCURATE 2, ENV_CONFIG 3, plus 1 (ReceiveMaxReceiveSize) as TEST_INACCURATE. These sum to 18 only if ReceiveMaxReceiveSize is counted in the TEST_INACCURATE group.
Tallies here are by primary verdict: ACCURATE 5, KSMBD_FAILURE 4, ENV_CONFIG 3, WINDOWS_BEHAVIOUR 3, TEST_INACCURATE 3 = 18.

## Notable cross-cutting findings
1. **STATUS_ACCESS_DENIED on the second connection within a test.** Three tests have a second scenario whose SMB2 session setup or open returns ACCESS_DENIED right after the first connection was deliberately terminated, e.g. `Status of SMB2 establish session and open file is STATUS_ACCESS_DENIED` at `Initialize_SendSmbdDataTransferTestCase`. The cause is unverified. Likely candidates: ksmbd state left over from the abruptly killed connection, an SUT-side file or user issue, or `DeleteFile.ps1` errors (`Cannot find path 'TestDrive:\<guid>.txt'`, which is a cleanup-script problem and does not flip results). Needs ksmbd logs on the SUT.
2. **ksmbd does not implement several 3.1.5.8 checks.** Observed: DataOffset alignment, DataLength+RemainingDataLength > MaxFragmentedSize, and the RemainingDataLength=0 vs FragmentReassemblyRemaining rule. It did terminate on a 19-byte message, on DataOffset past the message end and on an oversize DataLength. These are spec MUSTs, so they are genuine ksmbd non-conformance. This is from observation; I did not inspect the ksmbd source (unverified).
3. **Credit-window deadlock in the segment tests.** Both stalled for about 2 minutes (11:54:52→11:56:52 and 11:56:57→11:58:57) after "0 send credit remaining". The adapter sends raw bytes and decrements credits manually, then waits for a credit-grant message from the server that never arrives. Whether this is a ksmbd credit-grant bug or a test issue was not determined (see the per-test sections).
4. **Idle tests encode Windows timers** (120 s, 5 s). The spec says SHOULD and "implementation-specific".

## Per-test

### BVT_SmbdDataTransfer_Basic_SendSmallBytesOfData — PASS / ACCURATE (high)
- Purpose: a small payload is carried in a data transfer message.
- Spec: 2.2.3 and 3.1.5.8 (reception and delivery to the upper layer); MS-SMB2 write over RDMA.
- Test: sends an SMB2 WRITE (500 bytes) in one message, validates the write response (`DataLength==80`, `RemainingDataLength==0`) and the file content.
- Evidence: TestPassed, no CheckFailed. A DeleteFile.ps1 write error showed up in other tests' logs only.
- Verdict: ACCURATE; it checks real end-to-end behaviour.

### BVT_SmbdDataTransfer_Basic_SendModerateBytesData — PASS / ACCURATE (med)
- Purpose: several segments of one fragment are reassembled.
- Spec: 3.1.5.8 (FragmentReassemblyRemaining).
- Test: splits a 65536-byte write into messages and checks the write response and file content.
- Evidence: TestPassed. A DeleteFile.ps1 "Cannot find path" error is in the log (cleanup noise, not a failure).
- Verdict: ACCURATE. Minor quirk: `SendMultipleSegmentsWithVariableDataLength` sends a zero-length message with DataOffset 24 and RemainingDataLength set; per 2.2.3 a no-payload message must have DataOffset=0.

### SmbdDataTransfer_VariableLengthSegment — FAIL / KSMBD_FAILURE (+TEST_INACCURATE), low
- Purpose: variable-size segments, preceded by an empty message with RemainingDataLength=total.
- Spec: 3.1.5.8 (empty message with RemainingDataLength is legal), 3.1.5.9 (credits).
- Evidence: last log line `Status of send segment with length 127, 0 send credit remaining.` and then 2 min of silence, TestFailed with no CheckFailed (exception, probably the credit/receive timeout; text not available without trx).
- Analysis: the test must receive credit grants to continue. ksmbd either does not send the grant promptly (3.1.5.8 requires a prompt credit grant) or the test's credit bookkeeping is off. Unverified which; hence low confidence. The opening empty message with DataOffset=24 and DataLength=0 also deviates from 2.2.3.
- Recommended: check pcap for credit grants; send DataOffset=0 for empty messages; log the exception.

### SmbdDataTransfer_SmallLengthSegment — FAIL / KSMBD_FAILURE (+TEST_INACCURATE), low
- Purpose: 1-byte segments across a MaxFragmentSize fragment.
- Evidence: `Status of send segment with length 1, 0 send credit remaining.` then a 2-minute stall, then TestFailed.
- Analysis: it needs 262144 messages (or many tens of thousands for 65536) against a 255 credit window; it depends entirely on prompt credit replenishment. Same open questions as above.
- Recommended: same as VariableLengthSegment; cap message count.

### SmbdDataTransfer_Redundancy — PASS / ACCURATE (med)
- Purpose: trailing redundancy bytes are ignored.
- Spec: 2.2.3, padding ignored by the receiver.
- Test: pads the message to MAX_SEND_SIZE=1364 with zero bytes after DataLength and validates write response and file content.
- Evidence: TestPassed.
- Caveat: the spec defines padding between the header and the data (via DataOffset), not trailing bytes; the pass shows ksmbd ignores trailing bytes, which is reasonable but only weakly specified.

### SmbdDataTransfer_ReceiveMaxReceiveSize — FAIL / TEST_INACCURATE (+KSMBD), med
- Purpose: server sends MaxReceiveSize-size data; validate DataLength, DataOffset, RemainingDataLength.
- Evidence: `Assert.AreEqual failed. Expected: <1364>, Actual: <0>. Received SMBDirect Data Transfer Message: DataLength 0, RemainingDataLength 0` (ValidateReadResponse line 1462).
- Analysis: the first message received after the SMB2 READ was a 0-length message (credit grant or keepalive, which is legal per 3.1.5.8 "promptly send a credit grant"). The test assumes the first received message is payload. That is a test-ordering assumption valid only with Windows timing. Per spec an empty message may precede the data.
- Recommended: loop, skipping empty (DataLength==0) messages until payload arrives, then validate.

### SmbdDataTransfer_UncompletedMessage — PASS / ACCURATE (med)
- 3.1.5.8: a message shorter than 20 bytes MUST terminate the connection. A 19-byte send was followed by the connection ending. Caveat: with RDMA a send shorter than the posted receive is a valid transport event, so the termination comes from the SMBD length check; the pcap was not parsed.

### NegativeParameter_DataOffset_Against8ByteAligned — FAIL / KSMBD_FAILURE (high)
- 3.1.5.8: unaligned DataOffset MUST terminate. The test sends offset 23, waits 15 s and asserts disconnect.
- Evidence: `Assert.IsFalse failed. Connection should be terminated.` (line 447) after a 15 s wait.
- Verdict: spec-correct test; ksmbd does not check alignment.

### NegativeParameter_DataOffset_AgainstMessageLength — FAIL / ENV_CONFIG (+KSMBD), med
- Spec: DataOffset+DataLength > message length → terminate.
- Evidence: Scenario 1 (offset+8) passed its termination check; scenario 2 (uint.MaxValue) failed in setup with `STATUS_ACCESS_DENIED`. Scenario 2's actual check never ran, so ksmbd's behaviour there is unverified.
- Recommended: investigate the ACCESS_DENIED on the second session after a killed connection (ksmbd log).

### NegativeParameter_DataLength_AgainstMessageLength — FAIL / ENV_CONFIG (+KSMBD), med
- Same pattern. Scenario 1 (DataLength+1) was terminated; scenario 2 ("MaxSendSize") setup failed with STATUS_ACCESS_DENIED. Scenario 3 (uint.MaxValue) not reached.
- The test's stated purpose is the (DataOffset+DataLength) check, valid per 3.1.5.8.

### NegativeParameter_DataLength_AgainstMaxReceiveSize — FAIL / ENV_CONFIG (+TEST_INACCURATE), med
- Part 1 sends a message of ServerMaxReceive+1 bytes and observed termination. That is an oversized RDMA SEND (an RDMA-layer length error), not a 3.1.5.8 check, since 3.1.5.8 compares DataLength+RemainingDataLength with MaxFragmentSize. The stated test purpose (DataOffset+DataLength > message length) is copied from another test (misleading description).
- Part 2 setup failed with STATUS_ACCESS_DENIED, so the "exactly MaxReceive succeeds" check did not run.
- Recommended: correct the purpose text; do not attribute termination to the SMBD receiver check.

### NegativeParameter_AgainstMaxFragmentedSize — FAIL / KSMBD_FAILURE (high)
- 3.1.5.8: DataLength+RemainingDataLength > MaxFragmentSize → terminate.
- Evidence: `Send Data Transfer message with Server's MaxFragmentedSize + 1.` then `Assert.IsFalse failed. Connection should be terminated.` (line 786).
- Verdict: spec-correct, ksmbd does not enforce. The test's purpose text (copy-paste of "DataOffset + DataLength greater than message length") is misleading but the assertion is right.

### NegativeParameter_RemainingDataLength_AgainstMaxFragmentedSize — PASS / ACCURATE (high)
- Sends an empty message with RemainingDataLength=MaxFragmentedSize+1 and then uint.MaxValue; both terminated (`Connection should be terminated.` succeeded).
- Interesting: ksmbd terminates here but not for the DataLength variant above. Both scenarios are labelled "Scenario 1" (log typo). Termination appeared immediate (same second); the possibility that the connection was torn down by something else is unverified.

### NegativeParameter_RemainingDataLength_AgainstFragmentReassemblyRemaining — PASS (vacuous) / TEST_INACCURATE (high)
- Evidence: `Warning: Test case ... is off.` then TestPassed. Because `CheckDataLengthRemainingDataLength=false`, the body returns before any assertion, so PASS carries no information.
- Recommended: report Inconclusive/skip, not Pass; keep the flag as a capability gate but mark the result accordingly. For ksmbd, enable and expect a KSMBD failure per 3.1.5.8.

### NegativeParameter_RemainingDataLength_Zero — FAIL / KSMBD_FAILURE (high)
- 3.1.5.8: RemainingDataLength=0 while FragmentReassemblyRemaining>0 → terminate.
- Evidence: two messages sent OK, then 15 s later `Assert.IsFalse failed. Connection should be terminated.` (SendWithInvalidRemainingDataLength line 1747).
- Verdict: spec-correct; ksmbd does not enforce.

### IdleConnection_Client — FAIL / WINDOWS_BEHAVIOUR (+KSMBD), med
- Spec: 3.1.5.8, a RESPONSE_REQUESTED message MUST be answered promptly with a data transfer message.
- Test: sleeps 119 s, sends an empty message with RESPONSE_REQUESTED and CreditsGranted=0, expects within 5 s a reply with CreditsGranted>0, Flags==NONE, Reserved==0.
- Evidence: `Assert.IsTrue failed. CreditGranted is greater than 0` (line 1035), at the same second the request was sent, so a message did arrive (details unverified).
- Analysis: the spec requires a response but not CreditsGranted>0 (credits may be unchanged) nor Flags==NONE; the 119 s sleep races the server's own 120 s keepalive and the 5 s window is the Windows value (App. B <4>). The received message is probably a credit/keepalive message rather than the reply; the response did exist.
- Recommended: accept any data transfer response; drop the CreditsGranted>0 assertion; do not tie timing to 120 s.

### IdleConnection_Server — FAIL / WINDOWS_BEHAVIOUR (med)
- Spec: 3.1.6.2 SHOULD send RESPONSE_REQUESTED when the idle timer expires; the interval is implementation-specific (Windows 120 s, App. B <2>).
- Evidence: the first keepalive (flag set) and the reply passed; then on the second wait: `Flags is NONE` (expected RESPONSE_REQUESTED), line 1186.
- Analysis: after the first exchange ksmbd sent a non-keepalive message (e.g. credit update) rather than a second keepalive in the window, or its idle timer differs. Timing assumptions (125 s windows) are Windows-specific.
- Recommended: treat as optional behaviour (SHOULD); loop over messages until RESPONSE_REQUESTED or timeout, and take the interval from the SUT.

### IdleConnection_Server_Timeout — PASS / WINDOWS_BEHAVIOUR (med)
- Spec: 3.1.6.2 the peer SHOULD terminate if no response; 3.1.2.2 "can" disconnect, no timeout mandated.
- Test: waits 125 s for the keepalive, ignores it, sleeps 5 s, then waits up to 15 s for disconnect.
- Evidence: TestPassed. The passing result reflects ksmbd's timings (it terminated within about 20 s) rather than a spec number. The Platform>=WindowsServer2025 Inconclusive guard is not triggered for NonWindows.
- Verdict: the assertion is stricter than the spec but passed.

## Caveats
- `full.trx` was absent; exception texts for the two stalled segment tests were not retrieved.
- No pcap parsing was done; conclusions about ksmbd internals are unverified inference.
- Run timestamps in the logs are shown in mixed time zones.
