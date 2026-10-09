# MS-SMBD defect root-cause report (full2.trx, read-only investigation)

Evidence: `full2.trx` (parsed into `files\full2-results.json`), the per-test `rdma.pcap` files (decoded with `files\pcapdec.ps1`), the test/SDK source, the upstream ksmbd source in `files\ksmbd\` and `files\spec\smbd.txt`.

**Caveats**
- **Source drift.** The trx was produced at 05:45 from commit 10927210 plus working-tree state. `SmbdNegotiate.cs` was edited at 06:06 and committed at 06:10 (8259ccad). Stack line numbers in the trx therefore differ from the current files. Use `git show 10927210:TestSuites/MS-SMBD/src/TestSuite/SMBD/<file>` for exact run-time lines. Current line numbers are quoted below as "now".
- **No SUT access.** The ksmbd kernel version is unknown and there is no server-side log. Server-internal explanations are hypotheses from upstream source. Wire facts are certain.
- **Decoder note.** The first 20-byte SEND on each new connection is a Negotiate Request. Its field mapping is: credReq=min/max version, rsv=CreditsRequested, rem=PreferredSendSize, doff=MaxReceiveSize, dlen=MaxFragmentedSize.

## Summary

| Test | Classification | Confidence |
|---|---|---|
| ConsumeAllReceiveCredits | Test bug: `ValidateReadResponse` treats ksmbd's empty credit-grant message as READ data | High |
| BVT_OperationWithMinimumCredits | Client accounting is correct, so this is a ksmbd credit stall (spec 3.1.5.9). The test has no stall tolerance. | High (wire), medium (server cause) |
| NegativeParameter_CreditRequested | ksmbd violation (no terminate on CreditsRequested==0); description is also wrong (test-side doc defect) | Medium-high |
| IdleConnection_Client | Test bug: over-strict asserts (CreditsGranted>0, Flags==NONE) | High |
| IdleConnection_Server | Test bug: ksmbd sends two empty replies, the second is mistaken for the next keepalive | High |
| ReceiveMaxReceiveSize | Test bug (same as ConsumeAll) | High |
| SmallLengthSegment / VariableLengthSegment | Client bookkeeping is correct. ksmbd stops granting after its 255-buffer window is held in reassembly. Likely a ksmbd limit. Test design is also fragile. | Medium |
| NegativeParameter_DataLength_AgainstMaxReceiveSize, DataOffset_AgainstMessageLength, DataLength_AgainstMessageLength (ACCESS_DENIED) | Env/ksmbd teardown race plus a test that reconnects with no settle/retry. Credentials and session setup are ruled out. | High that it is not credentials, medium-low on the mechanism |
| SmbdNegotiate PreferredSendSizeWithZero / LessThan128 | Genuine ksmbd spec violation | High |
| SmbdNegotiate NegativeParameter_MaxReceiveSize / MaxFragmentedSize | Genuine ksmbd violation (rejects the boundary values 128 and 131072) | High |

---

## 1. SmbdCreditMgmt_ConsumeAllReceiveCredits

1. **Exception.** `Assert.AreEqual Expected 65536 Actual 0 ... DataLength 0`. Run-time line: `ValidateReadResponse` SmbdCreditManagement.cs:393, called from :103.
2. **Failing step.** `ValidateReadResponse` (now ~:405 onwards) receives the first message and expects it to be READ data. The first message is empty.
3. **Classification: test bug, high.**
   - ksmbd answers every client message with a separate empty credit-grant SEND (req=255, gr=1, dlen=0) before the real response. 3.1.5.8 explicitly allows this.
   - The client granted 10+2+2+2+2=18 credits in total. ksmbd sent 18 messages (11 pre-READ, 1 empty, 7 data) and stopped with rem=57340 left, because it ran out of send credits. The READ response is a valid STATUS_SUCCESS 65536-byte read.
   - The prior report's "73-byte SMB2 error" was a parsing mistake.
   - Secondary test issue: the READ is sent with CreditsGranted=0, and the test then expects the last message to carry gr>0. ksmbd's data messages carry gr=0 (legal).
4. **Spec 3.1.5.8:** "If Connection.SendQueue is empty, the credit processing specified in section 3.1.5.9 MUST be performed. If the number of new credits returned is greater than zero, the receiver MUST promptly send a newly constructed Data Transfer message with its CreditsGranted field set to the number of new credits on the Connection".
5. **Fix** in `ValidateReadResponse` (SmbdCreditManagement.cs): after each `SmbdReceivDataTransferMessage`, skip messages with `DataLength == 0` (account for their CreditsGranted) and receive again.

Before:
```csharp
status = (NtStatus)smbdAdapter.SmbdReceivDataTransferMessage(timeout, out transferPackage);
// ...asserts on transferPackage.DataLength + RemainingDataLength == readResponseSize - offset
```
After:
```csharp
do {
    status = (NtStatus)smbdAdapter.SmbdReceivDataTransferMessage(timeout, out transferPackage);
} while (transferPackage.DataLength == 0 && transferPackage.RemainingDataLength == 0
         && (transferPackage.Flags & SmbdDataTransfer_Flags.SMB_DIRECT_RESPONSE_REQUESTED) == 0);
// then assert as before
```
Also drop or relax the "last message must carry CreditsGranted>0" assert.

## 2. BVT_SmbdCreditMgmt_OperationWithMinimumCredits

1. **Exception.** `TimeoutException` after 126 s. Stack: `SmbdClient.SendMessage` :460 → `ReceiveDataTransferMessage` :317 → `SmbdConnectionEndpoint.ReceiveData` :675 → `Smb2Write` → `OperationWithSpecifiedCredits` SmbdCreditManagement.cs:253, called from :40.
2. **Failing step.** The Smb2 WRITE request, fragmented over several Data Transfer messages, blocks inside `SendMessage` waiting for a credit grant. `SendMessage` waits `KEEP_ALIVE_INTERVAL` (120 s) and then throws.
3. **Classification: ksmbd credit stall (spec 3.1.5.9), high on the wire evidence, medium on the server internals.** This is not a client accounting bug.
   - The client requested 1 credit and ksmbd granted 1. Every client send carries req=1 gr=1. The server had exactly one send credit left (the client granted 17, the server consumed 16).
   - Fragment 1 (rem=64308) received an empty gr=1 reply. Fragment 2 (rem=62968) received nothing for 120 s.
   - SDK check: `SendCredits` is decremented once per sent message in `SmbdClient.cs:453/533`. The adapter's `SendDataOverRdma` does not decrement. The client count is consistent with the wire.
   - Probable ksmbd mechanism: with recv_credit_target=1 and the credit already at target, it posts no new buffer and so grants nothing. v6.17 `is_receive_credit_post_required` and v6.18 `manage_credits_prior_sending` (returns 0 if count >= target) behave this way. In the newer `smbdirect_connection_recv_io_refill` there is a "target is only 1 → grant anyway" special case, but only when a buffer was posted.
4. **Spec 3.1.5.9:** "If Connection.ReceiveCredits is zero, or if Connection.SendCredits is one and the Connection.SendQueue is not empty, the sender MUST allocate and post at least one receive of size Connection.MaxReceiveSize and MUST increment Connection.ReceiveCredits by the number allocated and posted."
5. **Test-side hardening (optional).** `SendMessage` has no way to report "peer granted nothing". Catch the timeout and assert with a message that names the stall. No fix will make this test pass against this ksmbd.

## 3. SmbdCreditMgmt_NegativeParameter_CreditRequested

1. **Exception.** `Assert.IsFalse failed. Connection should be terminated`, SmbdCreditManagement.cs:219 (17.5 s).
2. **Failing step.** After negotiate, the test sends an empty Data Transfer (req=0, gr=0) and waits for the disconnect.
3. **Classification.**
   - **Description is a test-side defect.** The `[Description]` says "in SMBD Negotiate Request" but the code sends a Data Transfer message. The code matches 3.1.5.8. Change the description to "...CreditsRequested is 0 in an SMBD Data Transfer message".
   - **ksmbd did not terminate.** This is a genuine violation, medium-high confidence.
   - The server DREQ at 0.248 s belongs to a previous connection (client comm ID ...98, server ...D98B8548 for this test). The client sent its own DREQ at 15.05 s.
   - ksmbd v6.17 `recv_done` has no `credits_requested==0` check and stores target=0. The newer smbdirect code does reject it (`invalid: credits_requested == 0`).
4. **Spec 3.1.5.8:** "The receiver of the message MUST verify: ... The received CreditsRequested field is at least 1. ... If any of the preceding conditions are not satisfied, the receiver MUST terminate the connection and cease further processing."
5. **Fix** (test-side, documentation only): `[Description("Verify the connection will be terminated if CreditsRequested is 0 in an SMBD Data Transfer message.")]`.

## 4. SmbdDataTransfer_IdleConnection_Client

1. **Exception.** `Assert.IsTrue failed. CreditGranted is greater than 0`, SmbdDataTransfer.cs:1035 (now ~:1080-1140).
2. **Failing step.** After the idle wait the client sends an empty DT with RESPONSE_REQUESTED, req=255, gr=0. The test asserts CreditsGranted>0 on the first reply.
3. **Classification: test bug, high.**
   - ksmbd's first reply is an empty DT with gr=0 and flags=0. The second is an empty DT with gr=1.
   - gr=0 is legal. The Flags==NONE assert is also dubious, because a reply can carry flags depending on KeepaliveRequested.
4. **Spec 3.1.5.1:** "If CreditsGranted field of the first message in Connection.SendQueue is zero, the credit processing ... MUST be performed, and the CreditsGranted field of the message MUST be set to the number of new credits returned." Zero is possible if no new credits were returned.
   **Spec 3.1.5.8:** "If the SMB_DIRECT_RESPONSE_REQUESTED flag is set in the received Flags field, then Connection.KeepaliveRequested MUST be set to "PENDING". The receiver MUST set Connection.SendImmediate to TRUE and promptly send a Data Transfer message".
5. **Fix:** remove the `CreditsGranted > 0` assert (and the Flags==NONE assert), or accept either value. Assert only that a reply arrives (DataLength==0).

## 5. SmbdDataTransfer_IdleConnection_Server

1. **Exception.** Expected Flags SMB_DIRECT_RESPONSE_REQUESTED, actual NONE, SmbdDataTransfer.cs:1186 (now ~:1160-1280).
2. **Failing step.** After the client answers the server keepalive with RESPONSE_REQUESTED, the test reads the first reply. The next receive ("let idle timer expire again") then immediately returns a leftover empty message, not a second keepalive.
3. **Classification: test bug, high.**
   - Server keepalive (fl=0x1, gr=0) at 126.265 s. Client reply with RESPONSE_REQUESTED at 130.271 s. Server answers with TWO empty messages: gr=0 fl=0, then gr=1 fl=0.
   - The test consumes only one of them. The second is read as if it were the next keepalive, so the flag assert fails.
   - The idle timer values are implementation-specific.
4. **Spec 3.1.6.2 (Idle Connection Timer):** "the local peer SHOULD check whether Connection.KeepaliveRequested is set to "NONE", and if not, the local peer SHOULD terminate the connection. Otherwise, Connection.KeepaliveRequested SHOULD be set to "PENDING", and a Send of a Data Transfer message with the SMB_DIRECT_RESPONSE_REQUESTED flag set SHOULD be initiated."
5. **Fix:** before waiting for the next keepalive, drain empty messages without RESPONSE_REQUESTED:
```csharp
do { smbdAdapter.SmbdReceivDataTransferMessage(timeout, out msg); }
while ((msg.Flags & SmbdDataTransfer_Flags.SMB_DIRECT_RESPONSE_REQUESTED) == 0);
```

## 6. SmbdDataTransfer_ReceiveMaxReceiveSize

1. **Exception.** Expected DataLength 1364, actual 0. `ValidateReadResponse` SmbdDataTransfer.cs:1462 (now :1551), called from :355 (now :384).
2. **Failing step.** Same defect as test 1: the first message is ksmbd's empty credit grant.
3. **Classification: test bug, high.** The READ data that follows is valid: the first message has dlen=1340 rem=24 (total message 1364), then dlen=24.
4. **Spec:** same as test 1, 3.1.5.8.
5. **Fix:** skip leading empty (DataLength==0) messages in `ValidateReadResponse` (SmbdDataTransfer.cs:1551) as in test 1. The expected "DataLength == MaxReceiveSize" assert is also too strict, because the READ response header (SMB2 header plus Read response) is 64+16 bytes. Compare DataLength+RemainingDataLength to the total instead.

## 7. SmbdDataTransfer_SmallLengthSegment and _VariableLengthSegment

1. **Exception.** `TimeoutException` after ~125 s in `SendMultipleSegmentsWithVariableDataLength` (run-time :1670, now :1689) → `SmbdAdapter.SmbdReceivDataTransferMessage`. Called from :232 (Variable) and :268 (Small).
2. **Failing step.** The "receive credit grant" step (now ~:1770) waits for an empty grant message. None arrives for 120 s.
3. **Classification: ksmbd stall / limit, medium. Client bookkeeping is correct.**
   - VariableLengthSegment pcap: the client sent 263 DT messages. The server granted 255 (negotiate) + 8 grants = 263, so the client used exactly every credit granted. The test does `SendCredits--` once per message, and `SendDataOverRdma` does not decrement, so there is no double-count. The "0 send credit remaining" message is accurate.
   - ksmbd does not grant more. Every data segment sits in ksmbd's reassembly queue, because the upper layer cannot consume until the fragmented SMB2 message is complete. The recv buffers are not freed, so the server cannot post new ones to grant credits. The newer ksmbd refill code has an explicit "still in reassembly.list" comment confirming this.
   - SmallLengthSegment sends 1 byte per message (65536 messages needed vs 255 buffers). The pcap (438 KB) shows the same pattern.
   - Test design weakness: with a fragmented message that needs more messages than the peer has buffers, a deadlock is inevitable for a receiver that holds all fragments. The spec expects the receiver to cope ("several pauses can occur while waiting for credit replenishment" in Appendix B), but a real server may impose a limit.
4. **Spec 3.1.5.9:** "If Connection.ReceiveCredits is zero ... the sender MUST allocate and post at least one receive of size Connection.MaxReceiveSize". 3.1.5.8 says fragment contents MUST be appended to Connection.FragmentReassemblyBuffer. ksmbd's buffer-pool design is the cause.
5. **Fix (test-side options):** limit the data size so the number of segments stays below the server's credit window (e.g. segments <= 100), or treat a timeout in this step as Inconclusive, with a clear message.

## 8. NegativeParameter_* STATUS_ACCESS_DENIED (3 tests)

Tests: DataLength_AgainstMaxReceiveSize (called from :623), DataOffset_AgainstMessageLength (:506), DataLength_AgainstMessageLength (:541).

1. **Exception.** `Status of SMB2 establish session and open file is STATUS_ACCESS_DENIED`, `Initialize_SendSmbdDataTransferTestCase` :1300 (now :1384).
2. **Failing step.** The second scenario in the same test method. A new RDMA connection is made right after the first scenario's connection was aborted by the server.
3. **Classification: environment / ksmbd teardown race plus a test with no settle/retry. High that credentials and session setup are not the cause; medium-low on the exact mechanism.**
   - Scenario 1 (WRITE with msglen 1365 > ksmbd MaxReceiveSize 1364): no reply, and ksmbd sends DREQ at ~2.29 s (correct termination).
   - The client opens connection 2 about 50 ms later without answering the DREQ (no DREP). The server's DREQ retransmits for connection 1 continue to the end of the capture.
   - Connection 2: negotiate OK, SESSION_SETUP (MORE_PROCESSING then SUCCESS), then TREE_CONNECT to `\\192.168.10.12\SMBDTest` returns STATUS_ACCESS_DENIED (0xC0000022). The same user and share worked on connection 1, so credentials and the share path are not the problem.
   - Passing tests use one connection. These tests are the only ones that reconnect within ~50 ms of a server abort.
   - Hypothesis (unconfirmed): ksmbd rejects the tree connect while the old connection's session/tree state is still alive. Not verifiable without server access.
4. **Spec:** no spec claim is made.
5. **Fix:** in the second-scenario setup, wait for the old connection to be torn down (disconnect the old endpoint and `Thread.Sleep` ~6-10 s) and retry the SMB2 session/tree connect (e.g. 3 attempts) before asserting.

## 9. SmbdNegotiate (4 failures): genuine ksmbd violations

Values the tests send (decoded from the pcaps) match the spec boundaries. There is no unit or config defect.

| Test | Client sent | ksmbd returned | Spec |
|---|---|---|---|
| PreferredSendSizeWithZero | prefSend=0 | MaxReceiveSize=0, MaxFragmentedSize=**0** | 3.1.5.6/3.1.5.7 |
| PreferredSendSizeLessThan128 | prefSend=127 | MaxReceiveSize=127, MaxFragmentedSize=**16192** | 3.1.5.6/3.1.5.7 |
| NegativeParameter_MaxReceiveSize | maxRecv=127 → DREQ (correct); maxRecv=128 → DREQ (wrong) | STATUS_CANCELLED | 3.1.5.6 |
| NegativeParameter_MaxFragmentedSize | maxFrag=131071 → DREQ (correct); maxFrag=131072 → no negotiate response, server DREQ | STATUS_CANCELLED | 3.1.5.6 |

For comparison, the normal case: client prefSend=1364, maxRecv=8192, maxFrag=262144; ksmbd NEG_RSP prefSend=1364, maxRecv=1364, maxFrag=173910, gr=255, maxRW=8388608.

**Failing lines.** Run-time `NegotiateBasicChecker` :771 via `BasicNegotiate` :553 (now ~:888 and :631). The two NegativeParameter tests assert STATUS_SUCCESS at `BasicNegotiate` :550.

**ksmbd cause** (`transport_rdma_v6.17.c` ~2024-2030, same in 6.16/6.18):
- `max_recv_size = min(max_recv_size, req->preferred_send_size)` has no floor of 128.
- `max_fragmented_recv_size = (recv_credit_max*max_recv_size)/2`. For 255×127/2 this gives 16192; for 255×1364/2 it gives 173910.
- The negotiate-request check uses `max_receive_size <= 128` and `max_fragmented_size <= 128*1024`. This is an off-by-one: it rejects the exact minimums that the spec allows (v6.16 ~529-531, v6.17 ~502-504).

**Spec.**
- 3.1.5.6: "The MaxReceiveSize field is at least 128 bytes. The MaxFragmentedSize field is at least 131,072 bytes. If any of the preceding conditions are not satisfied, the receiver MUST terminate the connection". It also says to set Connection.MaxReceiveSize to the smaller of the sizes, and: "If the result is less than 128, then Connection.MaxReceiveSize MUST be set to 128."
- 3.1.5.7 (initiator verifying the response): "The MaxReceiveSize field is at least 128 bytes. The MaxFragmentedSize field is at least 131,072 bytes."

**Fix:** none for the test. Do not change these checks.

---

## Corrections to prior reports
- "73-byte SMB2 error" in ConsumeAll was a mis-parse. The READ response is a valid 65536-byte read.
- "ksmbd only grants 1 credit": wrong. ksmbd grants what the client requests (credit 1 only in the minimum-credits test).
- The server DREQ seen in CreditRequested at 0.248 s belongs to a different (earlier) connection. ksmbd did not terminate this one.
- The earlier pcap parser output contained TCP garbage; use `pcapdec.ps1`.
