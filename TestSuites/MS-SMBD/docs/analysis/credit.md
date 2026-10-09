# SmbdCreditManagement audit (6 tests)

Setup: Windows client 192.168.10.11 vs Linux ksmbd SUT 192.168.10.12 (RoCEv2).
Evidence: `C:\WPTS-Diagnostics\session-20261008-102557\tests\SmbdCreditManagement.*` (ptf-log.ndjson, rdma.pcap) and `fullrun-console.txt`.
Note: `full.trx` did not exist when this report was written (the run was still in progress). Outcomes below come from the ptf-log and the console. They are not yet confirmed against the trx.

Learn base: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smbd/<id>
- 3.1.5.8 Receiving a Data Transfer Message: `c860aa40-cf59-4020-adf3-4fd587d23c89`
- 3.1.5.9 Managing Credits Prior to Sending: `40c3ed31-8ae8-42f5-9c4b-f51fabdffacb`
- 3.1.5.1 Sending Upper Layer Messages: `eaf8ad73-3c14-4777-9b64-617ac25edfb7`
- 3.1.5.6 Receiving a Negotiate Request: `827afab8-ae7e-4697-ad96-16b7f3f60f65`
- 3.1.2.2 Idle Connection Timer: `1a5eb72a-863b-4554-ad6b-cdb9c1bbc59e`
- Appendix B (Windows behaviour): `91d0c998-25b6-4dd1-8ffb-b836c1d47bad`

## Summary

| Test | Result | Verdict | Conf. | Reason |
|---|---|---|---|---|
| BVT_SmbdCreditMgmt_OperationWithMinimumCredits | FAIL (TimeoutException after 120 s) | KSMBD_FAILURE (hypothesis for the internal cause) | med-high | With the client at 1 credit, ksmbd stops granting credits after the 2nd fragment, so the client stalls. |
| SmbdCreditMgmt_OperationWithLimitedCredits | PASS (but the write took ~10 min) | TEST_INACCURATE (weak assertions); secondary KSMBD_FAILURE | med | Only asserts that the write succeeds. It never checks credit limits, and the 10-minute duration is anomalous. |
| SmbdCreditMgmt_ConsumeAllSendCredits | PASS | TEST_INACCURATE (weak) | med | Spec-correct idea, but asserts only CreditsGranted>0. The design spec says it must be 10. |
| SmbdCreditMgmt_ConsumeAllReceiveCredits | FAIL (Expected 65536, Actual 0) | TEST_INACCURATE; secondary ENV_CONFIG | med-high | The test treats the server's empty credit-grant message as the READ data. It also never gets a valid READ response (see below). |
| SmbdCreditMgmt_ConsumeAllCreditServer_Timeout | FAIL (Expected 65536, Actual 73) | ENV_CONFIG / TEST_INACCURATE; secondary WINDOWS_BEHAVIOUR | med | The SMB2 READ returned a 73-byte SMB2 error (a 64-byte header plus 9 bytes). The "Send Credit Grant Timer" does not exist in MS-SMBD. |
| SmbdCreditMgmt_NegativeParameter_CreditRequested | FAIL (connection not terminated within 15 s) | KSMBD_FAILURE; secondary TEST_INACCURATE (title/description) | high | A spec-mandated termination (3.1.5.8) was not performed by ksmbd. |

Counts: KSMBD_FAILURE 2, TEST_INACCURATE 2, ENV_CONFIG 1, ACCURATE 0, WINDOWS_BEHAVIOUR 0 as primary verdicts (1 test has ENV_CONFIG/TEST_INACCURATE listed as a joint primary; counted under ENV_CONFIG).

## Config and shared facts
- ReceiveCreditMax and SendCreditTarget are 255 in the ptfconfig, but each test overrides them with its own credit value (1 or 10).
- MaxFragmentedSize is 262144 in the request.
- In the pcap, the negotiate request carries CreditsRequested=1 (the test value 1 or 10 in the other tests). The ksmbd response has req=255, gr=1, MaxFrag=173910, MaxRecv=1364.
- ksmbd only ever grants 1 credit in the negotiate response. Every ksmbd empty message carries gr=1.
- `SmbdTestBase.TestCleanup` swallows exceptions from DeleteFile and DisconnectRdma. This is a silent-failure risk for all tests (TEST_INACCURATE, minor).

## 1. BVT_SmbdCreditMgmt_OperationWithMinimumCredits
- **Purpose:** "SMBD operation works fine with minimum credits (only 1 credit)".
- **Spec:** 3.1.5.8 says the receiver MUST decrement ReceiveCredits. If the send queue is empty, run 3.1.5.9. If the new credits > 0, it MUST promptly send a Data Transfer message with CreditsGranted. 3.1.5.1 says the sender stops if SendCredits==0, or if SendCredits==1 and CreditsGranted==0.
- **Test:** Negotiate with credits=1. SMB2 session setup and open. SMB2 WRITE of 65536 bytes. Asserts negotiate success, MaxFragmentedSize>=131072, write STATUS_SUCCESS and Count==65536.
- **Observed:** The log shows "Write a moderate size of data" at 11:41:52.788, then nothing until 11:43:52.890. That is exactly the 120 s credit wait in `SmbdClient.SendMessage`. The exception is `System.TimeoutException: Timeout for waiting an object`.
- **pcap:** The client sends fragment 1 (rem=64308) and the server answers with an empty gr=1 message. The client sends fragment 2 (rem=62968) and the server never grants again. The client sits at 0 send credits and nothing further is sent until the disconnect at ~122 s.
- **Verdict:** KSMBD_FAILURE (med-high). The test is spec-correct. A server with ReceiveCredits back at 0 MUST promptly grant credits.
  - Cause hypothesis, unverified: ksmbd's recv_done/post_recv_credits logic gates credit posting on its reassembly state.
  - Test weakness: it never asserts the credit semantics, so the BVT label overstates what it checks. The design spec mentions "only grants 5 credits", which has no counterpart in the code.

## 2. SmbdCreditMgmt_OperationWithLimitedCredits
- **Purpose:** The same flow with credits=10.
- **Observed:** TestPassed. The write started at 11:43:57.356 and completed at 11:54:10.958, a duration of about 10 minutes. Asserts passed: STATUS_SUCCESS and Count==65536.
- **Anomaly:** 10 minutes strongly suggests repeated 120 s-class credit stalls that eventually recovered (about 5 stalls). Not verified from the pcap.
- **Verdict:** TEST_INACCURATE (med), secondary KSMBD_FAILURE. Passing says nothing about conformance to credit rules. There is no timing or credit assertion. The ksmbd stall pattern is the same as in test 1.
- **Fix:** Assert the credit counters (SendCredits/ReceiveCredits bounds after the exchange) and put a time bound on the operation.

## 3. SmbdCreditMgmt_ConsumeAllSendCredits
- **Purpose:** Consume all client send credits; the server must send an empty data transfer message to grant credits.
- **Spec:** 3.1.5.8, grant when new credits > 0.
- **Test:** Sends empty messages (CreditsRequested=10, CreditsGranted=1) while ClientConnection.SendCredits>0, ignoring send statuses. Then it receives a message and asserts CreditsGranted>0, CreditsRequested>0, DataLength==0, DataOffset==0 and RemainingDataLength==0.
- **Observed:** TestPassed (log: "CreditsRequested is 255", DataLength/DataOffset/RemainingDataLength all 0).
- **Verdict:** TEST_INACCURATE (med): the pass is genuine for the grant, but weak. The design spec says CreditsGranted MUST be 10, and the code only checks >0. Send statuses are ignored. The loop count depends on the negotiate grant of 1, so the "consume all" loop sends only one message. ksmbd behaviour on this path is acceptable.
- **Fix:** Assert the exact number of messages sent and check the send statuses.

## 4. SmbdCreditMgmt_ConsumeAllReceiveCredits
- **Purpose:** The server sends a multi-fragment response and exhausts its credits; it must wait for new grants.
- **Observed:** FAIL at `ValidateReadResponse` (SmbdCreditManagement.cs:393): "Expected 65536, Actual 0. Received SMBDirect Data Transfer Message: DataLength 0, RemainingDataLength 0".
- **pcap:** For the READ request (client req=10 gr=0, dlen=113) ksmbd replies first with an empty gr=1 message (dlen=0), then a 73-byte message (dlen=73, gr=0). 73 bytes is a 64-byte SMB2 header plus a 9-byte error response, so the READ failed on the server side. The status code is unverified; the cause is possibly the file `testFile_ReadLargeFile.txt` missing or smaller than the requested read length.
- **Verdict:** TEST_INACCURATE (med-high), secondary ENV_CONFIG. The test assumes the first received message is the data message. Per 3.1.5.8 an empty credit-grant message is a legitimate message the server may interleave, and the test does not skip it. Separately the data file on the SUT may be absent or too small, which would need a config check.
- **Also:** The `CreditsGranted>0` assert on the final message is not required by 3.1.5.1. The design spec's "wait 4 s" check is not implemented.
- **Fix:** Skip zero-length messages and check the SMB2 READ status before validating sizes. Verify the test file exists on the SUT with at least 65536 bytes.

## 5. SmbdCreditMgmt_ConsumeAllCreditServer_Timeout
- **Purpose (log):** "connection terminated because of Send Credit Grant Timer expiration if server with no send credits".
- **Spec:** MS-SMBD defines no "Send Credit Grant Timer". The closest is the Idle Connection Timer (3.1.2.2), after which the peer CAN disconnect (optional). Windows uses 120 s (Appendix B), and 5 s after a keepalive request. The design spec says 5 s and the code waits 120 s. This claim is unverified against the full PDF; only the Learn pages were checked.
- **Observed:** FAIL after 4 s: "Expected 65536, Actual 73. DataLength 73, RemainingDataLength 0" (line 152). Same pcap pattern as test 4: a 73-byte SMB2 error response. The test never reached the 120 s wait and the disconnect check.
- **Verdict:** ENV_CONFIG (med) for the actual failure (invalid READ response, same cause as test 4), with TEST_INACCURATE/WINDOWS_BEHAVIOUR as secondary: the timer named in the description does not exist, and the expectation that the server disconnects is Windows behaviour.
- **Fix:** Rename the test and description to Idle Connection Timer / keepalive. Assert the keepalive request instead of a mandatory disconnect. Fix the data file as in test 4.

## 6. SmbdCreditMgmt_NegativeParameter_CreditRequested
- **Purpose (log):** "connection terminated if CreditsRequested is 0 in SMBD Negotiate Request".
- **Spec:** 3.1.5.8: the receiver MUST verify CreditsRequested >= 1 and MUST terminate the connection otherwise. 3.1.5.6 has the same rule for a negotiate request.
- **Test:** Normal negotiate, then it sends a Data Transfer message with CreditsRequested=0 and an empty payload. It asserts the connection is terminated within 15 s.
- **Observed:** FAIL: "Actual disconnection time is 15010.477 ms ... Assert.IsFalse failed. Connection should be terminated". pcap: client sends req=0 gr=0 dlen=0 right after negotiate, and the server sends no further messages and no disconnect.
- **Verdict:** KSMBD_FAILURE (high); secondary TEST_INACCURATE. The check is spec-correct per 3.1.5.8, and ksmbd ignores the invalid message. The title and description mention a Negotiate Request, but the code sends a Data Transfer message.
- **Fix:** Fix the description. Add a negative negotiate variant with CreditsRequested=0 and a positive control.

## Unverified / caveats
- The trx outcomes were not available. The authoritative outcome and exception text should be re-checked in `full.trx`.
- The ksmbd internal reason for test 1 is a hypothesis.
- The READ error status in tests 4 and 5 and the cause of the 10-minute write in test 2 were not decoded.
