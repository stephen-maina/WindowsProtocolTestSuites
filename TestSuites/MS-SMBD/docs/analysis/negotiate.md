# SmbdNegotiate.cs audit (18 tests) — Windows driver 192.168.10.11 vs Linux ksmbd 192.168.10.12

Evidence: `full.trx` (authoritative outcome) + `C:\WPTS-Diagnostics\session-20261008-102557\tests\<test>__<guid>\{ptf-log.ndjson,rdma.pcap}`.
Result totals: **14 Passed, 4 Failed**. Config: Platform=NonWindows, DriverPlatform=WindowsServer2025, SendCreditTarget=255, MaxSendSize(PreferredSendSize)=1364, MaxReceiveSize=8192, MaxFragmentedSize=262144, DisconnectionTimeout=15 s.

Spec sources (Learn, MS-SMBD):
- 3.1.5.6 Receiving a Negotiate Request Message — https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smbd/827afab8-ae7e-4697-ad96-16b7f3f60f65
- 3.1.5.3 Sending a Negotiate Response — .../ms-smbd/58764b50-0908-41f6-a734-949378ed1f87
- 2.2.2 Negotiate Response Message — .../ms-smbd/97960a12-e3c8-4fdc-87be-dc534ca80abf
- 3.1.5.7 Receiving a Negotiate Response — .../ms-smbd/c0399f75-98f4-4185-b201-887d2b1a25a6
- 3.1.7.2 Connection Arrival (5 s Negotiation Timer, >=512-byte receive) — .../ms-smbd/1ebedd96-26fc-4840-86eb-78ad0ac1d2db
- 3.1.2.1 Negotiation Timer — .../ms-smbd/94d47090-dd30-42bc-863b-579c7a6b075d
- Appendix B product behaviour (<5>,<6>,<8>) — .../ms-smbd/91d0c998-25b6-4dd1-8ffb-b836c1d47bad
- 3.1.5.9 credits — .../ms-smbd/40c3ed31-8ae8-42f5-9c4b-f51fabdffacb

Key normative text (3.1.5.6): receiver MUST verify length >= 20 (else terminate); version range MUST include 0x0100 (else Negotiate Response failure, STATUS_NOT_SUPPORTED); CreditsRequested > 0, **MaxReceiveSize >= 128**, **MaxFragmentedSize >= 131,072** (else MUST terminate). Receiver SHOULD set Connection.MaxReceiveSize = min(own, PreferredSendSize) and "if the result is less than 128, MaxReceiveSize MUST be set to 128". 3.1.5.7: response is valid only if MaxReceiveSize >= 128 and MaxFragmentedSize >= 131,072.

## Summary

| Test | Result | Verdict | Conf. | Reason |
|---|---|---|---|---|
| BVT_SmbdNegotiate_Basic | Pass | ACCURATE | high | Valid response checked field by field vs 2.2.2/3.1.5.3 (minor: MaxReadWriteSize>=1 MiB floor is a Windows value) |
| SmbdNegotiate_PreferredSendSizeWithZero | **Fail** | KSMBD_FAILURE | high | ksmbd answers MaxReceiveSize=0, MaxFragmentedSize=0 (MUST be >=128 / >=131072) |
| SmbdNegotiate_PreferredSendSizeLessThan128 | **Fail** | KSMBD_FAILURE | high | ksmbd answers MaxReceiveSize=127, MaxFragmentedSize=16192 (<131072) |
| SmbdNegotiate_PreferredSendSizeMaxValue | Pass | TEST_INACCURATE | high | Description says "server will terminate" but test expects success; platform branch stale (Win 2012R2/2016 only, sends 8136 not the failing case) |
| SmbdNegotiate_Redundancy | Pass | ACCURATE | high | 512-byte request with 492 pad bytes accepted (length >= 20; server posts >=512 receive) |
| SmbdNegotiate_DisconnectAfterNegotiate | Pass | TEST_INACCURATE | med | "Server still available" only proves RDMA CM accept; no re-negotiate despite comment; no spec requirement |
| SmbdNegotiate_UncompletedMessage | Pass | ACCURATE | high | 19-byte message -> server DREQ; full negotiate afterwards OK |
| SmbdNegotiate_VersionRangeNotCover0x0100_LessThanMinVersion | Pass | ACCURATE (+TEST_INACCURATE) | high | ksmbd returns Status 0xC00000BB; test then swallows TimeoutException via Assert.Pass |
| SmbdNegotiate_VersionRangeNotCover0x0100_LargerThanMaxVersion | Pass | ACCURATE (+TEST_INACCURATE) | high | same as above |
| SmbdNegotiate_VersionRangeCover0x0100_EqualMinVersion | Pass | ACCURATE | high | Success + SMB2 negotiate/session/tree/create OK |
| SmbdNegotiate_VersionRangeCover0x0100_EqualMaxVersion | Pass | ACCURATE | high | same |
| SmbdNegotiate_VersionRangeCover0x0100_InMiddle | Pass | ACCURATE | high | same (pcap verified) |
| SmbdNegotiate_VersionRangeCover0x0100_EqualMinVersionAndMaxVersion | Pass | ACCURATE | med | TRX Passed; I did not inspect its log/pcap in detail (unverified beyond outcome) |
| SmbdNegotiate_NegativeParameter_CreditsRequested | Pass | ACCURATE | high | 0 -> DREQ; 1 and 65535 accepted |
| SmbdNegotiate_NegativeParameter_MaxReceiveSize | **Fail** | KSMBD_FAILURE (+TEST_INACCURATE labels) | high | ksmbd terminates MaxReceiveSize=128, which spec says is valid ("at least 128") |
| SmbdNegotiate_NegativeParameter_MaxFragmentedSize | **Fail** | KSMBD_FAILURE (+TEST_INACCURATE labels) | high | ksmbd terminates MaxFragmentedSize=131072, valid per spec |
| SmbdNegotiate_NegotiationTimer | Pass | ACCURATE | high | Negotiate at 4 s succeeds (timer 5 s, 3.1.7.2) |
| SmbdNegotiate_NegotiationTimer_Timeout | Pass | ACCURATE (weak lower bound) | high | pcap: server DREQ 5.50 s after RTU; test would also pass for any disconnect <= 20 s |

Verdict counts (primary): ACCURATE 12 (2 with TEST_INACCURATE secondary for swallowed errors/weakness), KSMBD_FAILURE 4, TEST_INACCURATE 2, WINDOWS_BEHAVIOUR 0, ENV_CONFIG 0.
(Counting the ACCURATE rows: Basic, Redundancy, Uncompleted, 2 NotCover, 4 Cover, Credits, Timer, Timer_Timeout = 12.)

## Cross-cutting findings

1. **Shared checker `NegotiateBasicChecker`** is spec-based for: Min/MaxVersion = 0x0100 and Reserved = 0 (3.1.5.3 MUSTs), NegotiatedVersion (2.2.2), CreditsGranted>0, PreferredSendSize <= request MaxReceiveSize (2.2.2), MaxFragmentedSize >= 131072 (3.1.5.7). `MaxReadWriteSize >= 1048576` is **not** in the spec (Appendix B <7>/<8> Windows values); it does not fail on ksmbd (8 MiB). `MaxReceiveSize <= PreferredSendSize` is only a SHOULD (3.1.5.6).
2. **Order of assertions masks the intended check**: in the PreferredSendSize<128 tests the shared checker fails on MaxFragmentedSize before the test's own `MaxReceiveSize == 128` assertion runs; in the NegativeParameter tests step 2 fails so steps 3 (uint.MaxValue) never run.
3. **Cleanup noise**: `DeleteFile.ps1` logs `CheckFailed ... Cannot find path 'TestDrive:\<guid>.txt'` in several Version tests (swallowed by TestCleanup's catch; tests still Passed). It is a cleanup/infra artefact, not a protocol result.
4. After a failed Negotiate Response the server sends CM_DREQ and the Windows client never answers with DREP, so the server retransmits DREQ for many seconds (pcap, NotCover tests). Client-side behaviour, harmless to the verdicts.
5. ksmbd kernel version was not determined; ksmbd behaviour below is inferred from pcaps, not from source (unverified against code).

## Per-test details

### BVT_SmbdNegotiate_Basic — Pass — ACCURATE (high)
- Purpose: negotiate with configured values succeeds. Spec 3.1.5.3/2.2.2/3.1.5.6.
- Test: connect, negotiate (255 credits, 1364, 8192, 262144), checker. All CheckSucceeded.
- Evidence: response bytes `0100 0100 0100 0000 ff00 ff00 00000000 00008000 54050000 54050000 56a70200` = versions 0x0100, credits 255/255, status 0, MaxReadWrite 8 MiB, PreferredSendSize 1364, MaxReceiveSize 1364, MaxFragmentedSize 173,910.
- Note: MaxReadWriteSize >= 1 MiB is a Windows floor (recommend dropping or making it a log).

### SmbdNegotiate_PreferredSendSizeWithZero — Fail — KSMBD_FAILURE (high)
- Spec: 3.1.5.6 "If the result is less than 128, then Connection.MaxReceiveSize MUST be set to 128"; 3.1.5.7 a response with MaxReceiveSize<128 or MaxFragmentedSize<131072 is invalid.
- Test: PreferredSendSize=0, expects success and MaxReceiveSize == 128.
- Observed: `Assert.IsTrue failed. MaxFragmentedSize in negotiate response is 0` (line 771). Request `...ff00 00000000 00200000 00000400`; response `... 54050000 00000000 00000000` -> MaxReceiveSize=0, MaxFragmentedSize=0.
- Justification: ksmbd derives its sizes from the unclamped PreferredSendSize (0) rather than clamping to 128; response also violates MaxReceiveSize>=128. Test expectation is spec-correct (clamp clause is conditional on the SHOULD, which Windows follows; ksmbd follows min() but not the clamp).
- Test improvement: assert MaxReceiveSize>=128 explicitly before the generic checker so the real defect is reported first.

### SmbdNegotiate_PreferredSendSizeLessThan128 — Fail — KSMBD_FAILURE (high)
- As above with PreferredSendSize=127: response MaxReceiveSize=127 (0x7f), MaxFragmentedSize=16192 (0x3f40 = 127*255/2) -> `MaxFragmentedSize in negotiate response is 16192`. Scenario 2 (128) never executed.
- Test defects (secondary): second log line says "Scenario 1" twice; scenario 2's `MaxReceiveSize == 128` coincides with min(1364,128) so it does not test clamping.

### SmbdNegotiate_PreferredSendSizeMaxValue — Pass — TEST_INACCURATE (high)
- Description: "server will terminate the connection" but the test asserts a successful negotiate (BasicNegotiate). Spec 3.1.5.6 has no upper limit; the 8136 failure is Windows 2012 R2+ behaviour (Appendix B <6>) and spec only says SHOULD-level min().
- Platform branch lists only 2012R2/2016 (Appendix B says "and later"), uses 8136 (which succeeds) rather than the failing value, so the described failure is never tested.
- Observed: request PreferredSendSize 0xffffffff, ksmbd answered normally (1364/1364/173910). Pass is legitimate for ksmbd but does not exercise the described behaviour.
- Fix: rename/describe as "large PreferredSendSize is accepted and clamped"; add Windows-only STATUS_INSUFFICIENT_RESOURCES test for >8136 for all Windows >= 2012R2.

### SmbdNegotiate_Redundancy — Pass — ACCURATE (high)
- Spec 3.1.5.6: message length "at least 20 bytes"; 3.1.7.2 server posts >=512-byte receive. Test sends 512-byte message (20 + 492 zero bytes), response checked by the full checker. pcap: 512-byte SEND, normal 32-byte response.

### SmbdNegotiate_DisconnectAfterNegotiate — Pass — TEST_INACCURATE (med)
- Purpose: server stays available after client disconnects. No spec requirement; it is a robustness check.
- Test only reconnects (CM accept); comment says "connect, and negotiate" but no negotiate is performed, so listener liveness is the only thing shown. Fix: negotiate again after reconnect.

### SmbdNegotiate_UncompletedMessage — Pass — ACCURATE (high)
- Spec 3.1.5.6: length < 20 -> MUST terminate. pcap: 19-byte SEND (pad count removed), server CM_DREQ 1 ms later, no response; subsequent full negotiate succeeds.

### SmbdNegotiate_VersionRangeNotCover0x0100_LessThanMinVersion (Min=0x0101,Max=0xFFFF) — Pass — ACCURATE + TEST_INACCURATE (high)
- Spec 3.1.5.6: MUST respond with failure Negotiate Response, STATUS_NOT_SUPPORTED; 3.1.5.3: other fields zero, graceful termination SHOULD.
- Observed: response `0001 0001 0000 0000 0000 0000 bb0000c0 ...zeros` (Status 0xC00000BB) followed by CM_DREQ. Log: `Status of SMBD negotiate STATUS_NOT_SUPPORTED`.
- Defect: after the check the test tries SMB2 on the dead connection, and the expected `TimeoutException` is turned into `Assert.Pass(...)` inside `catch` (log shows "Assert.Pass succeeded. Cannot send or receive packets"). Any timeout passes; the step verifies nothing. Fix: remove the SMB2 step or assert the endpoint is disconnected.

### SmbdNegotiate_VersionRangeNotCover0x0100_LargerThanMaxVersion (Min=0, Max=0x00FF) — Pass — ACCURATE + TEST_INACCURATE (high)
- Same as above; pcap response status 0xC00000BB then DREQ.

### SmbdNegotiate_VersionRangeCover0x0100_EqualMinVersion / EqualMaxVersion / InMiddle — Pass — ACCURATE (high)
- Spec: range includes 0x0100 -> success. ksmbd responds normally (InMiddle pcap: request min 0x00ff max 0x0101, response status 0, then SMB2 NEGOTIATE/SESSION_SETUP/TREE_CONNECT/CREATE succeed over RDMA, dialect Smb311). The SMB2-over-SMBD step is additional (MS-SMB2 SMB2-over-RDMA works).
- Caveat: spec says Min/MaxVersion SHOULD be ignored when 0x0100 is in range, so these are in-spec cases.

### SmbdNegotiate_VersionRangeCover0x0100_EqualMinVersionAndMaxVersion — Pass — ACCURATE (med)
- Same code path as the other Cover tests (Min=Max=0x0100). Only the TRX outcome was checked; detail not inspected.

### SmbdNegotiate_NegativeParameter_CreditsRequested — Pass — ACCURATE (high)
- Spec 3.1.5.6: CreditsRequested must be > 0 else terminate. pcap: credits=0 -> server DREQ, no response; credits=1 -> response CreditsGranted=1; credits=65535 -> granted 255.

### SmbdNegotiate_NegativeParameter_MaxReceiveSize — Fail — KSMBD_FAILURE (high)
- Spec: MaxReceiveSize "at least 128 bytes" is valid; <128 MUST be terminated.
- Step 1 (127): server DREQ, no response — PASS behaviour. Step 2 (128): server sends DREQ with no negotiate response -> client gets STATUS_CANCELLED: `Assert.AreEqual failed. Expected STATUS_SUCCESS, Actual STATUS_CANCELLED`.
- Justification: ksmbd rejects the boundary value 128 (off-by-one: treats 128 as invalid). Test correct. Step 3 (uint.MaxValue) unreached.
- Test defect (cosmetic): step 2/3 log text says "the connection MUST be terminated" though success is expected.

### SmbdNegotiate_NegativeParameter_MaxFragmentedSize — Fail — KSMBD_FAILURE (high)
- Step 1 (131071) terminated correctly. Step 2 (131072 = 00000200 LE bytes `00 00 02 00`): server DREQ, no response -> STATUS_CANCELLED. Spec says "at least 131,072" is valid. Same off-by-one in ksmbd. Step 3 (uint.MaxValue) unreached. Same cosmetic log issue.

### SmbdNegotiate_NegotiationTimer — Pass — ACCURATE (high)
- Spec 3.1.7.2: 5-second Negotiation Timer. Test sleeps 4 s then negotiates; succeeds. Note the test can never fail by being too slow on the server side unless the timer < 4 s; boundary 5 s not tested.

### SmbdNegotiate_NegotiationTimer_Timeout — Pass — ACCURATE (high, weak lower bound)
- Spec 3.1.2.1/3.1.7.2: server fails and disconnects after 5 s without Negotiate. pcap: CM_RTU at t=0.010, server CM_DREQ at t=5.504 s (conformant); ptf log: "Actual disconnection time is 460 ms" measured after the 5 s sleep. Subsequent negotiate succeeds.
- Weakness: it sleeps 5 s then allows 15 s more, so a server that disconnects at 1 s or 15 s would also pass; no check of ">= ~5 s". Fix: record time since connect and assert 5 s <= t <= ~7 s.

## Recommended fixes (tests)
1. NegativeParameter_* and PreferredSendSize*: assert the specific field (MaxReceiveSize>=128, MaxFragmentedSize>=131072) first; correct log text for the accept boundaries.
2. PreferredSendSizeMaxValue: align description/behaviour; cover all Windows >= 2012 R2 for the 8136 rule.
3. NotCover tests: delete the `Assert.Pass` in `catch` (swallowed error).
4. DisconnectAfterNegotiate: re-negotiate after reconnect.
5. Drop/relax the 1 MiB MaxReadWriteSize floor (Windows-specific).
6. Timer test: bound the elapsed time.

## ksmbd issues to report
- Rejects MaxReceiveSize == 128 and MaxFragmentedSize == 131072 in a Negotiate Request (spec: "at least").
- Does not clamp Connection.MaxReceiveSize to 128 when PreferredSendSize < 128 and derives MaxFragmentedSize from it, producing response values 0/127/16192 (< 131072).
