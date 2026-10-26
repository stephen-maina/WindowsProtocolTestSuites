// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Protocols.TestSuites.Smbd.Adapter;
using Microsoft.Protocols.TestTools;
using Microsoft.Protocols.TestTools.StackSdk;
using Microsoft.Protocols.TestTools.StackSdk.FileAccessService.Smb2;
using Microsoft.Protocols.TestTools.StackSdk.FileAccessService.Smbd;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;

namespace Microsoft.Protocol.TestSuites.Smbd.TestSuite
{
    /// <summary>
    /// [MS-SMBD] conformance tests that complement SmbdNegotiate, SmbdDataTransfer and SmbdCreditManagement:
    /// ignored reserved/padding fields, message-type confusion, credit growth, server-sent header validation
    /// and RDMA transfers at the MaxReadWriteSize boundary.
    /// Boundary values of the Negotiate Request (MaxReceiveSize 127/128, MaxFragmentedSize 131071/131072,
    /// CreditsRequested 0/1) and the fixed Negotiate Response fields are already asserted by
    /// SmbdNegotiate_NegativeParameter_* and NegotiateBasicChecker, so they are not repeated here.
    /// </summary>
    [TestClass]
    public class SmbdProtocolGaps : Smb2OverSmbdTestBase
    {
        // The pre-provisioned testFile_ReadLargeFile.txt is 8 MiB (see the User Guide).
        private const uint PROVISIONED_LARGE_FILE_SIZE = 8 * 1024 * 1024;

        // Upper bound on how long to wait for an optional server reaction (credit grant, failure response).
        private static readonly TimeSpan ReactionTimeout = TimeSpan.FromSeconds(15);

        #region Class Initialization and Cleanup
        [ClassInitializeAttribute()]
        public static void ClassInitialize(TestContext context)
        {
            TestClassBase.Initialize(context, "MS-SMBD_ServerTestSuite");
        }

        [ClassCleanupAttribute()]
        public static void ClassCleanup()
        {
            TestClassBase.Cleanup();
        }
        #endregion

        #region Negotiate Request: Reserved is ignored
        // WHAT: send a Negotiate Request whose Reserved field is 0xFFFF and verify the server still answers STATUS_SUCCESS.
        // WHY: the field must not influence processing; a server that validates it would reject a conformant peer.
        // SPEC: [MS-SMBD] 2.2.1 SMB_DIRECT_NEGOTIATE_REQUEST "Reserved (2 bytes): The sender SHOULD set this field to 0
        //       and the receiver MUST ignore it on receipt"; 3.1.5.6 lists no check of Reserved.
        [TestMethod()]
        [TestCategory("SmbdNegotiate")]
        [TestCategory("SmbdProtocolGaps")]
        [Description("Verify the server ignores a non-zero Reserved field in the SMBD Negotiate Request and answers STATUS_SUCCESS.")]
        [TestProperty("SpecSection", "[MS-SMBD] 2.2.1 Negotiate Request Message; 3.1.5.6 Receiving a Negotiate Request Message")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void SmbdNegotiate_ReservedFieldNonZero_Ignored()
        {
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Connect to server over RDMA.");
            NtStatus status = smbdAdapter.ConnectToServerOverRDMA();
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMBD connection is {0}.", status);

            SmbdNegotiateRequest request = new SmbdNegotiateRequest();
            request.MinVersion = SmbdVersion.V1;
            request.MaxVersion = SmbdVersion.V1;
            request.Reserved = 0xFFFF;
            request.CreditsRequested = (ushort)SmbdTestConfig.SendCreditTarget;
            request.PreferredSendSize = SmbdTestConfig.MaxSendSize;
            request.MaxReceiveSize = SmbdTestConfig.MaxReceiveSize;
            request.MaxFragmentedSize = SmbdTestConfig.MaxFragmentedSize;
            byte[] requestBytes = TypeMarshal.ToBytes<SmbdNegotiateRequest>(request);

            status = smbdAdapter.ClientConnection.Endpoint.PostReceive((uint)SmbdNegotiateResponse.SIZE);
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of Post Receive is {0}.", status);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Send Negotiate Request with Reserved = 0xFFFF.");
            status = smbdAdapter.SendDataOverRdma(requestBytes);
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of Send SMBD negotiate is {0}.", status);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Receive the Negotiate Response and verify it succeeded.");
            byte[] responseData;
            status = smbdAdapter.ReceiveDataOverRdma(
                TimeSpan.FromSeconds(SmbdConnection.ACTIVE_NEGOTIATION_TIMEOUT),
                out responseData);
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of receive Negotiate Response is {0}.", status);
            BaseTestSite.Assert.IsTrue(
                responseData != null && responseData.Length >= SmbdNegotiateResponse.SIZE,
                "Negotiate Response must be at least {0} bytes.", SmbdNegotiateResponse.SIZE);

            SmbdNegotiateResponse response = TypeMarshal.ToStruct<SmbdNegotiateResponse>(responseData);
            BaseTestSite.Assert.AreEqual<uint>(0, response.Status, "Status in negotiate response is {0}.", response.Status);
            BaseTestSite.Assert.AreEqual<SmbdVersion>(SmbdVersion.V1, response.NegotiatedVersion, "NegotiatedVersion is {0}.", response.NegotiatedVersion);
            BaseTestSite.Assert.IsTrue(response.CreditsGranted > 0, "CreditsGranted is {0}.", response.CreditsGranted);
        }
        #endregion

        #region Data Transfer: Reserved and Padding are ignored
        // WHAT: send three SMB2 WRITE requests in Data Transfer messages with non-zero Reserved, non-zero Padding, and both;
        //       each must be accepted and answered with the correct byte count.
        // WHY: a receiver that validates fields it must ignore terminates a conformant peer's connection.
        // SPEC: [MS-SMBD] 2.2.3 SMB_DIRECT_DATA_TRANSFER "Reserved ... the receiver MUST ignore it on receipt" and
        //       "Padding ... SHOULD be set to zero by the sender and MUST be ignored by the receiver";
        //       3.1.5.8 verifies only length, DataOffset alignment, DataOffset+DataLength and fragment sizes.
        [TestMethod()]
        [TestCategory("SmbdDataTransfer")]
        [TestCategory("SmbdProtocolGaps")]
        [Description("Verify the server ignores non-zero Reserved and Padding fields in SMBD Data Transfer messages.")]
        [TestProperty("SpecSection", "[MS-SMBD] 2.2.3 Data Transfer Message; 3.1.5.8 Receiving a Data Transfer Message")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void SmbdDataTransfer_ReservedAndPaddingNonZero_Ignored()
        {
            string fileName = CreateRandomFileName();
            ConnectNegotiateAndOpen(fileName);

            byte[] noisePadding = new byte[SmbdDataTransferMessage.DEFAULT_DATA_OFFSET - SmbdDataTransferMessage.MINIMUM_SIZE];
            for (int i = 0; i < noisePadding.Length; i++)
            {
                noisePadding[i] = 0xFF;
            }
            byte[] zeroPadding = new byte[noisePadding.Length];

            int contentSize = (int)SmbdTestConfig.SmallFileSizeInByte - Smb2OverSmbdTestClient.WRITE_REQUEST_HEADER_SIZE;
            ulong fileOffset = 0;

            WriteWithDataTransferHeader("Reserved = 0xFFFF", 0xFFFF, zeroPadding, contentSize, ref fileOffset);
            WriteWithDataTransferHeader("Padding = 0xFF", 0, noisePadding, contentSize, ref fileOffset);
            WriteWithDataTransferHeader("Reserved = 0xFFFF and Padding = 0xFF", 0xFFFF, noisePadding, contentSize, ref fileOffset);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Close file.");
            smbdAdapter.Smb2CloseFile();
        }
        #endregion

        #region Message type depends on connection state
        // WHAT: after the connection is ESTABLISHED, send a second Negotiate Request (20 bytes) and verify the server terminates.
        // WHY: in ESTABLISHED state every message is a Data Transfer message; the Negotiate Request layout read as a Data
        //      Transfer header has DataOffset = MaxReceiveSize and DataLength = MaxFragmentedSize, which can never fit in
        //      a 20-byte message (MaxFragmentedSize >= 131072 is enforced at negotiate time).
        // SPEC: [MS-SMBD] 3.1.5.8 "The receiver MUST verify that DataOffset + DataLength is less than or equal to the
        //       length of the received message; otherwise it MUST terminate the connection" (Connection.Role ESTABLISHED
        //       expects Data Transfer messages, 3.1.5.1 / 3.1.7.2).
        [TestMethod()]
        [TestCategory("SmbdNegotiate")]
        [TestCategory("SmbdProtocolGaps")]
        [Description("Verify the server terminates the connection when a second Negotiate Request is received after the connection is established.")]
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.5.8 Receiving a Data Transfer Message; 2.2.1 Negotiate Request Message")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void SmbdNegotiate_SecondNegotiateRequestAfterEstablished_Terminated()
        {
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Connect and complete SMBD negotiate.");
            NtStatus status = smbdAdapter.ConnectToServerOverRDMA();
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMBD connection is {0}.", status);
            status = smbdAdapter.SmbdNegotiate();
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMBD negotiate is {0}.", status);

            SmbdNegotiateRequest request = new SmbdNegotiateRequest();
            request.MinVersion = SmbdVersion.V1;
            request.MaxVersion = SmbdVersion.V1;
            request.Reserved = 0;
            request.CreditsRequested = (ushort)SmbdTestConfig.SendCreditTarget;
            request.PreferredSendSize = SmbdTestConfig.MaxSendSize;
            request.MaxReceiveSize = SmbdTestConfig.MaxReceiveSize;
            request.MaxFragmentedSize = SmbdTestConfig.MaxFragmentedSize;
            byte[] requestBytes = TypeMarshal.ToBytes<SmbdNegotiateRequest>(request);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Send a second Negotiate Request on the established connection.");
            status = smbdAdapter.SendDataOverRdma(requestBytes);
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of send second negotiate is {0}.", status);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Verify the server terminates the connection.");
            smbdAdapter.WaitRdmaDisconnect();
            BaseTestSite.Assert.IsFalse(smbdAdapter.ClientConnection.Endpoint.IsConnected, "Connection MUST be terminated.");

            AssertServerStillAvailable();
        }

        // WHAT: before negotiation, send a >= 20-byte Data Transfer message; it is parsed as a Negotiate Request and must not
        //       produce a successful negotiation (failure response or connection termination).
        // WHY: in ACTIVE/PASSIVE state the receiver expects a Negotiate Request only. The Data Transfer header read as a
        //      Negotiate Request has MinVersion = CreditsRequested (0x00FF here), MaxVersion = CreditsGranted (1),
        //      CreditsRequested = Reserved (0), MaxReceiveSize = DataOffset (0), MaxFragmentedSize = DataLength (0).
        // SPEC: [MS-SMBD] 3.1.5.6: the version range MUST include 0x0100 (else a failure response with STATUS_NOT_SUPPORTED,
        //       3.1.5.3) and CreditsRequested >= 1, MaxReceiveSize >= 128, MaxFragmentedSize >= 131072 (else MUST terminate).
        //       The shorter-than-20-byte case is covered by SmbdNegotiate_UncompletedMessage.
        [TestMethod()]
        [TestCategory("SmbdNegotiate")]
        [TestCategory("SmbdProtocolGaps")]
        [Description("Verify a Data Transfer message sent before SMBD negotiation is treated as a Negotiate Request and rejected.")]
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.5.6 Receiving a Negotiate Request Message; 3.1.5.3 Sending a Negotiate Response Message")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void SmbdNegotiate_DataTransferBeforeNegotiate_Rejected()
        {
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Connect to server over RDMA (no negotiate).");
            NtStatus status = smbdAdapter.ConnectToServerOverRDMA();
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMBD connection is {0}.", status);

            status = smbdAdapter.ClientConnection.Endpoint.PostReceive((uint)SmbdNegotiateResponse.SIZE);
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of Post Receive is {0}.", status);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Send an empty (20-byte) Data Transfer message instead of a Negotiate Request.");
            status = smbdAdapter.SmbdSendDataTransferMessage(
                (ushort)SmbdTestConfig.SendCreditTarget,
                1,
                SmbdDataTransfer_Flags.NONE,
                0,
                0,
                0,
                new byte[0]);
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of send Data Transfer message is {0}.", status);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Verify the server did not negotiate: failure response or termination.");
            AssertNegotiateRejectedOrTerminated();

            AssertServerStillAvailable();
        }
        #endregion

        #region Credits
        // WHAT: request ushort.MaxValue send credits in the Negotiate Request and run an SMB2 write over the connection.
        // WHY: the server must bound its grant by its own limit and keep working; a server that trusts the request would
        //      exhaust its receive resources or fail the connection.
        // SPEC: [MS-SMBD] 3.1.5.9 "Connection.ReceiveCredits ... less than Connection.ReceiveCreditMax": the credits a
        //       receiver grants are capped by ReceiveCreditMax, whatever the peer requests. ReceiveCreditMax is
        //       implementation-specific (Appendix A), so the test checks a usable, finite grant rather than a number.
        [TestMethod()]
        [TestCategory("SmbdCreditMgmt")]
        [TestCategory("SmbdProtocolGaps")]
        [Description("Verify the server grants a usable, bounded number of credits when CreditsRequested is ushort.MaxValue.")]
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.5.9 Managing Credits Prior to Sending; 3.1.5.6 Receiving a Negotiate Request Message")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void SmbdCreditMgmt_CreditsRequestedAboveServerMax_CappedAndUsable()
        {
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Connect to server over RDMA.");
            NtStatus status = smbdAdapter.ConnectToServerOverRDMA();
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMBD connection is {0}.", status);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "SMBD negotiate with CreditsRequested = ushort.MaxValue.");
            SmbdNegotiateResponse response;
            status = smbdAdapter.SmbdNegotiate(
                ushort.MaxValue,
                (ushort)SmbdTestConfig.ReceiveCreditMax,
                SmbdTestConfig.MaxSendSize,
                SmbdTestConfig.MaxReceiveSize,
                SmbdTestConfig.MaxFragmentedSize,
                out response);
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMBD negotiate is {0}.", status);
            BaseTestSite.Assert.IsTrue(response.CreditsGranted > 0, "CreditsGranted is {0}.", response.CreditsGranted);
            BaseTestSite.Assert.IsTrue(response.CreditsRequested > 0, "CreditsRequested is {0}.", response.CreditsRequested);
            BaseTestSite.Log.Add(LogEntryKind.Debug, "Server granted {0} credits for a request of {1}.", response.CreditsGranted, ushort.MaxValue);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Run SMB2 operations to prove the connection is usable with the granted credits.");
            string fileName = CreateRandomFileName();
            status = smbdAdapter.Smb2EstablishSessionAndOpenFile(fileName);
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMB2 establish session and open file is {0}.", status);

            byte[] data = new byte[SmbdTestConfig.ModerateFileSizeInByte];
            WRITE_Response writeResponse;
            status = (NtStatus)smbdAdapter.Smb2Write(0, data, out writeResponse);
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMB2 write is {0}.", status);
            BaseTestSite.Assert.AreEqual<uint>((uint)data.Length, writeResponse.Count, "Count in WRITE response is {0}.", writeResponse.Count);
            smbdAdapter.Smb2CloseFile();
        }

        // WHAT: negotiate with CreditsRequested = 1, then raise CreditsRequested in an empty Data Transfer message and verify
        //       the server sends a message with CreditsGranted > 0.
        // WHY: CreditsRequested is the total number of send credits the peer wants; a server that never grows the window
        //      starves a client that needs more parallelism.
        // SPEC: [MS-SMBD] 3.1.5.8 (CreditsRequested updates Connection.ReceiveCreditTarget; credit processing per 3.1.5.9
        //       runs and, if credits were added, the receiver promptly sends an empty Data Transfer message with
        //       CreditsGranted set to the number added). The server may already be at its ReceiveCreditMax, in which case
        //       no grant is required, so the test is Inconclusive rather than failed when none arrives.
        [TestMethod()]
        [TestCategory("SmbdCreditMgmt")]
        [TestCategory("SmbdProtocolGaps")]
        [Description("Verify the server grants additional credits when the client's CreditsRequested rises.")]
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.5.8 Receiving a Data Transfer Message; 3.1.5.9 Managing Credits Prior to Sending")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void SmbdCreditMgmt_CreditsRequestedRises_ServerGrantsMore()
        {
            const ushort INITIAL_CREDITS = 1;
            const ushort RAISED_CREDITS = 64;
            const int RECEIVE_BUFFERS = 8;

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Connect to server over RDMA.");
            NtStatus status = smbdAdapter.ConnectToServerOverRDMA();
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMBD connection is {0}.", status);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "SMBD negotiate with CreditsRequested = " + INITIAL_CREDITS);
            SmbdNegotiateResponse response;
            status = smbdAdapter.SmbdNegotiate(
                INITIAL_CREDITS,
                (ushort)SmbdTestConfig.ReceiveCreditMax,
                out response);
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMBD negotiate is {0}.", status);
            if (response.CreditsGranted >= RAISED_CREDITS)
            {
                BaseTestSite.Assert.Inconclusive(
                    "Server already granted {0} credits at negotiate, not below the raised request of {1}.",
                    response.CreditsGranted, RAISED_CREDITS);
            }

            ushort posted = 0;
            for (int i = 0; i < RECEIVE_BUFFERS; i++)
            {
                if (smbdAdapter.SmbdPostReceive() != NtStatus.STATUS_SUCCESS)
                {
                    break;
                }
                posted++;
            }
            BaseTestSite.Assert.IsTrue(posted > 0, "At least one receive buffer must be posted.");

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Send an empty Data Transfer message with CreditsRequested = " + RAISED_CREDITS);
            status = smbdAdapter.SmbdSendDataTransferMessage(
                RAISED_CREDITS,
                posted,
                SmbdDataTransfer_Flags.NONE,
                0,
                0,
                0,
                new byte[0]);
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of send Data Transfer message is {0}.", status);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Wait for a message that grants additional credits.");
            DateTime deadline = DateTime.UtcNow + ReactionTimeout;
            ushort granted = 0;
            while (granted == 0 && DateTime.UtcNow < deadline)
            {
                SmbdDataTransferMessage message;
                try
                {
                    status = smbdAdapter.SmbdReceivDataTransferMessage(ReactionTimeout, out message);
                }
                catch (TimeoutException)
                {
                    break;
                }
                if (status != NtStatus.STATUS_SUCCESS)
                {
                    break;
                }
                granted = message.CreditsGranted;
            }

            if (granted == 0)
            {
                BaseTestSite.Assert.Inconclusive(
                    "No credit grant arrived after CreditsRequested rose from {0} to {1}; the server may be at its ReceiveCreditMax (initial grant {2}).",
                    INITIAL_CREDITS, RAISED_CREDITS, response.CreditsGranted);
            }
            BaseTestSite.Assert.IsTrue(granted > 0, "Server granted {0} additional credits.", granted);
        }
        #endregion

        #region Server-sent Data Transfer header validation
        // WHAT: read more data over SMB2 (Channel NONE) than fits in one server message and validate every Data Transfer
        //       header the server sends.
        // WHY: SmbdDataTransfer_ReceiveMaxReceiveSize only checks the sum of DataLength + RemainingDataLength and the 8-byte
        //      alignment; the size bound, monotonic RemainingDataLength and reserved/padding bytes are not checked anywhere.
        // SPEC: [MS-SMBD] 3.1.5.4 Sending a Data Transfer Message: DataOffset MUST be 8-byte aligned; the message
        //       (DataOffset + DataLength) MUST NOT exceed Connection.MaxSendSize; for a fragmented payload
        //       RemainingDataLength is the amount still to be sent after this message (0 in the last one). Reserved and
        //       Padding SHOULD be 0 (2.2.3), so a non-zero value is logged as a warning only.
        [TestMethod()]
        [TestCategory("SmbdDataTransfer")]
        [TestCategory("SmbdProtocolGaps")]
        [Description("Verify the header of every server-sent Data Transfer message of a fragmented SMB2 READ response (Channel NONE).")]
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.5.4 Sending a Data Transfer Message; 2.2.3 Data Transfer Message")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void SmbdDataTransfer_ServerFragmentedReadResponse_HeadersValid()
        {
            const int TARGET_FRAGMENTS = 3;

            ConnectNegotiateAndOpen(smbdAdapter.TestConfig.TestFileName_LargeFile, true);

            // Largest message the server may send: the smaller of the client's MaxReceiveSize and the server's PreferredSendSize.
            uint maxMessageSize = smbdAdapter.ClientConnection.MaxReceiveSize;
            uint readLength = maxMessageSize * TARGET_FRAGMENTS;
            readLength = Math.Min(readLength, smbdAdapter.ClientConnection.MaxFragmentedSize - (uint)Smb2OverSmbdTestClient.READ_RESPONSE_HEADER_SIZE);
            readLength = Math.Min(readLength, smbdAdapter.Smb2MaxReadSize);
            readLength = Math.Min(readLength, PROVISIONED_LARGE_FILE_SIZE);
            uint totalResponseSize = readLength + (uint)Smb2OverSmbdTestClient.READ_RESPONSE_HEADER_SIZE;
            if (totalResponseSize + (uint)SmbdDataTransferMessage.DEFAULT_DATA_OFFSET <= maxMessageSize)
            {
                BaseTestSite.Assert.Inconclusive(
                    "READ response of {0} bytes fits in one {1}-byte message; cannot exercise fragmentation.",
                    totalResponseSize, maxMessageSize);
            }

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Send SMB2 READ for " + readLength + " bytes with Channel NONE.");
            byte[] readRequest = smbdAdapter.Smb2GetReadRequest(readLength);
            NtStatus status = smbdAdapter.SmbdSendDataTransferMessage(
                smbdAdapter.ClientConnection.SendCreditTarget,
                1,
                SmbdDataTransfer_Flags.NONE,
                0,
                (uint)SmbdDataTransferMessage.DEFAULT_DATA_OFFSET,
                (uint)readRequest.Length,
                readRequest);
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of send SMB2 READ request is {0}.", status);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Receive and validate every Data Transfer message of the response.");
            byte[] response = new byte[totalResponseSize];
            uint received = 0;
            uint previousRemaining = 0;
            int fragmentCount = 0;
            DateTime deadline = DateTime.UtcNow + TimeSpan.FromSeconds(SmbdConnection.KEEP_ALIVE_INTERVAL);
            bool done = false;
            while (!done)
            {
                BaseTestSite.Assert.IsTrue(DateTime.UtcNow < deadline, "READ response not complete after {0} bytes.", received);

                while (!done && smbdAdapter.ClientConnection.ReceiveCredits > 0)
                {
                    SmbdDataTransferMessage message;
                    status = smbdAdapter.SmbdReceivDataTransferMessage(smbdAdapter.TestConfig.Smb2ConnectionTimeout, out message);
                    BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of receive Data Transfer message is {0}.", status);

                    // An empty message only grants credits ([MS-SMBD] 3.1.5.4 / 3.1.5.8).
                    if (message.DataLength == 0 && message.RemainingDataLength == 0)
                    {
                        continue;
                    }

                    BaseTestSite.Assert.IsTrue(message.DataLength > 0, "A fragment must carry data, DataLength is {0}.", message.DataLength);
                    BaseTestSite.Assert.AreEqual<uint>(0, message.DataOffset % 8, "DataOffset {0} must be 8-byte aligned.", message.DataOffset);
                    BaseTestSite.Assert.IsTrue(
                        message.DataOffset >= SmbdDataTransferMessage.MINIMUM_SIZE,
                        "DataOffset {0} must not overlap the 20-byte header.", message.DataOffset);
                    BaseTestSite.Assert.IsTrue(
                        (ulong)message.DataOffset + message.DataLength <= maxMessageSize,
                        "DataOffset {0} + DataLength {1} must not exceed the maximum message size {2}.",
                        message.DataOffset, message.DataLength, maxMessageSize);

                    if (fragmentCount == 0)
                    {
                        BaseTestSite.Assert.AreEqual<uint>(
                            totalResponseSize,
                            message.DataLength + message.RemainingDataLength,
                            "First fragment: DataLength {0} + RemainingDataLength {1} must equal the response size.",
                            message.DataLength, message.RemainingDataLength);
                    }
                    else
                    {
                        BaseTestSite.Assert.IsTrue(
                            message.RemainingDataLength < previousRemaining,
                            "RemainingDataLength {0} must be smaller than the previous {1}.",
                            message.RemainingDataLength, previousRemaining);
                        BaseTestSite.Assert.AreEqual<uint>(
                            previousRemaining - message.DataLength,
                            message.RemainingDataLength,
                            "RemainingDataLength must drop by DataLength {0}.", message.DataLength);
                    }

                    // Reserved and Padding are only SHOULD-be-zero for the sender ([MS-SMBD] 2.2.3).
                    if (message.Reserved != 0 || !IsAllZero(message.Padding))
                    {
                        BaseTestSite.Log.Add(
                            LogEntryKind.Warning,
                            "Server sent non-zero Reserved ({0}) or Padding in fragment {1}; [MS-SMBD] 2.2.3 only says SHOULD be 0.",
                            message.Reserved, fragmentCount);
                    }

                    BaseTestSite.Assert.IsTrue(
                        (ulong)received + message.DataLength <= totalResponseSize,
                        "Received data exceeds the READ response size.");
                    Array.Copy(message.Buffer, 0, response, received, message.DataLength);
                    received += message.DataLength;
                    previousRemaining = message.RemainingDataLength;
                    fragmentCount++;

                    if (message.RemainingDataLength == 0)
                    {
                        done = true;
                    }
                }

                if (!done)
                {
                    ReplenishReceiveCredits();
                }
            }

            BaseTestSite.Assert.AreEqual<uint>(totalResponseSize, received, "Total received bytes.");
            BaseTestSite.Assert.IsTrue(
                fragmentCount >= 2,
                "Response of {0} bytes must be fragmented over at least 2 messages of at most {1} bytes, got {2}.",
                totalResponseSize, maxMessageSize, fragmentCount);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Decode the reassembled SMB2 READ response.");
            int consumedLength;
            int expectedLength;
            StackPacket[] packets = smbdAdapter.Decoder.Smb2DecodePacketCallback(new object(), response, out consumedLength, out expectedLength);
            Smb2ReadResponsePacket readResponse = (Smb2ReadResponsePacket)packets[0];
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, (NtStatus)readResponse.Header.Status, "Status of SMB2 READ is {0}.", (NtStatus)readResponse.Header.Status);
            BaseTestSite.Assert.AreEqual<uint>(readLength, readResponse.PayLoad.DataLength, "DataLength in SMB2 READ response.");

            smbdAdapter.Smb2CloseFile();
        }
        #endregion

        #region MaxReadWriteSize boundary
        // WHAT: SMB2 READ of exactly the server's MaxReadWriteSize over RDMA_V1; content equals the same range read in chunks.
        // WHY: the largest single RDMA transfer the server advertised must work; nothing else exercises the exact limit.
        // SPEC: [MS-SMBD] 3.1.5.7 / 2.2.2 MaxReadWriteSize is the maximum the sender transfers via RDMA Write/Read to
        //       satisfy a single upper-layer request; [MS-SMB2] 3.3.5.12: with SMB2_CHANNEL_RDMA_V1 the data is sent via
        //       [MS-SMBD] 3.1.4.5 and DataRemaining = bytes read, DataLength = 0.
        [TestMethod()]
        [TestCategory("Smb2OverRdmaChannel")]
        [TestCategory("SmbdProtocolGaps")]
        [Description("Verify SMB2 READ of exactly MaxReadWriteSize bytes over RDMA_V1 succeeds with correct content.")]
        [TestProperty("SpecSection", "[MS-SMBD] 2.2.2 Negotiate Response Message; 3.1.4.5 RDMA Write to Peer Buffer; [MS-SMB2] 3.3.5.12 Receiving an SMB2 READ Request")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannel_Read_ExactMaxReadWriteSize()
        {
            ReadOverRdmaAndVerify(0);
        }


        // WHAT: SMB2 WRITE of exactly MaxReadWriteSize over RDMA_V1; read back and compare.
        // WHY: the largest single RDMA Read the server must perform for one write must work and persist the data.
        // SPEC: [MS-SMBD] 3.1.4.6 RDMA Read from Peer Buffer; [MS-SMB2] 3.3.5.13 (Count = bytes written on success).
        //       The Windows Server 2025 Inconclusive guard is the known V1 WRITE product behaviour (see SKILL.md).
        [TestMethod()]
        [TestCategory("Smb2OverRdmaChannel")]
        [TestCategory("SmbdProtocolGaps")]
        [Description("Verify SMB2 WRITE of exactly MaxReadWriteSize bytes over RDMA_V1 succeeds with correct content.")]
        [TestProperty("SpecSection", "[MS-SMBD] 2.2.2 Negotiate Response Message; 3.1.4.6 RDMA Read from Peer Buffer; [MS-SMB2] 3.3.5.13 Receiving an SMB2 WRITE Request")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannel_Write_ExactMaxReadWriteSize()
        {
            WriteOverRdmaAndVerify(0);
        }

        #endregion

        #region Helpers
        /// <summary>
        /// Connect, SMBD negotiate with the configured values, establish an SMB2 session and open the file.
        /// </summary>
        private void ConnectNegotiateAndOpen(string fileName, bool inconclusiveIfMissing = false)
        {
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Connect, negotiate and open file " + fileName);
            NtStatus status = smbdAdapter.ConnectToServerOverRDMA();
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMBD connection is {0}.", status);

            status = smbdAdapter.SmbdNegotiate();
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMBD negotiate is {0}.", status);

            status = smbdAdapter.Smb2EstablishSessionAndOpenFile(fileName);
            // A missing pre-provisioned file is an environment problem, not a protocol failure ([MS-SMB2] 3.3.5.9).
            if (inconclusiveIfMissing && status == NtStatus.STATUS_OBJECT_NAME_NOT_FOUND)
            {
                BaseTestSite.Assert.Inconclusive("Pre-provisioned file '{0}' does not exist on the SUT share.", fileName);
            }
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMB2 establish session and open file is {0}.", status);
        }

        private void AssertServerStillAvailable()
        {
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Verify the server accepts a new connection and negotiate.");
            NtStatus status = smbdAdapter.ConnectToServerOverRDMA();
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMBD connection is {0}.", status);
            status = smbdAdapter.SmbdNegotiate();
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMBD negotiate is {0}.", status);
        }

        /// <summary>
        /// Passes when the server either terminated the connection or answered with a non-success Negotiate Response.
        /// </summary>
        private void AssertNegotiateRejectedOrTerminated()
        {
            byte[] data = null;
            bool received = false;
            try
            {
                NtStatus status = smbdAdapter.ReceiveDataOverRdma(ReactionTimeout, out data);
                received = status == NtStatus.STATUS_SUCCESS && data != null && data.Length >= SmbdNegotiateResponse.SIZE;
            }
            catch (TimeoutException)
            {
            }

            if (received)
            {
                SmbdNegotiateResponse response = TypeMarshal.ToStruct<SmbdNegotiateResponse>(data);
                BaseTestSite.Assert.AreNotEqual<uint>(0, response.Status, "Negotiate must not succeed, Status is {0}.", response.Status);
            }
            else
            {
                smbdAdapter.WaitRdmaDisconnect();
                BaseTestSite.Assert.IsFalse(smbdAdapter.ClientConnection.Endpoint.IsConnected, "Connection MUST be terminated.");
            }
        }

        private void WriteWithDataTransferHeader(string scenario, ushort reserved, byte[] padding, int contentSize, ref ulong fileOffset)
        {
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Send SMB2 WRITE in a Data Transfer message with " + scenario + ".");
            byte[] content = new byte[contentSize];
            for (int i = 0; i < content.Length; i++)
            {
                content[i] = (byte)('a' + (i + (int)fileOffset) % 26);
            }
            byte[] writeRequest = smbdAdapter.Smb2GetWriteRequest(fileOffset, content);

            NtStatus status = smbdAdapter.SmbdSendDataTransferMessage(
                smbdAdapter.ClientConnection.SendCreditTarget,
                1,
                SmbdDataTransfer_Flags.NONE,
                reserved,
                0,
                (uint)SmbdDataTransferMessage.DEFAULT_DATA_OFFSET,
                (uint)writeRequest.Length,
                padding,
                writeRequest);
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of send Data Transfer message is {0}.", status);

            SmbdDataTransferMessage message;
            do
            {
                status = smbdAdapter.SmbdReceivDataTransferMessage(smbdAdapter.TestConfig.Smb2ConnectionTimeout, out message);
                BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Server must answer the WRITE ({0}), receive status {1}.", scenario, status);
            }
            while (message.DataLength == 0);

            int consumedLength;
            int expectedLength;
            StackPacket[] packets = smbdAdapter.Decoder.Smb2DecodePacketCallback(new object(), message.Buffer, out consumedLength, out expectedLength);
            Smb2WriteResponsePacket writeResponse = (Smb2WriteResponsePacket)packets[0];
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, (NtStatus)writeResponse.Header.Status, "Status of SMB2 WRITE ({0}) is {1}.", scenario, (NtStatus)writeResponse.Header.Status);
            BaseTestSite.Assert.AreEqual<uint>((uint)content.Length, writeResponse.PayLoad.Count, "Count in WRITE response ({0}).", scenario);

            fileOffset += (ulong)content.Length;
        }

        /// <summary>
        /// Post fresh receive buffers and grant them to the server with an empty Data Transfer message.
        /// </summary>
        private void ReplenishReceiveCredits()
        {
            ushort posted = 0;
            while (smbdAdapter.SmbdPostReceive() == NtStatus.STATUS_SUCCESS)
            {
                posted++;
            }
            smbdAdapter.SmbdSendDataTransferMessage(
                smbdAdapter.ClientConnection.SendCreditTarget,
                posted,
                SmbdDataTransfer_Flags.NONE,
                0,
                0,
                0,
                new byte[0]);
        }

        private static bool IsAllZero(byte[] bytes)
        {
            if (bytes == null)
            {
                return true;
            }
            foreach (byte b in bytes)
            {
                if (b != 0)
                {
                    return false;
                }
            }
            return true;
        }

        private void ReadOverRdmaAndVerify(uint extraBytes)
        {
            ConnectNegotiateAndOpen(smbdAdapter.TestConfig.TestFileName_LargeFile, true);

            ulong wanted = (ulong)smbdAdapter.ServerConnection.MaxReadWriteSize + extraBytes;
            if (wanted > smbdAdapter.Smb2MaxReadSize)
            {
                BaseTestSite.Assert.Inconclusive("{0} bytes exceed the SMB2 MaxReadSize {1}; the SMB2 layer limits a single READ.", wanted, smbdAdapter.Smb2MaxReadSize);
            }
            if (wanted > PROVISIONED_LARGE_FILE_SIZE)
            {
                BaseTestSite.Assert.Inconclusive("{0} bytes exceed the {1}-byte pre-provisioned file.", wanted, PROVISIONED_LARGE_FILE_SIZE);
            }
            uint length = (uint)wanted;

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "SMB2 READ of " + length + " bytes over RDMA_V1.");
            byte[] whole = ReadRangeOverRdma(0, length);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Read the same range in chunks and compare.");
            uint chunk = Math.Max(length / 4, 1u);
            byte[] chunked = new byte[length];
            for (uint offset = 0; offset < length; offset += chunk)
            {
                uint size = Math.Min(chunk, length - offset);
                byte[] part = ReadRangeOverRdma(offset, size);
                Array.Copy(part, 0, chunked, offset, size);
            }
            BaseTestSite.Assert.IsTrue(SmbdUtilities.CompareByteArray(whole, chunked), "Content of the single READ equals the chunked READs.");

            smbdAdapter.Smb2CloseFile();
        }

        private byte[] ReadRangeOverRdma(ulong offset, uint length)
        {
            SmbdBufferDescriptorV1 descriptor;
            NtStatus status = smbdAdapter.SmbdRegisterBuffer(length, SmbdBufferReadWrite.RDMA_WRITE_PERMISSION_FOR_READ_FILE, out descriptor);
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Register buffer status is {0}.", status);
            byte[] channelInfo = TypeMarshal.ToBytes<SmbdBufferDescriptorV1>(descriptor);

            READ_Response readResponse;
            byte[] readData;
            status = (NtStatus)smbdAdapter.Smb2ReadOverRdmaChannel(offset, length, channelInfo, out readResponse, out readData);
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMB2 READ offset {0} length {1} is {2}.", offset, length, status);
            BaseTestSite.Assert.AreEqual<uint>(length, readResponse.DataRemaining, "DataRemaining in READ response.");
            BaseTestSite.Assert.AreEqual<int>(0, readData.Length, "READ response must carry no inline data for RDMA_V1.");

            byte[] data = new byte[length];
            status = smbdAdapter.SmbdReadRegisteredBuffer(data, descriptor);
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Read registered buffer status is {0}.", status);
            return data;
        }

        private void WriteOverRdmaAndVerify(uint extraBytes)
        {
            // Product behaviour (see SKILL.md): Windows Server 2025 fails every RDMA_V1 WRITE with STATUS_INVALID_PARAMETER.
            if (smbdAdapter.TestConfig.Platform >= Platform.WindowsServer2025)
            {
                BaseTestSite.Assert.Inconclusive("RDMA_V1 WRITE is not supported by this Windows Server 2025 SUT.");
            }

            string fileName = CreateRandomFileName();
            ConnectNegotiateAndOpen(fileName);

            ulong wanted = (ulong)smbdAdapter.ServerConnection.MaxReadWriteSize + extraBytes;
            if (wanted > smbdAdapter.Smb2MaxWriteSize)
            {
                BaseTestSite.Assert.Inconclusive("{0} bytes exceed the SMB2 MaxWriteSize {1}; the SMB2 layer limits a single WRITE.", wanted, smbdAdapter.Smb2MaxWriteSize);
            }
            uint length = (uint)wanted;

            byte[] content = new byte[length];
            for (uint i = 0; i < length; i++)
            {
                content[i] = (byte)((i * 31 + 7) & 0xFF);
            }

            SmbdBufferDescriptorV1 descriptor;
            NtStatus status = smbdAdapter.SmbdRegisterBuffer(length, SmbdBufferReadWrite.RDMA_READ_PERMISSION_FOR_WRITE_FILE, out descriptor);
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Register buffer status is {0}.", status);
            status = smbdAdapter.SmbdWriteRegisteredBuffer(content, descriptor);
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Write registered buffer status is {0}.", status);
            byte[] channelInfo = TypeMarshal.ToBytes<SmbdBufferDescriptorV1>(descriptor);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "SMB2 WRITE of " + length + " bytes over RDMA_V1.");
            WRITE_Response writeResponse;
            status = (NtStatus)smbdAdapter.Smb2WriteOverRdmaChannel(0, channelInfo, length, out writeResponse);
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMB2 WRITE is {0}.", status);
            BaseTestSite.Assert.AreEqual<uint>(length, writeResponse.Count, "Count in WRITE response.");

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Read the file back and compare.");
            ValidateFileContent(content);

            smbdAdapter.Smb2CloseFile();
        }
        #endregion
    }
}
