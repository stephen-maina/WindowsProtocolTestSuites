// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Protocols.TestSuites.Smbd.Adapter;
using Microsoft.Protocols.TestTools;
using Microsoft.Protocols.TestTools.StackSdk;
using Microsoft.Protocols.TestTools.StackSdk.FileAccessService.Smbd;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Threading;


namespace Microsoft.Protocol.TestSuites.Smbd.TestSuite
{
    [TestClass]
    public class SmbdNegotiate : SmbdTestBase
    {
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

        #region Test Cases
        // Spec: [MS-SMBD] 3.1.5.6 Receiving a Negotiate Request Message / 3.1.5.3 Sending a Negotiate Response Message / 2.2.2.
        // A valid request (version range includes 0x0100, CreditsRequested > 0, MaxReceiveSize >= 128,
        // MaxFragmentedSize >= 131072) MUST get a Negotiate Response with Status 0 and NegotiatedVersion 0x0100.
        // Note: the shared NegotiateBasicChecker also asserts CreditsGranted <= CreditsRequested, which is not
        // an explicit spec requirement (3.1.5.9 only bounds receive credits by ReceiveCreditTarget/Max).
        [TestMethod()]
        [TestCategory("BVT")]
        [TestCategory("SmbdNegotiate")]
        [Description("Verify SMBD negotiate request is working as expected using accepted values.")]
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.5.6 Receiving a Negotiate Request Message; 3.1.5.3 Sending a Negotiate Response Message; 2.2.2 Negotiate Response Message")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void BVT_SmbdNegotiate_Basic()
        {
            ushort CREDIT_REQUESTED = (ushort)SmbdTestConfig.SendCreditTarget;
            uint MAX_SEND_SIZE = SmbdTestConfig.MaxSendSize;
            uint MAX_RECEIVE_SIZE = SmbdTestConfig.MaxReceiveSize;
            uint MAX_FRAGMENT_SIZE = SmbdTestConfig.MaxFragmentedSize;

            // test purpose: Verify SMBD negotiate request is working as expected using accepted values.
            SmbdNegotiateResponse response;
            BasicNegotiate(
                CREDIT_REQUESTED,
                MAX_SEND_SIZE,
                MAX_RECEIVE_SIZE,
                MAX_FRAGMENT_SIZE,
                out response);
        }

        // Spec: [MS-SMBD] 3.1.5.6 Receiving a Negotiate Request Message.
        // Receiver SHOULD set Connection.MaxReceiveSize = min(Connection.MaxReceiveSize, PreferredSendSize);
        // if the result is < 128 it MUST be set to 128. Expecting exactly 128 relies on the SHOULD being followed.
        [TestMethod()]
        [TestCategory("SmbdNegotiate")]
        [Description("Verify SMBD negotiate will be successful when PreferredSendSize field is zero.")]
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.5.6 Receiving a Negotiate Request Message")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void SmbdNegotiate_PreferredSendSizeWithZero()
        {
            ushort CREDIT_REQUESTED = (ushort)SmbdTestConfig.SendCreditTarget;
            const uint PREFERRED_SEND_SIZE = 0;
            uint MAX_RECEIVE_SIZE = SmbdTestConfig.MaxReceiveSize;
            uint MAX_FRAGMENT_SIZE = SmbdTestConfig.MaxFragmentedSize;
            SmbdNegotiateResponse response;

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "SMBD negotiate with PreferredSendSize field set to zero.");
            BasicNegotiate(
                CREDIT_REQUESTED,
                PREFERRED_SEND_SIZE,
                MAX_RECEIVE_SIZE,
                MAX_FRAGMENT_SIZE,
                out response);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Verify the response.MaxReceiveSize is at least " + SmbdConnection.FLOOR_MAX_RECEIVE_SIZE);
            VerifyMaxReceiveSize(response, PREFERRED_SEND_SIZE);
        }

        // Spec: [MS-SMBD] 3.1.5.6 Receiving a Negotiate Request Message.
        // Receiver SHOULD set Connection.MaxReceiveSize = min(Connection.MaxReceiveSize, PreferredSendSize);
        // if the result is < 128 it MUST be set to 128 (PreferredSendSize 127 and 128 both yield 128).
        [TestMethod()]
        [TestCategory("SmbdNegotiate")]
        [Description("Verify SMBD negotiate will be successful when PreferredSendSize field is less than 128 bytes.")]
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.5.6 Receiving a Negotiate Request Message")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void SmbdNegotiate_PreferredSendSizeLessThan128()
        {
            ushort CREDIT_REQUESTED = (ushort)SmbdTestConfig.SendCreditTarget;
            // [MS-SMBD] Section 3.1.5.6: if the smaller of Connection.MaxReceiveSize and PreferredSendSize is less
            // than 128, Connection.MaxReceiveSize MUST be set to 128 (the normative floor).
            uint ExpectedSendSize = SmbdConnection.FLOOR_MAX_RECEIVE_SIZE;
            uint MAX_RECEIVE_SIZE = SmbdTestConfig.MaxReceiveSize;
            uint MAX_FRAGMENT_SIZE = SmbdTestConfig.MaxFragmentedSize;
            uint preferredSendSize;
            SmbdNegotiateResponse response;
            
            preferredSendSize = ExpectedSendSize - 1;
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Scenario 1: SMBD negotiate with preferredSendSize set to " + preferredSendSize);
            BasicNegotiate(
                CREDIT_REQUESTED,
                preferredSendSize,
                MAX_RECEIVE_SIZE,
                MAX_FRAGMENT_SIZE,
                out response);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Verify the response.MaxReceiveSize is at least " + SmbdConnection.FLOOR_MAX_RECEIVE_SIZE);
            VerifyMaxReceiveSize(response, preferredSendSize);

            preferredSendSize = ExpectedSendSize;
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Scenario 1: SMBD negotiate with preferredSendSize set to " + preferredSendSize);
            BasicNegotiate(
               CREDIT_REQUESTED,
               preferredSendSize,
               MAX_RECEIVE_SIZE,
               MAX_FRAGMENT_SIZE,
               out response);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Verify the response.MaxReceiveSize is at least " + SmbdConnection.FLOOR_MAX_RECEIVE_SIZE);
            VerifyMaxReceiveSize(response, preferredSendSize);
        }

        // Spec: [MS-SMBD] 3.1.5.6 Receiving a Negotiate Request Message.
        // The spec defines no upper bound for PreferredSendSize (only the 128 floor on the derived MaxReceiveSize);
        // the >8136 failure is Windows-only (Appendix A <6>) and is not normative for ksmbd.
        [TestMethod()]
        [TestCategory("SmbdNegotiate")]
        [Description("Verify the server will terminate the connection when PreferredSendSize field is maximum value of unsigned integer.")]
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.5.6 Receiving a Negotiate Request Message")]
        [TestProperty("SpecCompliance", "TODO")]
        public void SmbdNegotiate_PreferredSendSizeMaxValue()
        {
            // TODO(spec): the Description says the server terminates the connection, but [MS-SMBD] 3.1.5.6 defines no
            // upper bound on PreferredSendSize; the body (correctly) expects STATUS_SUCCESS. The >8136 failure is
            // Windows-only (Appendix A <6>). Fix the Description to say negotiate succeeds.
            ushort CREDIT_REQUESTED = (ushort)SmbdTestConfig.SendCreditTarget;
            uint MAX_RECEIVE_SIZE = SmbdTestConfig.MaxReceiveSize;
            uint MAX_FRAGMENT_SIZE = SmbdTestConfig.MaxFragmentedSize;
            uint preferredSendSize;
            SmbdNegotiateResponse response;

            if (smbdAdapter.TestConfig.IsWindowsServer2012R2OrLater)
            {
                // Windows-specific product behavior, [MS-SMBD] Appendix A <6> (Section 3.1.5.6): Windows Server 2012 R2
                // and later fail the request with STATUS_INSUFFICIENT_RESOURCES if PreferredSendSize is greater than
                // 8136. The limit comes from the WindowsMaxPreferredSendSize ptfconfig property and is applied only
                // when the SUT platform is Windows.
                preferredSendSize = smbdAdapter.TestConfig.WindowsMaxPreferredSendSize;
            }
            else
            {
                // The specification defines no upper bound for PreferredSendSize, so use the field's maximum value.
                preferredSendSize = uint.MaxValue;
            }

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "SMBD negotiate with PreferredSendSize field set to the max value " + preferredSendSize);
            BasicNegotiate(
               CREDIT_REQUESTED,
               preferredSendSize,
               MAX_RECEIVE_SIZE,
               MAX_FRAGMENT_SIZE,
               out response);
        }


        // Spec: [MS-SMBD] 3.1.5.6 Receiving a Negotiate Request Message (and 3.1.7.2 Connection Arrival).
        // The receiver posts a buffer of at least 512 bytes and only requires the message to be at least 20 bytes,
        // so trailing bytes after the 20-byte request must be accepted.
        [TestMethod()]
        [TestCategory("SmbdNegotiate")]
        [Description("Verify server can receive SMBD negotiate request with 512 bytes, 20 bytes of SMBD Negotiate request and 492 redundancy bytes.")]
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.5.6 Receiving a Negotiate Request Message; 3.1.7.2 Connection Arrival")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void SmbdNegotiate_Redundancy()
        {
            ushort CREDIT_REQUESTED = (ushort)SmbdTestConfig.SendCreditTarget;
            uint MAX_SEND_SIZE = SmbdTestConfig.MaxSendSize;
            uint MAX_RECEIVE_SIZE = SmbdTestConfig.MaxReceiveSize;
            uint MAX_FRAGMENT_SIZE = SmbdTestConfig.MaxFragmentedSize;
            // [MS-SMBD] Section 3.1.4.1 / 3.1.5.6: the receiver posts a receive buffer of at least 512 bytes
            // for the Negotiate Request message (the request itself is 20 bytes, the rest is padding).
            const int NEGOTIATE_SIZE = 512;

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Connect to server over RDMA.");
            NtStatus status = smbdAdapter.ConnectToServerOverRDMA();
            BaseTestSite.Assert.AreEqual<NtStatus>(status, NtStatus.STATUS_SUCCESS, "Status of SMBD connection is {0}.", status);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Create SMBD Negotiate request.");
            SmbdNegotiateRequest request = new SmbdNegotiateRequest();
            request.MinVersion = SmbdVersion.V1;
            request.MaxVersion = SmbdVersion.V1;
            request.Reserved = 0;
            request.CreditsRequested = CREDIT_REQUESTED;
            request.PreferredSendSize = MAX_SEND_SIZE;
            request.MaxReceiveSize = MAX_RECEIVE_SIZE;
            request.MaxFragmentedSize = MAX_FRAGMENT_SIZE;

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Add 492 redundancy bytes.");
            byte[] requestBytes = TypeMarshal.ToBytes<SmbdNegotiateRequest>(request);
            byte[] allbytes = new byte[NEGOTIATE_SIZE];
            Array.Copy(requestBytes, allbytes, requestBytes.Length);

            // post receive 
            status = smbdAdapter.ClientConnection.Endpoint.PostReceive(NEGOTIATE_SIZE);
            BaseTestSite.Assert.AreEqual<NtStatus>(status, NtStatus.STATUS_SUCCESS, "Status of Post Receive is {0}.", status);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Send SMBD negotiate request.");
            status = smbdAdapter.SendDataOverRdma(allbytes);
            BaseTestSite.Assert.AreEqual<NtStatus>(status, NtStatus.STATUS_SUCCESS, "Status of Send SMBD negotiate is {0}.", status);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Receive and verify NEGOTIATE response.");
            byte[] responseData;
            smbdAdapter.ReceiveDataOverRdma(
                TimeSpan.FromSeconds(SmbdConnection.ACTIVE_NEGOTIATION_TIMEOUT),
                out responseData);
            SmbdNegotiateResponse response = TypeMarshal.ToStruct<SmbdNegotiateResponse>(responseData);
            smbdAdapter.DisconnectRdma();

            NegotiateBasicChecker(
                response,
                CREDIT_REQUESTED,
                MAX_RECEIVE_SIZE,
                MAX_SEND_SIZE,
                MAX_FRAGMENT_SIZE);
        }

        // Spec: [MS-SMBD] 3.1.7.1 Connection Loss (peer disconnect is handled by terminating the Connection).
        // The spec has no normative statement about the server staying "available" after a client disconnect.
        [TestMethod()]
        [TestCategory("SmbdNegotiate")]
        [Description("Verify server is still available if client disconnect RDMA after SMBD negotiate")]
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.7.1 Connection Loss")]
        [TestProperty("SpecCompliance", "TODO")]
        public void SmbdNegotiate_DisconnectAfterNegotiate()
        {
            // TODO(spec): [MS-SMBD] defines no requirement about server availability after a client disconnect; this is
            // a robustness check, not a spec conformance test. Spec only requires Connection Loss handling (3.1.7.1).
            ushort CREDIT_REQUESTED = (ushort)SmbdTestConfig.SendCreditTarget;
            uint MAX_SEND_SIZE = SmbdTestConfig.MaxSendSize;
            uint MAX_RECEIVE_SIZE = SmbdTestConfig.MaxReceiveSize;
            uint MAX_FRAGMENT_SIZE = SmbdTestConfig.MaxFragmentedSize;

            SmbdNegotiateResponse response;
            BasicNegotiate(
                CREDIT_REQUESTED,
                MAX_SEND_SIZE,
                MAX_RECEIVE_SIZE,
                MAX_FRAGMENT_SIZE,
                out response);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Disconnect from server.");
            smbdAdapter.DisconnectRdma();

            // check server does not crash
            // Connect to server over RDMA, and negotiate
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Verify server is still available after disconnect RDMA after SMBD negotiate.");
            NtStatus ret = smbdAdapter.ConnectToServerOverRDMA();
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, ret, "Status of SMBD connection is {0}", ret);
        }

        // Spec: [MS-SMBD] 3.1.5.6 Receiving a Negotiate Request Message.
        // The receiver MUST verify the message length is at least 20 bytes; otherwise it MUST terminate the connection.
        [TestMethod()]
        [TestCategory("SmbdNegotiate")]
        [Description("Verify server will terminate the connection if received negotiate message is less than 20 bytes.")]
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.5.6 Receiving a Negotiate Request Message")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void SmbdNegotiate_UncompletedMessage()
        {
            ushort CREDIT_REQUESTED = (ushort)SmbdTestConfig.SendCreditTarget;
            uint MAX_SEND_SIZE = SmbdTestConfig.MaxSendSize;
            uint MAX_RECEIVE_SIZE = SmbdTestConfig.MaxReceiveSize;
            uint MAX_FRAGMENT_SIZE = SmbdTestConfig.MaxFragmentedSize;

            #region Create a negotiate message, Sends only 19 bytes of negotiate message to peer
            
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Connect to server over RDMA");
            NtStatus status = smbdAdapter.ConnectToServerOverRDMA();
            BaseTestSite.Assert.AreEqual<NtStatus>(status, NtStatus.STATUS_SUCCESS, "Status of SMBD connection is {0}", status);

            // Create negotiate message
            SmbdNegotiateRequest smbdRequest = new SmbdNegotiateRequest();
            smbdRequest.MinVersion = SmbdVersion.V1;
            smbdRequest.MaxVersion = SmbdVersion.V1;
            smbdRequest.Reserved = 0;
            smbdRequest.CreditsRequested = CREDIT_REQUESTED;
            smbdRequest.PreferredSendSize = MAX_SEND_SIZE;
            smbdRequest.MaxReceiveSize = MAX_RECEIVE_SIZE;
            smbdRequest.MaxFragmentedSize = MAX_FRAGMENT_SIZE;

            byte[] requestBytes = TypeMarshal.ToBytes<SmbdNegotiateRequest>(smbdRequest);
            byte[] uncompletedRequest = new byte[requestBytes.Length - 1];
            Array.Copy(requestBytes, uncompletedRequest, uncompletedRequest.Length);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Send SMBD negotiate message with only 19 bytes.");
            status = smbdAdapter.SendDataOverRdma(uncompletedRequest);
            BaseTestSite.Assert.AreEqual<NtStatus>(status, NtStatus.STATUS_SUCCESS, "Status of Send SMBD negotiate {0}", status);

            // wait for connection to be terminated 
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Verify server connection will be terminated.");
            smbdAdapter.WaitRdmaDisconnect();            
            BaseTestSite.Assert.IsFalse(smbdAdapter.ClientConnection.Endpoint.IsConnected, "Connection should be terminated.");
            #endregion

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Basic negotiate, sending the whole 20 bytes of SMBD negotiate message to peer, verify server returns STATUS_SUCCESS.");
            SmbdNegotiateResponse response;
            BasicNegotiate(
                CREDIT_REQUESTED,
                MAX_SEND_SIZE,
                MAX_RECEIVE_SIZE,
                MAX_FRAGMENT_SIZE,
                out response);
        }

        // Spec: [MS-SMBD] 3.1.5.6 Receiving a Negotiate Request Message.
        // If the range MinVersion..MaxVersion does not include 0x0100 the receiver MUST send a failure
        // Negotiate Response with Status STATUS_NOT_SUPPORTED (3.1.5.3). Here MinVersion = 0x0101 (> 0x0100).
        [TestMethod]
        [TestCategory("SmbdNegotiate")]
        [Description("Verify server responses with STATUS_NOT_SUPPORTED when MinVersion is grater than 0x0100 which should be included in the range.")]
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.5.6 Receiving a Negotiate Request Message; 3.1.5.3 Sending a Negotiate Response Message")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void SmbdNegotiate_VersionRangeNotCover0x0100_LessThanMinVersion()
        {
            Negotiate_Version(
                (SmbdVersion)(SmbdVersion.V1 + 1),
                (SmbdVersion)ushort.MaxValue);
        }

        // Spec: [MS-SMBD] 3.1.5.6 Receiving a Negotiate Request Message.
        // If the range MinVersion..MaxVersion does not include 0x0100 the receiver MUST send a failure
        // Negotiate Response with Status STATUS_NOT_SUPPORTED (3.1.5.3). Here MaxVersion = 0x00FF (< 0x0100).
        [TestMethod]
        [TestCategory("SmbdNegotiate")]
        [Description("Verify server responses with STATUS_NOT_SUPPORTED when MaxVersion is less than 0x0100 which should be included in the range.")]
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.5.6 Receiving a Negotiate Request Message; 3.1.5.3 Sending a Negotiate Response Message")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void SmbdNegotiate_VersionRangeNotCover0x0100_LargerThanMaxVersion()
        {
            Negotiate_Version(
                (SmbdVersion)ushort.MinValue,
                (SmbdVersion)(SmbdVersion.V1 - 1));
        }

        // Spec: [MS-SMBD] 3.1.5.6 Receiving a Negotiate Request Message.
        // If the range MinVersion..MaxVersion includes 0x0100 the request is accepted; the version fields
        // SHOULD be ignored otherwise (Windows <5> rejects ranges other than 0x0100-0x0100, not normative for ksmbd).
        [TestMethod]
        [TestCategory("SmbdNegotiate")]
        [Description("Verify server responses with STATUS_SUCCESS when MinVersion equals to 0x0100 which should be included in the range.")]
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.5.6 Receiving a Negotiate Request Message")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void SmbdNegotiate_VersionRangeCover0x0100_EqualMinVersion()
        {
            Negotiate_Version(
                SmbdVersion.V1,
                (SmbdVersion)ushort.MaxValue);
        }

        // Spec: [MS-SMBD] 3.1.5.6 Receiving a Negotiate Request Message.
        // If the range MinVersion..MaxVersion includes 0x0100 the request is accepted; the version fields
        // SHOULD be ignored otherwise (Windows <5> rejects ranges other than 0x0100-0x0100, not normative for ksmbd).
        [TestMethod]
        [TestCategory("SmbdNegotiate")]
        [Description("Verify server responses with STATUS_SUCCESS when MaxVersion equals to 0x0100 which should be included in the range.")]
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.5.6 Receiving a Negotiate Request Message")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void SmbdNegotiate_VersionRangeCover0x0100_EqualMaxVersion()
        {
            Negotiate_Version(
                (SmbdVersion)ushort.MinValue,
                SmbdVersion.V1);
        }

        // Spec: [MS-SMBD] 3.1.5.6 Receiving a Negotiate Request Message.
        // If the range MinVersion..MaxVersion includes 0x0100 the request is accepted; the version fields
        // SHOULD be ignored otherwise (Windows <5> rejects ranges other than 0x0100-0x0100, not normative for ksmbd).
        [TestMethod]
        [TestCategory("SmbdNegotiate")]
        [Description("Verify server responses with STATUS_SUCCESS when MinVersion is less than 0x0100 while MaxVersion is grater than 0x0100.")]
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.5.6 Receiving a Negotiate Request Message")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void SmbdNegotiate_VersionRangeCover0x0100_InMiddle()
        {
            Negotiate_Version(
                (SmbdVersion)(SmbdVersion.V1 - 1),
                (SmbdVersion)(SmbdVersion.V1 + 1));
        }

        // Spec: [MS-SMBD] 3.1.5.6 Receiving a Negotiate Request Message.
        // The range MinVersion..MaxVersion (0x0100..0x0100) includes 0x0100, so the request MUST be accepted.
        [TestMethod]
        [TestCategory("SmbdNegotiate")]
        [Description("Verify server responses with STATUS_SUCCESS when MinVersion and MaxVersion equal to 0x0100 which should be included in the range.")]
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.5.6 Receiving a Negotiate Request Message")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void SmbdNegotiate_VersionRangeCover0x0100_EqualMinVersionAndMaxVersion()
        {
            Negotiate_Version(
                SmbdVersion.V1,
                SmbdVersion.V1);
        }

        // Spec: [MS-SMBD] 3.1.5.6 Receiving a Negotiate Request Message.
        // The receiver MUST terminate the connection if CreditsRequested is 0; values >= 1 are valid.
        [TestMethod()]
        [TestCategory("SmbdNegotiate")]
        [Description("Verify the server will terminate the connection when CreditsRequested field is less than or equal to 0.")]
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.5.6 Receiving a Negotiate Request Message")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void SmbdNegotiate_NegativeParameter_CreditsRequested()
        {
            const ushort ExpectedCredit = 0;
            uint MAX_SEND_SIZE = SmbdTestConfig.MaxSendSize;
            uint MAX_RECEIVE_SIZE = SmbdTestConfig.MaxReceiveSize;
            uint MAX_FRAGMENT_SIZE = SmbdTestConfig.MaxFragmentedSize;
            ushort creditsRequested = ExpectedCredit;

            // CreditRequested = 0
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "SMBD negotiate with CreditRequested field set to 0.");
            NegativeNegotiate(
                creditsRequested,
                MAX_SEND_SIZE,
                MAX_RECEIVE_SIZE,
                MAX_FRAGMENT_SIZE);

            // CreditRequested = 1
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "SMBD negotiate with CreditRequested field set to 1.");
            creditsRequested = ExpectedCredit + 1;
            SmbdNegotiateResponse response;
            BasicNegotiate(
               creditsRequested,
               MAX_SEND_SIZE,
               MAX_RECEIVE_SIZE,
               MAX_FRAGMENT_SIZE,
               out response);

            // CreditRequested = ushort.MaxValue
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "SMBD negotiate with CreditRequested field set to ushort.MaxValue:" + ushort.MaxValue);
            creditsRequested = ushort.MaxValue;
            BasicNegotiate(
               creditsRequested,
               MAX_SEND_SIZE,
               MAX_RECEIVE_SIZE,
               MAX_FRAGMENT_SIZE,
               out response);
        }

        // Spec: [MS-SMBD] 3.1.5.6 Receiving a Negotiate Request Message.
        // The receiver MUST terminate the connection if MaxReceiveSize < 128 (127 here); 128 and larger are valid.
        [TestMethod()]
        [TestCategory("SmbdNegotiate")]
        [Description("Verify the server will terminate the connection when MaxReceiveSize field is less than 128 bytes.")]
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.5.6 Receiving a Negotiate Request Message")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void SmbdNegotiate_NegativeParameter_MaxReceiveSize()
        {
            ushort CREDIT_REQUESTED = (ushort)SmbdTestConfig.SendCreditTarget;
            uint MAX_SEND_SIZE = SmbdTestConfig.MaxSendSize;
            // [MS-SMBD] Section 3.1.5.6: the Negotiate Request MaxReceiveSize MUST be at least 128 bytes.
            uint ExpectedReceiveSize = SmbdConnection.FLOOR_MAX_RECEIVE_SIZE;
            uint MAX_FRAGMENT_SIZE = SmbdTestConfig.MaxFragmentedSize;
            uint maxReceiveSize;
            SmbdNegotiateResponse response;

            // MaxReceiveSize = 127, the connection MUST be terminated
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "SMBD negotiate with MaxReceiveSize field set to 127, the connection MUST be terminated.");
            maxReceiveSize = ExpectedReceiveSize - 1;
            NegativeNegotiate(
                CREDIT_REQUESTED,
                MAX_SEND_SIZE,
                maxReceiveSize,
                MAX_FRAGMENT_SIZE);

            // MaxReceiveSize = 128(minimum value that can be accepted), the connection MUST be terminated
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "SMBD negotiate with MaxReceiveSize field set to 128 (minimum valid value), the negotiate MUST succeed.");
            maxReceiveSize = ExpectedReceiveSize;
            BasicNegotiate(
               CREDIT_REQUESTED,
               MAX_SEND_SIZE,
               maxReceiveSize,
               MAX_FRAGMENT_SIZE,
               out response);

            // MaxReceiveSize = uint.MaxValue, the connection MUST be terminated
            BaseTestSite.Log.Add(LogEntryKind.TestStep, string.Format("SMBD negotiate with MaxReceiveSize field set to uint.MaxValue {0}, the negotiate MUST succeed.", uint.MaxValue));
            maxReceiveSize = uint.MaxValue;
            BasicNegotiate(
               CREDIT_REQUESTED,
               MAX_SEND_SIZE,
               maxReceiveSize,
               MAX_FRAGMENT_SIZE,
               out response);
        }

        // Spec: [MS-SMBD] 3.1.5.6 Receiving a Negotiate Request Message.
        // The receiver MUST terminate the connection if MaxFragmentedSize < 131,072; 131072 and larger are valid.
        [TestMethod()]
        [TestCategory("SmbdNegotiate")]
        [Description("Verify the server will terminate the connection when MaxFragmentedSize field is less than 131,072 bytes.")]
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.5.6 Receiving a Negotiate Request Message")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void SmbdNegotiate_NegativeParameter_MaxFragmentedSize()
        {
            ushort CREDIT_REQUESTED = (ushort)SmbdTestConfig.SendCreditTarget;
            uint MAX_SEND_SIZE = SmbdTestConfig.MaxSendSize;
            uint MAX_RECEIVE_SIZE = SmbdTestConfig.MaxReceiveSize;
            // [MS-SMBD] Section 3.1.5.6: the Negotiate Request MaxFragmentedSize MUST be at least 131,072 bytes.
            uint ExpectedFragmentedSize = SmbdConnection.FLOOR_MAX_FRAGMENTED_SIZE;
            uint fragmentedSize;
            SmbdNegotiateResponse response;

            // MaxFragmentedSize = 131071, the connection MUST be terminated
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "SMBD negotiate with MaxFragmentedSize field set to 131071, the connection MUST be terminated.");
            fragmentedSize = ExpectedFragmentedSize - 1;
            NegativeNegotiate(
                CREDIT_REQUESTED,
                MAX_SEND_SIZE,
                MAX_RECEIVE_SIZE,
                fragmentedSize);

            // MaxFragmentedSize = 131072, Negotiate with STATUS_SUCCESS
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "SMBD negotiate with MaxFragmentedSize field set to 131072, Negotiate with STATUS_SUCCESS.");
            fragmentedSize = ExpectedFragmentedSize;
            BasicNegotiate(
               CREDIT_REQUESTED,
               MAX_SEND_SIZE,
               MAX_RECEIVE_SIZE,
               fragmentedSize,
               out response);

            // MaxFragmentedSize = uint.MaxValue, Negotiate with STATUS_SUCCESS
            BaseTestSite.Log.Add(LogEntryKind.TestStep, string.Format("SMBD negotiate with MaxFragmentedSize field set to uint.MaxValue {0}, Negotiate with STATUS_SUCCESS.", uint.MaxValue));
            fragmentedSize = uint.MaxValue;
            BasicNegotiate(
               CREDIT_REQUESTED,
               MAX_SEND_SIZE,
               MAX_RECEIVE_SIZE,
               fragmentedSize,
               out response);
        }

        // Spec: [MS-SMBD] 3.1.7.2 Connection Arrival (5-second Negotiation Timer for a PASSIVE connection);
        // 3.1.6.1 Negotiation Timer (on expiry the peer SHOULD terminate). A Negotiate Request sent before the
        // timer expires (4 s here) must be processed normally.
        [TestMethod()]
        [TestCategory("SmbdNegotiate")]
        [Description("Verify server will not terminate connection within 5 seconds after RDMA connection is established")]
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.7.2 Connection Arrival; 3.1.6.1 Negotiation Timer; 3.1.5.6 Receiving a Negotiate Request Message")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void SmbdNegotiate_NegotiationTimer()
        {
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Connect to server over RDMA");
            NtStatus ret = smbdAdapter.ConnectToServerOverRDMA();
            BaseTestSite.Assert.AreEqual<NtStatus>(ret, NtStatus.STATUS_SUCCESS, "Status of SMBD connection is {0}", ret);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Wait 4 seconds (less than the connection timeout of 5 seconds).");
            Thread.Sleep(TimeSpan.FromSeconds(SmbdConnection.PASSIVE_NEGOTIATION_TIMEOUT - 1));

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Send Negotiate request and receive the response.");
            NtStatus status = smbdAdapter.SmbdNegotiate();

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Verify server does not terminate the connection.");
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMBD negotiate", status);
        }

        // Spec: [MS-SMBD] 3.1.7.2 Connection Arrival (5-second Negotiation Timer); 3.1.6.1 Negotiation Timer:
        // "When the Negotiation Timer expires, the local peer SHOULD terminate the connection."
        [TestMethod()]
        [TestCategory("SmbdNegotiate")]
        [Description("Verify server will terminate connection after 5 seconds when RDMA connection is established.")]
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.7.2 Connection Arrival; 3.1.6.1 Negotiation Timer")]
        [TestProperty("SpecCompliance", "TODO")]
        public void SmbdNegotiate_NegotiationTimer_Timeout()
        {
            // TODO(spec): [MS-SMBD] 3.1.6.1 says the peer only SHOULD terminate when the Negotiation Timer expires, and the
            // 5-second value appears only in 3.1.7.2 (Connection Arrival). The test hard-asserts termination right at
            // 5 s with no tolerance; relax to a SHOULD (e.g. allow a grace period / treat non-termination as inconclusive).
            ushort CREDIT_REQUESTED = (ushort)SmbdTestConfig.SendCreditTarget;
            uint MAX_SEND_SIZE = SmbdTestConfig.MaxSendSize;
            uint MAX_RECEIVE_SIZE = SmbdTestConfig.MaxReceiveSize;
            uint MAX_FRAGMENT_SIZE = SmbdTestConfig.MaxFragmentedSize;

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Connect to server over RDMA");
            NtStatus ret = smbdAdapter.ConnectToServerOverRDMA();
            BaseTestSite.Assert.AreEqual<NtStatus>(ret, NtStatus.STATUS_SUCCESS, "Status of SMBD connection is {0}", ret);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Wait 5 seconds for timeout.");
            Thread.Sleep(TimeSpan.FromSeconds(SmbdConnection.PASSIVE_NEGOTIATION_TIMEOUT));
            // wait for connection to be terminated 
            smbdAdapter.WaitRdmaDisconnect();

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Verify server connection will be terminated.");
            BaseTestSite.Assert.IsFalse(smbdAdapter.ClientConnection.Endpoint.IsConnected, "Connection should be terminated.");

            // verify that server is still available
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Verify server is still available, not crashed.");
            SmbdNegotiateResponse response;
            BasicNegotiate(
                CREDIT_REQUESTED,
                MAX_SEND_SIZE,
                MAX_RECEIVE_SIZE,
                MAX_FRAGMENT_SIZE,
                out response);
        }
        #endregion

        #region Test Common Method

        public void BasicNegotiate(
            ushort creditsRequested,
            uint preferredSendSize,
            uint maxReceiveSize,
            uint maxFragmentedSize,
            out SmbdNegotiateResponse response)
        {
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Connect to server over RDMA");
            NtStatus status = smbdAdapter.ConnectToServerOverRDMA();
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMBD connection is {0}", status);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "SMBD Negotiate");
            status = smbdAdapter.SmbdNegotiate(
                creditsRequested,
                (ushort)smbdAdapter.TestConfig.ReceiveCreditMax,
                preferredSendSize,
                maxReceiveSize,
                maxFragmentedSize,
                out response,
                SmbdVersion.V1,
                SmbdVersion.V1
                );
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMBD negotiate is {0}", status);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Verify SMBD negotiate response");
            NegotiateBasicChecker(
                response,
                creditsRequested,
                maxReceiveSize,
                preferredSendSize,
                maxFragmentedSize);
        }


        public void NegativeNegotiate(
            ushort creditsRequested,
            uint preferredSendSize,
            uint maxReceiveSize,
            uint maxFragmentSize)
        {
            // Connect to server over RDMA, and negotiate
            NtStatus status = smbdAdapter.ConnectToServerOverRDMA();
            BaseTestSite.Assert.AreEqual<NtStatus>(status, NtStatus.STATUS_SUCCESS, "Status of SMBD connection is {0}", status);

            // send negotiate message
            SmbdNegotiateRequest smbdRequest = new SmbdNegotiateRequest();
            smbdRequest.MinVersion = SmbdVersion.V1;
            smbdRequest.MaxVersion = SmbdVersion.V1;
            smbdRequest.Reserved = 0;
            smbdRequest.CreditsRequested = creditsRequested;
            smbdRequest.PreferredSendSize = preferredSendSize;
            smbdRequest.MaxReceiveSize = maxReceiveSize;
            smbdRequest.MaxFragmentedSize = maxFragmentSize;

            byte[] requestBytes = TypeMarshal.ToBytes<SmbdNegotiateRequest>(smbdRequest);

            BaseTestSite.Log.Add(LogEntryKind.Debug,
                        @"Send Negotiate request with parameters:
                        MinVersion: {0},
                        MaxVersion: {1},
                        CreditsRequested: {2},
                        PreferredSendSize: {3},
                        MaxReceiveSize: {4},
                        MaxFragmentedSize: {5}
                        ",
                        smbdRequest.MinVersion,
                        smbdRequest.MaxVersion,
                        smbdRequest.CreditsRequested,
                        smbdRequest.PreferredSendSize,
                        smbdRequest.MaxReceiveSize,
                        smbdRequest.MaxFragmentedSize);
            // send message
            status = smbdAdapter.SendDataOverRdma(requestBytes);
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of Send SMBD negotiate {0}", status);

            // wait for connection to be terminated 
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Verify server connection will be terminated.");
            smbdAdapter.WaitRdmaDisconnect();
            BaseTestSite.Assert.IsFalse(smbdAdapter.ClientConnection.Endpoint.IsConnected, "Connection MUST be terminated, but it is not terminated.");
        }

        public void Negotiate_Version(
            SmbdVersion minVer,
            SmbdVersion maxVer)
        {
            ushort CREDIT_REQUESTED = (ushort)SmbdTestConfig.SendCreditTarget;
            ushort RECEIVE_CREDIT_MAX = (ushort)SmbdTestConfig.ReceiveCreditMax;
            uint MAX_SEND_SIZE = SmbdTestConfig.MaxSendSize;
            uint MAX_RECEIVE_SIZE = SmbdTestConfig.MaxReceiveSize;
            uint MAX_FRAGMENT_SIZE = SmbdTestConfig.MaxFragmentedSize;

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Connect to server over RDMA");
            NtStatus status = smbdAdapter.ConnectToServerOverRDMA();
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMBD connection is {0}", status);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, string.Format("SMBD Negotiate, MinVersion: {0}; MaxVersion: {1}", minVer.ToString(), maxVer.ToString()));
            SmbdNegotiateResponse response;
            status = smbdAdapter.SmbdNegotiate(
                CREDIT_REQUESTED,
                RECEIVE_CREDIT_MAX,
                MAX_SEND_SIZE,
                MAX_RECEIVE_SIZE,
                MAX_FRAGMENT_SIZE,
                out response,
                minVer,
                maxVer
                );

            // try to negotiate on SMB2
            string fileName = CreateRandomFileName();

            // Windows Server 2012 fails the Negotiate Request Message with STATUS_NOT_SUPPORTED if MinVersion or MaxVersion is not 0x0100.
            if (smbdAdapter.TestConfig.Platform == Platform.WindowsServer2012)
            {
                if (minVer == SmbdVersion.V1
                    && maxVer == SmbdVersion.V1)
                {
                    BaseTestSite.Assert.AreEqual<NtStatus>(
                        NtStatus.STATUS_SUCCESS,
                        status,
                        "SMBD Negotiate should succeed");

                    BaseTestSite.Log.Add(LogEntryKind.TestStep, "Establish SMB2 connection and open file " + fileName);
                    status = smbdAdapter.Smb2EstablishSessionAndOpenFile(fileName);
                    BaseTestSite.Assert.AreEqual<NtStatus>(
                            NtStatus.STATUS_SUCCESS,
                            status,
                            "Smb2EstablishSessionAndOpenFile should success");
                }
                else
                {
                    BaseTestSite.Assert.AreEqual<NtStatus>(
                        NtStatus.STATUS_NOT_SUPPORTED,
                        status,
                        "Status of SMBD negotiate {0}", status);

                    try
                    {
                        BaseTestSite.Log.Add(LogEntryKind.TestStep, "Try to establish SMB2 connection and open file " + fileName);
                        status = smbdAdapter.Smb2EstablishSessionAndOpenFile(fileName);
                        BaseTestSite.Assert.AreNotEqual<NtStatus>(
                            NtStatus.STATUS_SUCCESS,
                            status,
                            "Status of Smb2EstablishSessionAndOpenFile is {0}", status);
                    }
                    catch (TimeoutException e)
                    {
                        // WHAT: record the timeout instead of Assert.Pass; the SMBD negotiate status was already asserted above.
                        // WHY: the old Pass ended the test and hid the outcome of the follow-up SMB2 attempt.
                        // SPEC: [MS-SMBD] 3.1.5.6 - an unsupported version range is failed with STATUS_NOT_SUPPORTED; Appendix B <5>
                        //       (Windows Server 2012). With the negotiate failed, no SMB2 response is the expected outcome.
                        BaseTestSite.Log.Add(LogEntryKind.Comment, "No SMB2 response after failed SMBD negotiate (expected). " + e.Message);
                    }
                }
            }
            else
            {
                if (minVer <= SmbdVersion.V1
                    && maxVer >= SmbdVersion.V1)
                {
                    BaseTestSite.Assert.AreEqual<NtStatus>(
                        NtStatus.STATUS_SUCCESS,
                        status,
                        "SMBD Negotiate should succeed");

                    BaseTestSite.Log.Add(LogEntryKind.TestStep, "Establish SMB2 connection and open file " + fileName);
                    status = smbdAdapter.Smb2EstablishSessionAndOpenFile(fileName);
                    BaseTestSite.Assert.AreEqual<NtStatus>(
                            NtStatus.STATUS_SUCCESS,
                            status,
                            "Smb2EstablishSessionAndOpenFile should success");
                }
                else
                {
                    BaseTestSite.Assert.AreEqual<NtStatus>(
                        NtStatus.STATUS_NOT_SUPPORTED,
                        status,
                        "Status of SMBD negotiate {0}", status);
                    if (smbdAdapter.TestConfig.DriverPlatform > Platform.NonWindows)
                    {
                        try
                        {
                            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Try to establish SMB2 connection and open file " + fileName);
                            status = smbdAdapter.Smb2EstablishSessionAndOpenFile(fileName);
                            BaseTestSite.Assert.AreNotEqual<NtStatus>(
                                NtStatus.STATUS_SUCCESS,
                                status,
                                "Status of Smb2EstablishSessionAndOpenFile is {0}", status);
                        }
                        catch (TimeoutException e)
                        {
                            // WHAT/WHY/SPEC: as above - [MS-SMBD] 3.1.5.6 STATUS_NOT_SUPPORTED was asserted; a timeout on the follow-up SMB2 attempt is expected.
                            BaseTestSite.Log.Add(LogEntryKind.Comment, "No SMB2 response after failed SMBD negotiate (expected). " + e.Message);
                        }
                    }
                }
            }
        }

        /// <summary>
        /// WHAT: checks the MaxReceiveSize returned in a Negotiate Response.
        /// WHY: [MS-SMBD] 3.1.5.6 only says the receiver SHOULD (Appendix A &lt;6&gt;) set Connection.MaxReceiveSize to
        /// min(Connection.MaxReceiveSize, PreferredSendSize); the result MUST NOT be below 128. A server that
        /// returns its own fixed receive size (e.g. Tuxera's rdma_max_receive_size) is conformant, so the clamp is
        /// asserted only for Windows, which implements it.
        /// SPEC: [MS-SMBD] 3.1.5.6 Receiving a Negotiate Request Message.
        /// </summary>
        private void VerifyMaxReceiveSize(SmbdNegotiateResponse response, uint preferredSendSize)
        {
            BaseTestSite.Assert.IsTrue(
                response.MaxReceiveSize >= SmbdConnection.FLOOR_MAX_RECEIVE_SIZE,
                "MaxReceiveSize in negotiate response is {0}, expected at least {1}",
                response.MaxReceiveSize, SmbdConnection.FLOOR_MAX_RECEIVE_SIZE);

            bool clamped = preferredSendSize < SmbdConnection.FLOOR_MAX_RECEIVE_SIZE
                ? response.MaxReceiveSize == SmbdConnection.FLOOR_MAX_RECEIVE_SIZE
                : response.MaxReceiveSize <= preferredSendSize;

            if (smbdAdapter.TestConfig.IsWindowsPlatform)
            {
                BaseTestSite.Assert.IsTrue(
                    clamped,
                    "MaxReceiveSize in Windows negotiate response is {0}, expected it clamped to PreferredSendSize {1} (at least 128)",
                    response.MaxReceiveSize, preferredSendSize);
            }
            else if (!clamped)
            {
                BaseTestSite.Log.Add(
                    LogEntryKind.Warning,
                    "SUT returned MaxReceiveSize {0} for PreferredSendSize {1}; [MS-SMBD] 3.1.5.6 only SHOULD clamp it.",
                    response.MaxReceiveSize, preferredSendSize);
            }
        }

        public void NegotiateBasicChecker(
            SmbdNegotiateResponse response,
            ushort creditsRequested,
            uint maxReceiveSize,
            uint preferredSendSize,
            uint maxFragmentedSize)
        {
            // verify the response
            BaseTestSite.Assert.AreEqual<SmbdVersion>(
                SmbdVersion.V1,
                response.MinVersion,
                "MinVersion in negotiate response is {0}", response.MinVersion);
            BaseTestSite.Assert.AreEqual<SmbdVersion>(
                SmbdVersion.V1,
                response.MaxVersion,
                "MaxVersion in negotiate response is {0}", response.MaxVersion);
            BaseTestSite.Assert.AreEqual<SmbdVersion>(
                SmbdVersion.V1,
                response.NegotiatedVersion,
                "NegotiatedVersion in negotiate response is {0}", response.NegotiatedVersion);
            BaseTestSite.Assert.AreEqual<ushort>(
                0,
                response.Reserved,
                "Reserved in negotiate response is {0}", response.Reserved);
            BaseTestSite.Assert.IsTrue(
                response.CreditsGranted > 0 && response.CreditsGranted <= creditsRequested,
                "CreditsGranted in negotiate response is {0}", response.CreditsGranted);
            BaseTestSite.Assert.IsTrue(
                response.CreditsRequested > 0,
                "CreditsRequested in negotiate response is {0}", response.CreditsRequested);
            BaseTestSite.Assert.AreEqual<uint>(
                0,
                response.Status,
                "Status in negotiate response is {0}", response.Status);
            // [MS-SMBD] Section 3.1.5.7 defines no lower bound for MaxReadWriteSize; it is the smaller of an
            // implementation-specific value and the peer's value. Only require a non-zero value for every SUT.
            BaseTestSite.Assert.IsTrue(
                response.MaxReadWriteSize > 0,
                "MaxReadWriteSize in negotiate response is {0}", response.MaxReadWriteSize);
            if (smbdAdapter.TestConfig.IsWindowsPlatform)
            {
                // Windows-specific product behavior, [MS-SMBD] Appendix A <7> (Section 3.1.5.7): Windows limits
                // MaxReadWriteSize to 1048576 (Windows Server 2012 without [MSKB-2934016]) or 8388608 (otherwise),
                // so a Windows SUT is expected to return at least WindowsMinMaxReadWriteSize.
                BaseTestSite.Assert.IsTrue(
                    response.MaxReadWriteSize >= smbdAdapter.TestConfig.WindowsMinMaxReadWriteSize,
                    "MaxReadWriteSize in Windows negotiate response is {0}, expected at least {1}",
                    response.MaxReadWriteSize,
                    smbdAdapter.TestConfig.WindowsMinMaxReadWriteSize);
            }
            if (preferredSendSize >= SmbdConnection.FLOOR_MAX_RECEIVE_SIZE)
            {
                VerifyMaxReceiveSize(response, preferredSendSize);
            }
            // server MUST set Connection.MaxSendSize to the smaller(Connection.MaxSendSize, MaxReceiveSize).
            BaseTestSite.Assert.IsTrue(
                response.PreferredSendSize >= SmbdConnection.FLOOR_MAX_RECEIVE_SIZE && response.PreferredSendSize <= maxReceiveSize,
                "PreferredSendSize in negotiate response is {0}", response.PreferredSendSize);
            BaseTestSite.Assert.IsTrue(
                response.MaxFragmentedSize >= SmbdConnection.FLOOR_MAX_FRAGMENTED_SIZE,
                "MaxFragmentedSize in negotiate response is {0}", response.MaxFragmentedSize);
        }

        #endregion
    }
}
