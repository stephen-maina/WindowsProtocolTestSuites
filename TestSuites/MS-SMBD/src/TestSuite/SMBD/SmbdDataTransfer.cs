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
using System.Text;
using System.Threading;


namespace Microsoft.Protocol.TestSuites.Smbd.TestSuite
{
    [TestClass]
    public class SmbdDataTransfer : SmbdTestBase
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
        [TestMethod()]
        [TestCategory("BVT")]
        [TestCategory("SmbdDataTransfer")]
        [Description("Verify SMBD data transfer message can transfer small data as payload")]
        // [MS-SMBD] 3.1.5.4 / 3.1.5.8: a single Data Transfer message (DataOffset 24, 8-byte aligned,
        // RemainingDataLength 0) carrying an upper-layer payload MUST be accepted and passed to the upper layer.
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.5.4 Sending a Data Transfer Message; [MS-SMBD] 3.1.5.8 Receiving a Data Transfer Message")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void BVT_SmbdDataTransfer_Basic_SendSmallBytesOfData()
        {
            // define data for test case
            uint MAX_SEND_SIZE = SmbdTestConfig.MaxSendSize;
            uint MAX_FRAGMENT_SIZE = SmbdTestConfig.MaxFragmentedSize;
            uint MAX_RECEIVE_SIZE = SmbdTestConfig.MaxReceiveSize;

            byte[] smb2WriteRequest;
            byte[] fileContent;
            Initialize_SendSmbdDataTransferTestCase(
                MAX_SEND_SIZE,
                MAX_FRAGMENT_SIZE,
                MAX_RECEIVE_SIZE,
                smbdAdapter.TestConfig.SmallFileSizeInByte,
                out fileContent,
                out smb2WriteRequest);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Send SMBDirect Data Transfer messages.");
            #region Send SMBDirect Data Transfer messages

            // send SMBD Data transfer 
            NtStatus status = (NtStatus)smbdAdapter.SmbdSendDataTransferMessage(
                smbdAdapter.ClientConnection.SendCreditTarget,
                1,
                SmbdDataTransfer_Flags.NONE,
                0,
                (uint)SmbdDataTransferMessage.DEFAULT_DATA_OFFSET,
                (uint)smb2WriteRequest.Length,
                smb2WriteRequest
                );
            BaseTestSite.Assert.AreEqual<NtStatus>(status, NtStatus.STATUS_SUCCESS, "Status of send SMB2 negotiate request is {0}", status);

            #endregion

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Validate Write response.");
            ValidateWriteResponse(fileContent);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Validate file content.");
            ValidateFileContent(fileContent);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Close file and disconnect from server.");
            smbdAdapter.Smb2CloseFile();
            // disconnect
            smbdAdapter.DisconnectRdma();
        }

        [TestMethod()]
        [TestCategory("BVT")]
        [TestCategory("SmbdDataTransfer")]
        [Description("Verify higher-layer can transfer moderate size data over SMBD."
                    + "And SUT can receive several segments of one fragment and reassemble several SMBD Data Transfer message.")]
        // [MS-SMBD] 3.1.5.4 / 3.1.5.8 / 3.1.5.9: a payload split into several segments (RemainingDataLength = bytes not yet sent)
        // MUST be reassembled by the receiver; when new credits are available the receiver MUST promptly send an
        // empty Data Transfer message with CreditsGranted set to the number of new credits.
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.5.4 Sending a Data Transfer Message; [MS-SMBD] 3.1.5.8 Receiving a Data Transfer Message; [MS-SMBD] 3.1.5.9 Managing Credits Prior to Sending")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void BVT_SmbdDataTransfer_Basic_SendModerateBytesData()
        {
            // define data for test case
            uint MAX_SEND_SIZE = SmbdTestConfig.MaxSendSize;
            uint MAX_FRAGMENT_SIZE = SmbdTestConfig.MaxFragmentedSize;
            uint MAX_RECEIVE_SIZE = SmbdTestConfig.MaxReceiveSize;

            byte[] smb2WriteRequest;
            byte[] fileContent;
            NtStatus status;
            Initialize_SendSmbdDataTransferTestCase(
                MAX_SEND_SIZE,
                MAX_FRAGMENT_SIZE,
                MAX_RECEIVE_SIZE,
                smbdAdapter.TestConfig.ModerateFileSizeInByte,
                out fileContent,
                out smb2WriteRequest);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Send SMBDirect Data Transfer messages.");

            #region Send SMBDirect Data Transfer messages

            // devide data into multiple segments
            List<SmbdDataTransferMessage> messages = SmbdClient.SplitData2Segments(
                smb2WriteRequest,
                smbdAdapter.ClientConnection.MaxSendSize - (uint)SmbdDataTransferMessage.DEFAULT_DATA_OFFSET);

            SmbdDataTransferMessage transferPackage;
            for (int index = 0; index < messages.Count;)
            {
                for (; index < messages.Count && smbdAdapter.ClientConnection.SendCredits > 0; ++index)
                {
                    status = (NtStatus)smbdAdapter.SmbdSendDataTransferMessage(
                        (ushort)(messages.Count - index),
                        1,
                        SmbdDataTransfer_Flags.NONE,
                        messages[index].RemainingDataLength,
                        messages[index].DataOffset,
                        messages[index].DataLength,
                        messages[index].Buffer
                        );
                    smbdAdapter.ClientConnection.SendCredits--;
                    BaseTestSite.Assert.AreEqual<NtStatus>(
                        NtStatus.STATUS_SUCCESS,
                        status,
                        "Status of send segment with length {0}",
                        messages[index].DataLength
                        );
                }

                if (index < messages.Count)
                {
                    // receive the empty message for granting send credits
                    status = (NtStatus)smbdAdapter.SmbdReceivDataTransferMessage(
                        TimeSpan.FromSeconds(SmbdConnection.KEEP_ALIVE_INTERVAL),
                        out transferPackage
                        );
                    BaseTestSite.Assert.AreEqual<uint>(0, transferPackage.DataLength, "Empty message");

                    #region Check the empty message, which is to grant credit
                    BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of receive SMB2 negotiate response {0}", status);

                    // BaseTestSite.Assert.AreEqual<ushort>(1, transferPackage.CreditsGranted, "CreditsGranted of Response is {0}", transferPackage.CreditsGranted);
                    BaseTestSite.Assert.IsTrue(transferPackage.CreditsGranted > 0, "CreditsGranted of Response is {0}", transferPackage.CreditsRequested);
                    BaseTestSite.Assert.IsTrue(transferPackage.CreditsRequested > 0, "CreditsRequested of Response is {0}", transferPackage.CreditsRequested);
                    BaseTestSite.Assert.AreEqual<SmbdDataTransfer_Flags>(SmbdDataTransfer_Flags.NONE, transferPackage.Flags, "Flags of Response is {0}", transferPackage.Flags);
                    BaseTestSite.Assert.AreEqual<ushort>(0, transferPackage.Reserved, "Reserved of Response is {0}", transferPackage.Reserved);
                    BaseTestSite.Assert.AreEqual<uint>(0, transferPackage.RemainingDataLength, "Reserved of Response is {0}", transferPackage.RemainingDataLength);
                    BaseTestSite.Assert.AreEqual<uint>(0, transferPackage.DataOffset, "DataOffset of Response is {0}", transferPackage.DataOffset);
                    BaseTestSite.Assert.AreEqual<uint>(0, transferPackage.DataLength, "DataLength of Response is {0}", transferPackage.DataLength);
                    BaseTestSite.Assert.AreEqual<uint>(0, (uint)transferPackage.Padding.Length, "Padding length is {0}", transferPackage.Padding.Length);
                    #endregion

                    // raise receive request for write response
                    status = smbdAdapter.SmbdPostReceive();
                }
            }

            #endregion

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Validate Write response.");
            ValidateWriteResponse(fileContent);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Validate file content.");
            ValidateFileContent(fileContent);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Close file and disconnect from server.");
            smbdAdapter.Smb2CloseFile();
            // disconnect
            smbdAdapter.DisconnectRdma();
        }

        [TestMethod()]
        [TestCategory("SmbdDataTransfer")]
        [Description("Send moderate size data over SMBD in several segments and DataLength in each segment is variable. Verify SUT can receive all segments and reassemble data correctly.")]
        // [MS-SMBD] 3.1.5.8: the receiver appends each segment (DataOffset/DataLength) to Connection.FragmentReassemblyBuffer;
        // FragmentReassemblyRemaining is set from the first RemainingDataLength and reduced by each DataLength, and the buffer is
        // passed up when RemainingDataLength is 0. The spec allows segments of any DataLength (including 0).
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.5.8 Receiving a Data Transfer Message")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void SmbdDataTransfer_VariableLengthSegment()
        {
            // define data for test case
            uint MAX_SEND_SIZE = SmbdTestConfig.MaxSendSize;
            uint MAX_FRAGMENT_SIZE = SmbdTestConfig.MaxFragmentedSize;
            uint MAX_RECEIVE_SIZE = SmbdTestConfig.MaxReceiveSize;

            byte[] smb2WriteRequest;
            byte[] fileContent;

            Initialize_SendSmbdDataTransferTestCase(
                MAX_SEND_SIZE,
                MAX_FRAGMENT_SIZE,
                MAX_RECEIVE_SIZE,
                smbdAdapter.TestConfig.ModerateFileSizeInByte,
                out fileContent,
                out smb2WriteRequest);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Send first empty message with RemainingDataLength set to the size of data.");
            #region Send first empty message with RemainingDataLength = size of data
            // [MS-SMBD] Section 3.1.5.1: CreditsRequested is set to Connection.SendCreditTarget (SendCreditTarget ptfconfig property).
            NtStatus status = (NtStatus)smbdAdapter.SmbdSendDataTransferMessage(
                        (ushort)SmbdTestConfig.SendCreditTarget,
                        1,
                        SmbdDataTransfer_Flags.NONE,
                        (uint)smb2WriteRequest.Length,
                        0,
                        0,
                        new byte[0]
                        );
            smbdAdapter.ClientConnection.SendCredits--;
            BaseTestSite.Assert.AreEqual<NtStatus>(
                NtStatus.STATUS_SUCCESS,
                status,
                "Status of send segment with first empty message");
            #endregion

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Send data with multiple SMBD Data Transfer messages.");
            /// Send data with multiple SMBD Data Transfer messages
            /// . Send SMBD Data Transfer message with data length 128
            /// . Send SMBD Data Transfer message with data length 127
            /// . Send SMBD Data Transfer message with data length 126
            /// .....
            /// . Send SMBD Data Transfer message with data length 1
            /// . Send SMBD Data Transfer message with data length 0
            /// . Send SMBD Data Transfer message with data length 1
            /// .....
            SendMultipleSegmentsWithVariableDataLength(smb2WriteRequest);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Validate Write response.");
            ValidateWriteResponse(fileContent);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Validate File content.");
            ValidateFileContent(fileContent);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Close File and disconnect from server.");
            smbdAdapter.Smb2CloseFile();
            // disconnect
            smbdAdapter.DisconnectRdma();
        }

        [TestMethod()]
        [TestCategory("SmbdDataTransfer")]
        [Description("Send MaxFragmentSize data over SMBD in several segments and DataLength in each segment is 1 byte."
                    + "So there are a large number of SMBD Data Transfer messages in one fragment. Verify SUT can receive all segments and reassemble data correctly.")]
        // [MS-SMBD] 3.1.5.8: many 1-byte segments (each padded with trailing bytes to the server's MaxReceiveSize) MUST be reassembled
        // correctly; trailing bytes beyond DataOffset + DataLength are permitted (only the sum <= message length is verified).
        // Note: the Description mentions MaxFragmentSize data but the test uses ModerateFileSizeInByte.
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.5.8 Receiving a Data Transfer Message")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void SmbdDataTransfer_SmallLengthSegment()
        {
            // define data for test case
            uint MAX_SEND_SIZE = SmbdTestConfig.MaxSendSize;
            uint MAX_FRAGMENT_SIZE = SmbdTestConfig.MaxFragmentedSize;
            uint MAX_RECEIVE_SIZE = SmbdTestConfig.MaxReceiveSize;

            byte[] smb2WriteRequest;
            byte[] fileContent;
            Initialize_SendSmbdDataTransferTestCase(
                MAX_SEND_SIZE,
                MAX_FRAGMENT_SIZE,
                MAX_RECEIVE_SIZE,
                smbdAdapter.TestConfig.ModerateFileSizeInByte,
                out fileContent,
                out smb2WriteRequest);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Send multiple segments with variable data length.");
            SendMultipleSegmentsWithVariableDataLength(
                smb2WriteRequest,
                true,
                true);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Validate Write response");
            ValidateWriteResponse(fileContent);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Validate file content");
            ValidateFileContent(fileContent);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Close file and disconnect from server.");
            smbdAdapter.Smb2CloseFile();
            // disconnect
            smbdAdapter.DisconnectRdma();
        }

        [TestMethod()]
        [TestCategory("SmbdDataTransfer")]
        [Description("Verify server can receive SMBD Data Transfer message with redundancy bytes at the end of SMBD Data Transfer message.")]
        // [MS-SMBD] 3.1.5.8: the receiver verifies only that DataOffset + DataLength <= received message length, so bytes after
        // the payload are tolerated; 2.2.3 Padding MUST be ignored by the receiver.
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.5.8 Receiving a Data Transfer Message; [MS-SMBD] 2.2.3 Data Transfer Message")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void SmbdDataTransfer_Redundancy()
        {
            // define data for test case
            uint MAX_SEND_SIZE = SmbdTestConfig.MaxSendSize;
            uint MAX_FRAGMENT_SIZE = SmbdTestConfig.MaxFragmentedSize;
            uint MAX_RECEIVE_SIZE = SmbdTestConfig.MaxReceiveSize;

            byte[] smb2WriteRequest;
            byte[] fileContent;

            Initialize_SendSmbdDataTransferTestCase(
                MAX_SEND_SIZE,
                MAX_FRAGMENT_SIZE,
                MAX_RECEIVE_SIZE,
                smbdAdapter.TestConfig.SmallFileSizeInByte,
                out fileContent,
                out smb2WriteRequest);

            SmbdDataTransferMessage dataTransferMessage = new SmbdDataTransferMessage();
            dataTransferMessage.CreditsRequested = (ushort)SmbdTestConfig.SendCreditTarget; // [MS-SMBD] Section 3.1.5.1
            dataTransferMessage.CreditsGranted = 1;
            dataTransferMessage.Flags = SmbdDataTransfer_Flags.NONE;
            dataTransferMessage.DataOffset = 24;
            dataTransferMessage.RemainingDataLength = 0;
            dataTransferMessage.Reserved = 0;
            dataTransferMessage.Padding = new byte[4];
            dataTransferMessage.DataLength = (uint)smb2WriteRequest.Length;
            dataTransferMessage.Buffer = smb2WriteRequest;

            // generate bytes and add Redundancy bytes
            byte[] smbdBytes = TypeMarshal.ToBytes<SmbdDataTransferMessage>(dataTransferMessage);
            byte[] smbdBytesWithRedundancy = new byte[MAX_SEND_SIZE];
            Array.Copy(smbdBytes, smbdBytesWithRedundancy, smbdBytes.Length);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Send Data with redundancy bytes over RDMA.");
            smbdAdapter.SendDataOverRdma(smbdBytesWithRedundancy);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Validate Write response.");
            ValidateWriteResponse(fileContent);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Validate File content.");
            ValidateFileContent(fileContent);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Close file and disconnect from server.");
            smbdAdapter.Smb2CloseFile();
            // disconnect
            smbdAdapter.DisconnectRdma();
        }

        [TestMethod()]
        [TestCategory("SmbdDataTransfer")]
        [Description("Make server send MaxReceiveSize size data. Verify the parameters DataLength, DataOffset and DataRemainingLength in received SMBD Data Transfer message")]
        // [MS-SMBD] 3.1.5.4: when sending, DataOffset MUST be 8-byte aligned, DataOffset + DataLength MUST NOT exceed
        // Connection.MaxSendSize, and RemainingDataLength is the total not yet sent (0 in the final segment).
        // The test checks alignment and DataLength + RemainingDataLength per message; it does not assert DataOffset == 24 (only a SHOULD).
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.5.4 Sending a Data Transfer Message; [MS-SMBD] 2.2.3 Data Transfer Message")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void SmbdDataTransfer_ReceiveMaxReceiveSize()
        {
            // define data for test case
            uint MAX_SEND_SIZE = SmbdTestConfig.MaxSendSize;
            uint MAX_FRAGMENT_SIZE = SmbdTestConfig.MaxFragmentedSize;
            uint MAX_RECEIVE_SIZE = SmbdTestConfig.MaxReceiveSize;

            Initialize_ReceiveSmbdDataTransferTestCase(
                MAX_SEND_SIZE,
                MAX_FRAGMENT_SIZE,
                MAX_RECEIVE_SIZE,
                0,
                true);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Validate SMB2 Read response.");
            ValidateReadResponse((int)smbdAdapter.ClientConnection.MaxReceiveSize);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Close file and disconnect from server.");
            smbdAdapter.Smb2CloseFile();
            smbdAdapter.DisconnectRdma();
        }

        [TestMethod()]
        [TestCategory("SmbdDataTransfer")]
        [Description("Verify server will terminate the connection if received data transfer message is less than 20 bytes.")]
        // [MS-SMBD] 3.1.5.8: the receiver MUST verify the received message is at least 20 bytes; otherwise it MUST terminate
        // the connection and cease processing.
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.5.8 Receiving a Data Transfer Message")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void SmbdDataTransfer_UncompletedMessage()
        {
            // define data for test case
            uint MAX_SEND_SIZE = SmbdTestConfig.MaxSendSize;
            uint MAX_FRAGMENT_SIZE = SmbdTestConfig.MaxFragmentedSize;
            uint MAX_RECEIVE_SIZE = SmbdTestConfig.MaxReceiveSize;
            const int UNCOMPLETE_SIZE = 19;

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Connect to server over RDMA");
            NtStatus status = smbdAdapter.ConnectToServerOverRDMA();
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMBD connection is {0}", status);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "SMBD Negotiate");
            SmbdNegotiateResponse response;
            status = smbdAdapter.SmbdNegotiate(MAX_SEND_SIZE, MAX_RECEIVE_SIZE, MAX_FRAGMENT_SIZE, out response);
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMBD negotiate is {0}", status);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Generate a 19-bytes packet.");
            SmbdDataTransferMessage dataTransfer = new SmbdDataTransferMessage();
            dataTransfer.CreditsRequested = smbdAdapter.ClientConnection.SendCreditTarget;
            dataTransfer.CreditsGranted = 1;
            dataTransfer.Flags = SmbdDataTransfer_Flags.NONE;
            dataTransfer.RemainingDataLength = 0;
            dataTransfer.DataOffset = 0;
            dataTransfer.DataLength = 0;
            dataTransfer.Padding = new byte[0];
            dataTransfer.Buffer = new byte[0];
            byte[] dataTransferPackage = TypeMarshal.ToBytes<SmbdDataTransferMessage>(dataTransfer);
            byte[] uncompleteDataTransferPackage = new byte[UNCOMPLETE_SIZE];
            Array.Copy(dataTransferPackage, uncompleteDataTransferPackage, UNCOMPLETE_SIZE);

            // send message out
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Send the uncompleted Data Transfer package to server.");
            status = smbdAdapter.SendDataOverRdma(uncompleteDataTransferPackage);
            BaseTestSite.Assert.AreEqual<NtStatus>(status, NtStatus.STATUS_SUCCESS, "Status of send SMBDirect Data Transfer message is {0}", status);

            // wait for connection to be terminated 
            smbdAdapter.WaitRdmaDisconnect();
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Verify server connection will be terminated.");
            BaseTestSite.Assert.IsFalse(smbdAdapter.ClientConnection.Endpoint.IsConnected, "Connection should be terminated.");
        }

        [TestMethod()]
        [TestCategory("SmbdDataTransfer")]
        [Description("Verify the connection will be terminated if DataOffset is not 8-byte aligned.")]
        // [MS-SMBD] 3.1.5.8 / 2.2.3: DataOffset MUST be 8-byte aligned; if the received DataOffset is not aligned the
        // receiver MUST terminate the connection.
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.5.8 Receiving a Data Transfer Message; [MS-SMBD] 2.2.3 Data Transfer Message")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void SmbdDataTransfer_NegativeParameter_DataOffset_Against8ByteAligned()
        {
            const int EXPECTED_DATA_OFFSET = 24;
            // define data for test case
            uint MAX_SEND_SIZE = SmbdTestConfig.MaxSendSize;
            uint MAX_FRAGMENT_SIZE = SmbdTestConfig.MaxFragmentedSize;
            uint MAX_RECEIVE_SIZE = SmbdTestConfig.MaxReceiveSize;

            byte[] smb2WriteRequest;
            byte[] fileContent;
            NtStatus status;

            #region EXPECTED_DATA_OFFSET - 1
            Initialize_SendSmbdDataTransferTestCase(
                MAX_SEND_SIZE,
                MAX_FRAGMENT_SIZE,
                MAX_RECEIVE_SIZE,
                smbdAdapter.TestConfig.SmallFileSizeInByte,
                out fileContent,
                out smb2WriteRequest);

            // Send SMBD Data Transfer message
            BaseTestSite.Log.Add(LogEntryKind.TestStep, string.Format("Send SMBD Data Transfer message with offset {0} which is not 8-byte aligned.", EXPECTED_DATA_OFFSET - 1));
            status = (NtStatus)smbdAdapter.SmbdSendDataTransferMessage(
                smbdAdapter.ClientConnection.SendCreditTarget,
                1,
                SmbdDataTransfer_Flags.NONE,
                0,
                EXPECTED_DATA_OFFSET - 1,
                (uint)smb2WriteRequest.Length,
                smb2WriteRequest
                );
            BaseTestSite.Assert.AreEqual<NtStatus>(status, NtStatus.STATUS_SUCCESS, "Status of send SMBDirect Data Transfer message is {0}", status);

            // wait for connection to be terminated 
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Verify server connection will be terminated.");
            smbdAdapter.WaitRdmaDisconnect();
            BaseTestSite.Assert.IsFalse(smbdAdapter.ClientConnection.Endpoint.IsConnected, "Connection should be terminated.");
            #endregion

            #region EXPECTED_DATA_OFFSET + 1
            Initialize_SendSmbdDataTransferTestCase(
                MAX_SEND_SIZE,
                MAX_FRAGMENT_SIZE,
                MAX_RECEIVE_SIZE,
                smbdAdapter.TestConfig.SmallFileSizeInByte,
                out fileContent,
                out smb2WriteRequest);

            // Send SMBD Data Transfer message
            BaseTestSite.Log.Add(LogEntryKind.TestStep, string.Format("Send SMBD Data Transfer message with offset {0} which is not 8-byte aligned.", EXPECTED_DATA_OFFSET + 1));
            status = (NtStatus)smbdAdapter.SmbdSendDataTransferMessage(
                smbdAdapter.ClientConnection.SendCreditTarget,
                1,
                SmbdDataTransfer_Flags.NONE,
                0,
                EXPECTED_DATA_OFFSET + 1,
                (uint)smb2WriteRequest.Length,
                smb2WriteRequest
                );
            BaseTestSite.Assert.AreEqual<NtStatus>(status, NtStatus.STATUS_SUCCESS, "Status of send SMBDirect Data Transfer message is {0}", status);

            // wait for connection to be terminated 
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Verify server connection will be terminated.");
            smbdAdapter.WaitRdmaDisconnect();
            BaseTestSite.Assert.IsFalse(smbdAdapter.ClientConnection.Endpoint.IsConnected, "Connection should be terminated.");
            #endregion

        }

        [TestMethod()]
        [TestCategory("SmbdDataTransfer")]
        [Description("Verify the connection will be terminated if DataOffset + DataLength is greater than message length. "
                    + "In this case, only change DataOffset to terminate the connection.")]
        // [MS-SMBD] 3.1.5.8: the receiver MUST verify DataOffset + DataLength <= received message length, otherwise terminate.
        // Scenario 2 (uint.MaxValue) is additionally not 8-byte aligned, so it also trips the alignment check (still terminates).
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.5.8 Receiving a Data Transfer Message")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void SmbdDataTransfer_NegativeParameter_DataOffset_AgainstMessageLength()
        {
            const int EXPECTED_DATA_OFFSET = 24;
            // define data for test case
            uint MAX_SEND_SIZE = SmbdTestConfig.MaxSendSize;
            uint MAX_FRAGMENT_SIZE = SmbdTestConfig.MaxFragmentedSize;
            uint MAX_RECEIVE_SIZE = SmbdTestConfig.MaxReceiveSize;

            const int DATA_OFFSET_BASE_ADDRESS = 12;

            // EXPECTED_DATA_OFFSET + 8
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Scenario 1: Send SMBD Data Transfer message with EXPECTED_DATA_OFFSET + 8.");
            CommonTestMethod_ModifyField_SmbdDataTransfer(
                MAX_SEND_SIZE,
                MAX_FRAGMENT_SIZE,
                MAX_RECEIVE_SIZE,
                smbdAdapter.TestConfig.SmallFileSizeInByte,
                DATA_OFFSET_BASE_ADDRESS,
                EXPECTED_DATA_OFFSET + 8);

            // uint.MaxValue
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Scenario 2: Send SMBD Data Transfer message with size of uint.MaxValue.");
            CommonTestMethod_ModifyField_SmbdDataTransfer(
                MAX_SEND_SIZE,
                MAX_FRAGMENT_SIZE,
                MAX_RECEIVE_SIZE,
                smbdAdapter.TestConfig.SmallFileSizeInByte,
                DATA_OFFSET_BASE_ADDRESS,
                uint.MaxValue);

        }

        [TestMethod()]
        [TestCategory("SmbdDataTransfer")]
        [Description("Verify the connection will be terminated if (DataOffset + DataLength) is greater than the length of the SMBD message. "
                    + "In this test case, update only DataLength to terminate the connection")]
        // [MS-SMBD] 3.1.5.8: the receiver MUST verify DataOffset + DataLength <= received message length, otherwise terminate.
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.5.8 Receiving a Data Transfer Message")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void SmbdDataTransfer_NegativeParameter_DataLength_AgainstMessageLength()
        {
            // define data for test case
            uint MAX_SEND_SIZE = SmbdTestConfig.MaxSendSize;
            uint MAX_FRAGMENT_SIZE = SmbdTestConfig.MaxFragmentedSize;
            uint MAX_RECEIVE_SIZE = SmbdTestConfig.MaxReceiveSize;

            const int DATA_LENGTH_BASE_ADDRESS = 16;

            // orginal size + 1
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Scenario 1: Send SMBD Data Transfer message with orginal size + 1.");
            CommonTestMethod_ModifyField_SmbdDataTransfer(
                MAX_SEND_SIZE,
                MAX_FRAGMENT_SIZE,
                MAX_RECEIVE_SIZE,
                smbdAdapter.TestConfig.SmallFileSizeInByte,
                DATA_LENGTH_BASE_ADDRESS,
                smbdAdapter.TestConfig.SmallFileSizeInByte + 1);

            // MaxSendSize
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Scenario 2: Send SMBD Data Transfer message with MaxSendSize.");
            CommonTestMethod_ModifyField_SmbdDataTransfer(
                MAX_SEND_SIZE,
                MAX_FRAGMENT_SIZE,
                MAX_RECEIVE_SIZE,
                smbdAdapter.TestConfig.SmallFileSizeInByte,
                DATA_LENGTH_BASE_ADDRESS,
                1,
                true);

            // uint.MaxValue
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Scenario 3: Send SMBD Data Transfer message with size of uint.MaxValue: " + uint.MaxValue);
            CommonTestMethod_ModifyField_SmbdDataTransfer(
                MAX_SEND_SIZE,
                MAX_FRAGMENT_SIZE,
                MAX_RECEIVE_SIZE,
                smbdAdapter.TestConfig.SmallFileSizeInByte,
                DATA_LENGTH_BASE_ADDRESS,
                uint.MaxValue);
        }

        [TestMethod()]
        [TestCategory("SmbdDataTransfer")]
        [Description("Verify the connection will be terminated if (DataOffset + DataLength) is greater than the length of the SMBD message. "
                    + "In this test case, update only DataLength to terminate the connection.")]
        // [MS-SMBD] 3.1.5.7 / 3.1.5.9: the receiver posts receive buffers of Connection.MaxReceiveSize and the sender's
        // Connection.MaxSendSize is capped to the peer's MaxReceiveSize. 3.1.5.8 has no explicit "message <= MaxReceiveSize" check.
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.5.7 Receiving a Negotiate Response Message; [MS-SMBD] 3.1.5.8 Receiving a Data Transfer Message; [MS-SMBD] 3.1.5.9 Managing Credits Prior to Sending")]
        [TestProperty("SpecCompliance", "TODO")]
        public void SmbdDataTransfer_NegativeParameter_DataLength_AgainstMaxReceiveSize()
        {
            // TODO(spec): 3.1.5.8 does not list a message-size > MaxReceiveSize check among its terminate conditions; termination here
            // stems from RDMA receive-buffer overflow (3.1.5.9), which is provider behavior, not a normative SMBD verification. The
            // Description (copied from the DataLength test) also does not match the scenario, and the Windows <6> branch is not normative.
            // Re-describe as an RDMA-level expectation or drop the termination assertion.
            // define data for test case, get the server's capability
            uint MAX_SEND_SIZE;
            if (smbdAdapter.TestConfig.IsWindowsServer2012R2OrLater)
            {
                // Windows-specific product behavior, [MS-SMBD] Appendix A <6> (Section 3.1.5.6): Windows Server 2012 R2
                // and later fail the request with STATUS_INSUFFICIENT_RESOURCES if PreferredSendSize is greater than
                // 8136; the limit is taken from the WindowsMaxPreferredSendSize ptfconfig property.
                MAX_SEND_SIZE = smbdAdapter.TestConfig.WindowsMaxPreferredSendSize;
            }
            else
            {
                // The specification defines no upper bound for PreferredSendSize.
                MAX_SEND_SIZE = uint.MaxValue;
            }

            const uint MAX_FRAGMENT_SIZE = uint.MaxValue;
            const uint MAX_RECEIVE_SIZE = uint.MaxValue;

            byte[] smb2WriteRequest;
            byte[] fileContent;

            #region Send Data Transfer message with Server's MaxReceiveSize + 1
            Initialize_SendSmbdDataTransferTestCase(
                MAX_SEND_SIZE,
                MAX_FRAGMENT_SIZE,
                MAX_RECEIVE_SIZE,
                (uint)SmbdDataTransferMessage.DEFAULT_DATA_OFFSET - 1,
                out fileContent,
                out smb2WriteRequest,
                true);
            BaseTestSite.Log.Add(
                LogEntryKind.Debug,
                "MaxReceiveSize is {0}", smbdAdapter.ServerConnection.MaxReceiveSize);

            #region Send SMBDirect Data Transfer messages

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Send Data Transfer message with Server's MaxReceiveSize + 1");
            NtStatus status = (NtStatus)smbdAdapter.SmbdSendDataTransferMessage(
                smbdAdapter.ClientConnection.SendCreditTarget,
                1,
                SmbdDataTransfer_Flags.NONE,
                0,
                (uint)SmbdDataTransferMessage.DEFAULT_DATA_OFFSET,
                (uint)smb2WriteRequest.Length,
                smb2WriteRequest
                );
            BaseTestSite.Log.Add(
                LogEntryKind.Debug,
                "Status of send data is {0}", status);
            #endregion

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Verify server connection will be terminated.");
            smbdAdapter.WaitRdmaDisconnect();
            BaseTestSite.Assert.IsFalse(smbdAdapter.ClientConnection.Endpoint.IsConnected, "Connection should be terminated.");
            smbdAdapter.DisconnectRdma();
            #endregion

            #region Send Data Transfer message with Server's MaxReceiveSize
            Initialize_SendSmbdDataTransferTestCase(
                MAX_SEND_SIZE,
                MAX_FRAGMENT_SIZE,
                MAX_RECEIVE_SIZE,
                (uint)SmbdDataTransferMessage.DEFAULT_DATA_OFFSET,
                out fileContent,
                out smb2WriteRequest,
                true);
            BaseTestSite.Log.Add(
                LogEntryKind.Debug,
                "MaxReceiveSize is {0}", smbdAdapter.ServerConnection.MaxReceiveSize);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Send Data Transfer message with Server's MaxReceiveSize.");
            #region Send SMBDirect Data Transfer messages

            // send SMBD Data transfer 
            status = (NtStatus)smbdAdapter.SmbdSendDataTransferMessage(
                smbdAdapter.ClientConnection.SendCreditTarget,
                1,
                SmbdDataTransfer_Flags.NONE,
                0,
                (uint)SmbdDataTransferMessage.DEFAULT_DATA_OFFSET,
                (uint)smb2WriteRequest.Length,
                smb2WriteRequest
                );
            BaseTestSite.Assert.AreEqual<NtStatus>(status, NtStatus.STATUS_SUCCESS, "Status of send SMB2 negotiate request is {0}", status);

            #endregion

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Verify SMB2 Write response in SMBD Data Transfer message.");
            ValidateWriteResponse(fileContent);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Close file and disconnect from server.");
            smbdAdapter.Smb2CloseFile();
            smbdAdapter.DisconnectRdma();
            #endregion

        }

        [TestMethod()]
        [TestCategory("SmbdDataTransfer")]
        [Description("Verify the connection will be terminated if (DataOffset + DataLength) is greater than the length of the SMBD message. "
                    + "In this test case, update only DataLength to terminate the connection.")]
        // [MS-SMBD] 3.1.5.8: the receiver MUST verify DataLength + RemainingDataLength <= the maximum fragmented size
        // (spec text says "Connection.MaxFragmentSize"; the abstract data model defines MaxFragmentedRecvSize), else terminate.
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.5.8 Receiving a Data Transfer Message; [MS-SMBD] 3.1.5.4 Sending a Data Transfer Message")]
        [TestProperty("SpecCompliance", "TODO")]
        public void SmbdDataTransfer_NegativeParameter_AgainstMaxFragmentedSize()
        {
            // TODO(spec): the per-message RemainingDataLength is altered according to the implementation-specific
            // CheckDataLengthRemainingDataLength ptfconfig flag (not a spec concept), and the first segment already violates the
            // 3.1.5.8 sum check so later sends/credit-grant asserts may race with termination. The Description is copied from
            // another test, and the "MaxFragmentedSize" referenced by 3.1.5.8 is the ambiguous "Connection.MaxFragmentSize".
            // Simplify to a single message (see RemainingDataLength_AgainstMaxFragmentedSize) and fix the description.
            // define data for test case, get the server's capability
            uint MAX_SEND_SIZE;
            if (smbdAdapter.TestConfig.IsWindowsServer2012R2OrLater)
            {
                // Windows-specific product behavior, [MS-SMBD] Appendix A <6> (Section 3.1.5.6): Windows Server 2012 R2
                // and later fail the request with STATUS_INSUFFICIENT_RESOURCES if PreferredSendSize is greater than
                // 8136; the limit is taken from the WindowsMaxPreferredSendSize ptfconfig property.
                MAX_SEND_SIZE = smbdAdapter.TestConfig.WindowsMaxPreferredSendSize;
            }
            else
            {
                // The specification defines no upper bound for PreferredSendSize.
                MAX_SEND_SIZE = uint.MaxValue;
            }

            const uint MAX_FRAGMENT_SIZE = uint.MaxValue;
            const uint MAX_RECEIVE_SIZE = uint.MaxValue;
            int fileContentSize;
            NtStatus status;

            byte[] smb2WriteRequest;
            byte[] fileContent;

            Initialize_SendSmbdDataTransferTestCase(
                MAX_SEND_SIZE,
                MAX_FRAGMENT_SIZE,
                MAX_RECEIVE_SIZE,
                0,
                out fileContent,
                out smb2WriteRequest,
                true);

            BaseTestSite.Log.Add(
                LogEntryKind.Debug,
                "MaxReceiveSize is {0}", smbdAdapter.ServerConnection.MaxReceiveSize);
            BaseTestSite.Log.Add(
                LogEntryKind.Debug,
                "MaxFragmentedSize is {0}", smbdAdapter.ServerConnection.MaxFragmentedSize);

            #region Send Data Transfer message with Server's MaxFragmentedSize + 1

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Send Data Transfer message with Server's MaxFragmentedSize + 1.");
            fileContentSize = (int)(smbdAdapter.ServerConnection.MaxFragmentedSize + 1 -
                Smb2OverSmbdTestClient.WRITE_REQUEST_HEADER_SIZE);
            fileContent = Encoding.ASCII.GetBytes(Smb2Utility.CreateRandomStringInByte(fileContentSize));
            // generate SMB2 Write request
            smb2WriteRequest = smbdAdapter.Smb2GetWriteRequest(0, fileContent);

            // devide data into multiple segments
            List<SmbdDataTransferMessage> messages = SmbdClient.SplitData2Segments(
                smb2WriteRequest,
                smbdAdapter.ServerConnection.MaxReceiveSize - (uint)SmbdDataTransferMessage.DEFAULT_DATA_OFFSET);

            #region Send Data
            SmbdDataTransferMessage transferPackage;
            for (int index = 0; index < messages.Count;)
            {
                for (; index < messages.Count && smbdAdapter.ClientConnection.SendCredits > 0; ++index)
                {
                    uint RemainingDataLength = 0;
                    if (messages[index].RemainingDataLength != 0)
                    {
                        if (smbdAdapter.TestConfig.CheckDataLengthRemainingDataLength)
                        { // SUT not check
                            RemainingDataLength = messages[index].RemainingDataLength - (uint)(messages.Count - index);
                        }
                        else
                        { // SUT check
                            RemainingDataLength = messages[index].RemainingDataLength - 1;
                        }
                    }
                    status = (NtStatus)smbdAdapter.SmbdSendDataTransferMessage(
                        (ushort)(messages.Count - index),
                        1,
                        SmbdDataTransfer_Flags.NONE,
                        RemainingDataLength,
                        messages[index].DataOffset,
                        messages[index].DataLength,
                        messages[index].Buffer
                        );
                    smbdAdapter.ClientConnection.SendCredits--;
                    BaseTestSite.Assert.AreEqual<NtStatus>(
                        NtStatus.STATUS_SUCCESS,
                        status,
                        "Status of send segment with length {0}",
                        messages[index].DataLength
                        );
                }

                if (index < messages.Count)
                {
                    // receive the empty message for granting send credits
                    status = (NtStatus)smbdAdapter.SmbdReceivDataTransferMessage(
                        TimeSpan.FromSeconds(SmbdConnection.KEEP_ALIVE_INTERVAL),
                        out transferPackage
                        );
                    BaseTestSite.Assert.AreEqual<uint>(0, transferPackage.DataLength, "Empty message");

                    #region Check the empty message, which is to grant credit
                    BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of receive SMB2 negotiate response {0}", status);

                    // BaseTestSite.Assert.AreEqual<ushort>(1, transferPackage.CreditsGranted, "CreditsGranted of Response is {0}", transferPackage.CreditsGranted);
                    BaseTestSite.Assert.IsTrue(transferPackage.CreditsGranted > 0, "CreditsGranted of Response is {0}", transferPackage.CreditsRequested);
                    BaseTestSite.Assert.IsTrue(transferPackage.CreditsRequested > 0, "CreditsRequested of Response is {0}", transferPackage.CreditsRequested);
                    BaseTestSite.Assert.AreEqual<SmbdDataTransfer_Flags>(SmbdDataTransfer_Flags.NONE, transferPackage.Flags, "Flags of Response is {0}", transferPackage.Flags);
                    BaseTestSite.Assert.AreEqual<ushort>(0, transferPackage.Reserved, "Reserved of Response is {0}", transferPackage.Reserved);
                    BaseTestSite.Assert.AreEqual<uint>(0, transferPackage.RemainingDataLength, "Reserved of Response is {0}", transferPackage.RemainingDataLength);
                    BaseTestSite.Assert.AreEqual<uint>(0, transferPackage.DataOffset, "DataOffset of Response is {0}", transferPackage.DataOffset);
                    BaseTestSite.Assert.AreEqual<uint>(0, transferPackage.DataLength, "DataLength of Response is {0}", transferPackage.DataLength);
                    BaseTestSite.Assert.AreEqual<uint>(0, (uint)transferPackage.Padding.Length, "Padding length is {0}", transferPackage.Padding.Length);
                    #endregion

                    // raise receive request for write response
                    status = smbdAdapter.SmbdPostReceive();
                }
            }
            #endregion

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Check server connection will be terminated.");
            smbdAdapter.WaitRdmaDisconnect();
            BaseTestSite.Assert.IsFalse(smbdAdapter.ClientConnection.Endpoint.IsConnected, "Connection should be terminated.");

            #endregion

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Disconnect from server.");
            smbdAdapter.DisconnectRdma();


            Initialize_SendSmbdDataTransferTestCase(
                MAX_SEND_SIZE,
                MAX_FRAGMENT_SIZE,
                MAX_RECEIVE_SIZE,
                0,
                out fileContent,
                out smb2WriteRequest,
                true);

            BaseTestSite.Log.Add(
                LogEntryKind.Debug,
                "MaxReceiveSize is {0}", smbdAdapter.ServerConnection.MaxReceiveSize);
            BaseTestSite.Log.Add(
                LogEntryKind.Debug,
                "MaxFragmentedSize is {0}", smbdAdapter.ServerConnection.MaxFragmentedSize);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Send Data Transfer message with Server's MaxFragmentedSize.");
            #region Send Data Transfer message with Server's MaxFragmentedSize

            // devide data into multiple segments
            messages = SmbdClient.SplitData2Segments(
                smb2WriteRequest,
                smbdAdapter.ServerConnection.MaxReceiveSize - (uint)SmbdDataTransferMessage.DEFAULT_DATA_OFFSET);

            #region Send Data
            for (int index = 0; index < messages.Count;)
            {
                for (; index < messages.Count && smbdAdapter.ClientConnection.SendCredits > 0; ++index)
                {
                    status = (NtStatus)smbdAdapter.SmbdSendDataTransferMessage(
                        (ushort)(messages.Count - index),
                        1,
                        SmbdDataTransfer_Flags.NONE,
                        messages[index].RemainingDataLength,
                        messages[index].DataOffset,
                        messages[index].DataLength,
                        messages[index].Buffer
                        );
                    smbdAdapter.ClientConnection.SendCredits--;
                    BaseTestSite.Assert.AreEqual<NtStatus>(
                        NtStatus.STATUS_SUCCESS,
                        status,
                        "Status of send segment with length {0}",
                        messages[index].DataLength
                        );
                }

                if (index < messages.Count)
                {
                    // receive the empty message for granting send credits
                    status = (NtStatus)smbdAdapter.SmbdReceivDataTransferMessage(
                        TimeSpan.FromSeconds(SmbdConnection.KEEP_ALIVE_INTERVAL),
                        out transferPackage
                        );
                    BaseTestSite.Assert.AreEqual<uint>(0, transferPackage.DataLength, "Empty message");

                    #region Check the empty message, which is to grant credit
                    BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of receive SMB2 negotiate response {0}", status);

                    // BaseTestSite.Assert.AreEqual<ushort>(1, transferPackage.CreditsGranted, "CreditsGranted of Response is {0}", transferPackage.CreditsGranted);
                    BaseTestSite.Assert.IsTrue(transferPackage.CreditsGranted > 0, "CreditsGranted of Response is {0}", transferPackage.CreditsRequested);
                    BaseTestSite.Assert.IsTrue(transferPackage.CreditsRequested > 0, "CreditsRequested of Response is {0}", transferPackage.CreditsRequested);
                    BaseTestSite.Assert.AreEqual<SmbdDataTransfer_Flags>(SmbdDataTransfer_Flags.NONE, transferPackage.Flags, "Flags of Response is {0}", transferPackage.Flags);
                    BaseTestSite.Assert.AreEqual<ushort>(0, transferPackage.Reserved, "Reserved of Response is {0}", transferPackage.Reserved);
                    BaseTestSite.Assert.AreEqual<uint>(0, transferPackage.RemainingDataLength, "Reserved of Response is {0}", transferPackage.RemainingDataLength);
                    BaseTestSite.Assert.AreEqual<uint>(0, transferPackage.DataOffset, "DataOffset of Response is {0}", transferPackage.DataOffset);
                    BaseTestSite.Assert.AreEqual<uint>(0, transferPackage.DataLength, "DataLength of Response is {0}", transferPackage.DataLength);
                    BaseTestSite.Assert.AreEqual<uint>(0, (uint)transferPackage.Padding.Length, "Padding length is {0}", transferPackage.Padding.Length);
                    #endregion

                    // raise receive request for write response
                    status = smbdAdapter.SmbdPostReceive();
                }
            }
            #endregion

            #endregion

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Verify SMB2 Write response in SMBD Data Transfer message.");
            ValidateWriteResponse(fileContent);
        }

        [TestMethod()]
        [TestCategory("SmbdDataTransfer")]
        [Description("Verify the connection will be terminated if the summery, the current DataRemainingLength and DataLength field exceed Connection.MaxFragmentedSize. "
                    + "In this test case, update only DataRemainingLength to terminate the connection.")]
        // [MS-SMBD] 3.1.5.8: the receiver MUST verify DataLength + RemainingDataLength <= Connection max fragmented size
        // (spec wording: "Connection.MaxFragmentSize"); otherwise it MUST terminate the connection.
        // The test is skipped (Inconclusive) on Windows Server 2025 - a platform-specific exclusion, not a spec statement.
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.5.8 Receiving a Data Transfer Message")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void SmbdDataTransfer_NegativeParameter_RemainingDataLength_AgainstMaxFragmentedSize()
        {
            if (smbdAdapter.TestConfig.Platform >= Platform.WindowsServer2025)
            {
                BaseTestSite.Assert.Inconclusive("This test case currently does not support Windows Server 2025.");
            }
            
            // MaxFragmentedSize + 1
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Scenario 1: Send SMBD Data Transfer message with MaxFragmentedSize + 1.");
            CommonTestMethod_RemainingDataLength_AgainstMaxFragmentedSize(
                1,
                true);

            // uint.MaxValue
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Scenario 1: Send SMBD Data Transfer message with MaxFragmentedSize set to uint.MaxValue.");
            CommonTestMethod_RemainingDataLength_AgainstMaxFragmentedSize(uint.MaxValue);
        }

        [TestMethod()]
        [TestCategory("SmbdDataTransfer")]
        [Description("Verify the connection will be terminated if RemainingDataLength is zero and Connection.FragmentReassemblyRemaining is NOT equal to the received DataLength.")]
        // [MS-SMBD] 3.1.5.8: when RemainingDataLength is 0 and Connection.FragmentReassemblyRemaining (after being reduced by the
        // received DataLength) is still greater than zero, the receiver MUST terminate the connection.
        // Requires at least 3 segments for the "last 2nd message" scenario (depends on ModerateFileSizeInByte / MaxSendSize).
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.5.8 Receiving a Data Transfer Message")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void SmbdDataTransfer_NegativeParameter_RemainingDataLength_Zero()
        {
            // define data for test case
            uint MAX_SEND_SIZE = SmbdTestConfig.MaxSendSize;
            uint MAX_FRAGMENT_SIZE = SmbdTestConfig.MaxFragmentedSize;
            uint MAX_RECEIVE_SIZE = SmbdTestConfig.MaxReceiveSize;

            byte[] smb2WriteRequest;
            byte[] fileContent;
            List<SmbdDataTransferMessage> messages;

            #region invalid RemainingDataLength in second message
            Initialize_SendSmbdDataTransferTestCase(
                MAX_SEND_SIZE,
                MAX_FRAGMENT_SIZE,
                MAX_RECEIVE_SIZE,
                smbdAdapter.TestConfig.ModerateFileSizeInByte,
                out fileContent,
                out smb2WriteRequest);

            // devide data into multiple segments
            messages = SmbdClient.SplitData2Segments(smb2WriteRequest, smbdAdapter.ClientConnection.MaxSendSize
                - (uint)SmbdDataTransferMessage.DEFAULT_DATA_OFFSET);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Send 2 SMBD Data Transfer messages, and set invalid RemainingDataLength in the second message.");
            SendWithInvalidRemainingDataLength(messages, 2, 0);
            #endregion

            #region invalid RemainingDataLength in last 2nd message
            Initialize_SendSmbdDataTransferTestCase(
                MAX_SEND_SIZE,
                MAX_FRAGMENT_SIZE,
                MAX_RECEIVE_SIZE,
                smbdAdapter.TestConfig.ModerateFileSizeInByte,
                out fileContent,
                out smb2WriteRequest);

            // devide data into multiple segments
            messages = SmbdClient.SplitData2Segments(smb2WriteRequest, smbdAdapter.ClientConnection.MaxSendSize
                - (uint)SmbdDataTransferMessage.DEFAULT_DATA_OFFSET);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Send several SMBD Data Transfer messages, and set invalid RemainingDataLength in last 2nd message.");
            SendWithInvalidRemainingDataLength(messages, messages.Count - 1, 0);
            #endregion

        }

        [TestMethod()]
        [TestCategory("SmbdDataTransfer")]
        [Description("Verify the connection will be terminated if RemainingDataLength + DataLength is greater than Connection.FragmentReassemblyRemaining.")]
        // [MS-SMBD] 3.1.5.8: the only normative reassembly checks are DataLength + RemainingDataLength <= max fragmented size
        // and FragmentReassemblyRemaining == 0 when RemainingDataLength is 0.
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.5.8 Receiving a Data Transfer Message")]
        [TestProperty("SpecCompliance", "TODO")]
        public void SmbdDataTransfer_NegativeParameter_RemainingDataLength_AgainstFragmentReassemblyRemaining()
        {
            // TODO(spec): 3.1.5.8 does not require terminating when RemainingDataLength + DataLength exceeds
            // FragmentReassemblyRemaining (for a non-first segment the field is only reduced by DataLength, RemainingDataLength is not
            // compared). The test is gated by the implementation-specific CheckDataLengthRemainingDataLength flag; it asserts behavior the
            // spec does not define. Remove, or mark as implementation-specific.
            // define data for test case
            uint MAX_SEND_SIZE = SmbdTestConfig.MaxSendSize;
            uint MAX_FRAGMENT_SIZE = SmbdTestConfig.MaxFragmentedSize;
            uint MAX_RECEIVE_SIZE = SmbdTestConfig.MaxReceiveSize;

            byte[] smb2WriteRequest;
            byte[] fileContent;
            List<SmbdDataTransferMessage> messages;

            // PTF config, implementation may not support such function
            // WHAT: when the feature flag is off, mark the test Inconclusive instead of returning (which reported a pass).
            // WHY: a silent return counted as a pass although nothing was verified (vacuous pass).
            // SPEC: [MS-SMBD] 3.1.5.8 does not require this check (it only reduces FragmentReassemblyRemaining by DataLength), so it
            //       is opt-in via the implementation-specific CheckDataLengthRemainingDataLength ptfconfig flag.
            if (smbdAdapter.TestConfig.CheckDataLengthRemainingDataLength == false)
            {
                BaseTestSite.Assert.Inconclusive(
                    "CheckDataLengthRemainingDataLength is off: this implementation-specific check is not run.");
            }

            #region send RemainingDataLength in 2nd message
            Initialize_SendSmbdDataTransferTestCase(
                MAX_SEND_SIZE,
                MAX_FRAGMENT_SIZE,
                MAX_RECEIVE_SIZE,
                smbdAdapter.TestConfig.ModerateFileSizeInByte,
                out fileContent,
                out smb2WriteRequest);

            // devide data into multiple segments
            messages = SmbdClient.SplitData2Segments(smb2WriteRequest, smbdAdapter.ClientConnection.MaxSendSize
                - (uint)SmbdDataTransferMessage.DEFAULT_DATA_OFFSET);
            SendWithInvalidRemainingDataLength(messages, 2, 1, true);
            #endregion


        }

        [TestMethod()]
        [TestCategory("SmbdDataTransfer")]
        [Description("Verify server will response when receive SMBD Data Transfer message with flag SMB_DIRECT_RESPONSE_REQUESTED.")]
        // [MS-SMBD] 3.1.5.8: on receiving SMB_DIRECT_RESPONSE_REQUESTED the receiver MUST set KeepaliveRequested = PENDING and promptly
        // send a Data Transfer message (3.1.5.1).
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.5.8 Receiving a Data Transfer Message; [MS-SMBD] 3.1.5.1 Sending Upper Layer Messages")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void SmbdDataTransfer_IdleConnection_Client()
        {
            // define data for test case
            uint MAX_SEND_SIZE = SmbdTestConfig.MaxSendSize;
            uint MAX_FRAGMENT_SIZE = SmbdTestConfig.MaxFragmentedSize;
            uint MAX_RECEIVE_SIZE = SmbdTestConfig.MaxReceiveSize;

            byte[] smb2WriteRequest;
            byte[] fileContent;

            // prepare for idle connection, so that SMB2 will not terminate the connection
            Initialize_SendSmbdDataTransferTestCase(
                MAX_SEND_SIZE,
                MAX_FRAGMENT_SIZE,
                MAX_RECEIVE_SIZE,
                smbdAdapter.TestConfig.SmallFileSizeInByte,
                out fileContent,
                out smb2WriteRequest);
            smbdAdapter.Smb2CloseFile();

            BaseTestSite.Log.Add(LogEntryKind.TestStep, string.Format("Sleep {0} seconds before KeepAliveInterval timeout of {1} seconds.", smbdAdapter.TestConfig.KeepAliveInterval - 1, smbdAdapter.TestConfig.KeepAliveInterval));
            Thread.Sleep(TimeSpan.FromSeconds(smbdAdapter.TestConfig.KeepAliveInterval - 1));

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Send an empty SMBDirect Data Transfer message with flag SMB_DIRECT_RESPONSE_REQUESTED.");
            NtStatus status = smbdAdapter.SmbdSendDataTransferMessage(
                smbdAdapter.ClientConnection.SendCreditTarget,
                0,
                SmbdDataTransfer_Flags.SMB_DIRECT_RESPONSE_REQUESTED,
                0,
                0,
                0,
                new byte[0]);
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of Send SMBDirect Data Transfer message is {0}", status);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Verify server still response.");
            smbdAdapter.SmbdPostReceive();
            try
            {
                SmbdDataTransferMessage transferMessage;
                smbdAdapter.SmbdReceivDataTransferMessage(
                    TimeSpan.FromSeconds(SmbdConnection.IDLE_CONNECTION_TIMEOUT),
                    out transferMessage);

                // WHAT: CreditsGranted is no longer asserted; Flags may be NONE or SMB_DIRECT_RESPONSE_REQUESTED.
                // WHY: the old asserts (CreditsGranted > 0, Flags == NONE) encoded Windows behaviour and failed on ksmbd.
                // SPEC: [MS-SMBD] 3.1.5.1 - CreditsGranted is the count of new credits from 3.1.5.9 and may be 0; Flags is
                //       SMB_DIRECT_RESPONSE_REQUESTED only if KeepaliveRequested is PENDING, otherwise 0x0000.
                BaseTestSite.Assert.IsTrue(
                    transferMessage.Flags == SmbdDataTransfer_Flags.NONE
                    || transferMessage.Flags == SmbdDataTransfer_Flags.SMB_DIRECT_RESPONSE_REQUESTED,
                    "Flags in received SMBDirect Data Transfer message is {0}", transferMessage.Flags);
                BaseTestSite.Assert.AreEqual<ushort>(
                    0,
                    transferMessage.Reserved,
                    "Reserved in received SMBDirect Data Transfer message is {0}", transferMessage.Reserved);
                BaseTestSite.Assert.AreEqual<uint>(
                    0,
                    transferMessage.RemainingDataLength,
                    "RemainingDataLength in received SMBDirect Data Transfer message is {0}", transferMessage.RemainingDataLength);
                BaseTestSite.Assert.AreEqual<uint>(
                    0,
                    transferMessage.DataOffset,
                    "DataOffset in received SMBDirect Data Transfer message is {0}", transferMessage.DataOffset);
                BaseTestSite.Assert.AreEqual<uint>(
                    0,
                    transferMessage.DataLength,
                    "DataLength in received SMBDirect Data Transfer message is {0}", transferMessage.DataLength);
                BaseTestSite.Assert.AreEqual<int>(
                    0,
                    transferMessage.Padding.Length,
                    "Length of padding in received SMBDirect Data Transfer message is {0}", transferMessage.Padding.Length);
                BaseTestSite.Assert.AreEqual<int>(
                    transferMessage.Buffer.Length,
                    transferMessage.Reserved,
                    "Length of buffer in received SMBDirect Data Transfer message is {0}", transferMessage.Buffer.Length);
            }
            catch (TimeoutException)
            {
                BaseTestSite.Assert.Fail("Server do not response within {0} seconds", SmbdConnection.IDLE_CONNECTION_TIMEOUT);
            }


        }

        [TestMethod()]
        [TestCategory("SmbdDataTransfer")]
        [Description("Verify server will send SMBD Data Transfer message with SMB_DIRECT_RESPONSE_REQUESTED flag when Idle Connection Timer is expired.")]
        // [MS-SMBD] 3.1.6.2: when the Idle Connection Timer expires and KeepaliveRequested is NONE, the peer SHOULD set it to PENDING and
        // SHOULD send an (empty) Data Transfer message with SMB_DIRECT_RESPONSE_REQUESTED (3.1.5.1: Flags MUST then carry the flag).
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.6.2 Idle Connection Timer; [MS-SMBD] 3.1.5.1 Sending Upper Layer Messages; [MS-SMBD] 3.1.5.8 Receiving a Data Transfer Message")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void SmbdDataTransfer_IdleConnection_Server()
        {
            // define data for test case
            uint MAX_SEND_SIZE = SmbdTestConfig.MaxSendSize;
            uint MAX_FRAGMENT_SIZE = SmbdTestConfig.MaxFragmentedSize;
            uint MAX_RECEIVE_SIZE = SmbdTestConfig.MaxReceiveSize;

            byte[] smb2WriteRequest;
            byte[] fileContent;

            // prepare for idle connection, so that SMB2 will not terminate the connection
            Initialize_SendSmbdDataTransferTestCase(
                MAX_SEND_SIZE,
                MAX_FRAGMENT_SIZE,
                MAX_RECEIVE_SIZE,
                smbdAdapter.TestConfig.SmallFileSizeInByte,
                out fileContent,
                out smb2WriteRequest);
            smbdAdapter.Smb2CloseFile();

            SmbdDataTransferMessage dataTransfer;

            BaseTestSite.Log.Add(LogEntryKind.TestStep, string.Format("Let Idle Timer expired on server by doing nothing within {0} seconds.", smbdAdapter.TestConfig.KeepAliveInterval + 5));
            smbdAdapter.SmbdReceivDataTransferMessage(
                TimeSpan.FromSeconds(smbdAdapter.TestConfig.KeepAliveInterval + 5),
                out dataTransfer);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Check server sends SMBD Data Transfer message with SMB_DIRECT_RESPONSE_REQUESTED flag.");
            #region Check received Data
            BaseTestSite.Assert.IsTrue(
                dataTransfer.CreditsRequested > 0,
                "CreditRequested is {0}", dataTransfer.CreditsRequested);
            BaseTestSite.Assert.AreEqual<uint>(
                0,
                dataTransfer.DataOffset,
                "DataOffset is {0}", dataTransfer.DataOffset);
            BaseTestSite.Assert.AreEqual<uint>(
                0,
                dataTransfer.DataLength,
                "DataLength is {0}", dataTransfer.DataLength);
            BaseTestSite.Assert.AreEqual<uint>(
                0,
                dataTransfer.RemainingDataLength,
                "RemainingDataLength is {0}", dataTransfer.RemainingDataLength);
            BaseTestSite.Assert.AreEqual<SmbdDataTransfer_Flags>(
                SmbdDataTransfer_Flags.SMB_DIRECT_RESPONSE_REQUESTED,
                dataTransfer.Flags,
                "Flags is {0}", dataTransfer.Flags);
            #endregion

            // WHAT: on non-Windows SUTs stop after the first keepalive check and skip the 5 s response / repeat-keepalive timing checks.
            // WHY: those timings are Windows defaults, not protocol requirements; asserting them tested the product, not the spec.
            // SPEC: [MS-SMBD] 3.1.6.2 Idle Connection Timer (SHOULD, timer value implementation-specific) and Appendix B <4>
            //       (Windows sets the timer to 5 s; KeepaliveInterval default 120 s in <8>).
            if (!smbdAdapter.TestConfig.IsWindowsPlatform)
            {
                BaseTestSite.Log.Add(LogEntryKind.Comment, "Non-Windows SUT: skipping Windows-specific idle timer timing checks.");
                smbdAdapter.DisconnectRdma();
                return;
            }

            Thread.Sleep(TimeSpan.FromSeconds(SmbdConnection.IDLE_CONNECTION_TIMEOUT - 1));

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Send response message to server with flag SMB_DIRECT_RESPONSE_REQUESTED");
            // [MS-SMBD] Section 3.1.5.1: CreditsRequested is set to Connection.SendCreditTarget (SendCreditTarget ptfconfig property).
            smbdAdapter.SmbdSendDataTransferMessage(
                (ushort)SmbdTestConfig.SendCreditTarget,
                1,
                SmbdDataTransfer_Flags.SMB_DIRECT_RESPONSE_REQUESTED,
                0,
                0,
                0,
                new byte[0]);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Check server will response in 5 seconds");
            smbdAdapter.SmbdReceivDataTransferMessage(
                TimeSpan.FromSeconds(SmbdConnection.IDLE_CONNECTION_TIMEOUT + 1), out dataTransfer);
            #region Check receive Data
            BaseTestSite.Assert.IsTrue(
                dataTransfer.CreditsRequested > 0,
                "CreditRequested is {0}", dataTransfer.CreditsRequested);
            BaseTestSite.Assert.AreEqual<uint>(
                0,
                dataTransfer.DataOffset,
                "DataOffset is {0}", dataTransfer.DataOffset);
            BaseTestSite.Assert.AreEqual<uint>(
                0,
                dataTransfer.DataLength,
                "DataLength is {0}", dataTransfer.DataLength);
            BaseTestSite.Assert.AreEqual<uint>(
                0,
                dataTransfer.RemainingDataLength,
                "RemainingDataLength is {0}", dataTransfer.RemainingDataLength);
            BaseTestSite.Assert.AreEqual<SmbdDataTransfer_Flags>(
                SmbdDataTransfer_Flags.NONE,
                dataTransfer.Flags,
                "Flags is {0}", dataTransfer.Flags);
            #endregion

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Let Idle Timer expired on server again and recieve message with flag SMB_DIRECT_RESPONSE_REQUESTED");
            smbdAdapter.SmbdReceivDataTransferMessage(
                TimeSpan.FromSeconds(smbdAdapter.TestConfig.KeepAliveInterval + 5),
                out dataTransfer);

            #region Check receive Data
            BaseTestSite.Assert.IsTrue(
                dataTransfer.CreditsRequested > 0,
                "CreditRequested is {0}", dataTransfer.CreditsRequested);
            BaseTestSite.Assert.AreEqual<uint>(
                0,
                dataTransfer.DataOffset,
                "DataOffset is {0}", dataTransfer.DataOffset);
            BaseTestSite.Assert.AreEqual<uint>(
                0,
                dataTransfer.DataLength,
                "DataLength is {0}", dataTransfer.DataLength);
            BaseTestSite.Assert.AreEqual<uint>(
                0,
                dataTransfer.RemainingDataLength,
                "RemainingDataLength is {0}", dataTransfer.RemainingDataLength);
            BaseTestSite.Assert.AreEqual<SmbdDataTransfer_Flags>(
                SmbdDataTransfer_Flags.SMB_DIRECT_RESPONSE_REQUESTED,
                dataTransfer.Flags,
                "Flags is {0}", dataTransfer.Flags);
            #endregion

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Disconnect from server.");
            smbdAdapter.DisconnectRdma();
        }

        [TestMethod()]
        [TestCategory("SmbdDataTransfer")]
        [Description("Verify server will terminate connection when no response for SMBD Data Transfer message with SMB_DIRECT_RESPONSE_REQUESTED flag.")]
        // [MS-SMBD] 3.1.6.2: when the Idle Connection Timer expires and KeepaliveRequested is not NONE (keepalive sent, no reply), the
        // local peer SHOULD terminate the connection.
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.6.2 Idle Connection Timer; [MS-SMBD] 3.1.5.1 Sending Upper Layer Messages")]
        [TestProperty("SpecCompliance", "TODO")]
        public void SmbdDataTransfer_IdleConnection_Server_Timeout()
        {
            // TODO(spec): termination on keepalive timeout is only a SHOULD, and the wait time (IDLE_CONNECTION_TIMEOUT, matching the
            // Windows <4> 5 s value) is implementation-specific; the test asserts it as a hard requirement. The test is also skipped on
            // Windows Server 2025 (platform-specific, not spec-based).
            if (smbdAdapter.TestConfig.Platform >= Platform.WindowsServer2025)
            {
                BaseTestSite.Assert.Inconclusive("This test case currently does not support Windows Server 2025.");
            }
            
            // define data for test case
            uint MAX_SEND_SIZE = SmbdTestConfig.MaxSendSize;
            uint MAX_FRAGMENT_SIZE = SmbdTestConfig.MaxFragmentedSize;
            uint MAX_RECEIVE_SIZE = SmbdTestConfig.MaxReceiveSize;

            byte[] smb2WriteRequest;
            byte[] fileContent;

            // prepare for idle connection, so that SMB2 will not terminate the connection
            Initialize_SendSmbdDataTransferTestCase(
                MAX_SEND_SIZE,
                MAX_FRAGMENT_SIZE,
                MAX_RECEIVE_SIZE,
                smbdAdapter.TestConfig.SmallFileSizeInByte,
                out fileContent,
                out smb2WriteRequest);
            smbdAdapter.Smb2CloseFile();

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Let Idle Timer expired on server and recieve message with flag SMB_DIRECT_RESPONSE_REQUESTED");
            SmbdDataTransferMessage dataTransfer;
            smbdAdapter.SmbdReceivDataTransferMessage(
                TimeSpan.FromSeconds(smbdAdapter.TestConfig.KeepAliveInterval + 5),
                out dataTransfer);

            #region Check receive Data
            BaseTestSite.Assert.IsTrue(
                dataTransfer.CreditsRequested > 0,
                "CreditRequested is {0}", dataTransfer.CreditsRequested);
            BaseTestSite.Assert.AreEqual<uint>(
                0,
                dataTransfer.DataOffset,
                "DataOffset is {0}", dataTransfer.DataOffset);
            BaseTestSite.Assert.AreEqual<uint>(
                0,
                dataTransfer.DataLength,
                "DataLength is {0}", dataTransfer.DataLength);
            BaseTestSite.Assert.AreEqual<uint>(
                0,
                dataTransfer.RemainingDataLength,
                "RemainingDataLength is {0}", dataTransfer.RemainingDataLength);
            BaseTestSite.Assert.AreEqual<SmbdDataTransfer_Flags>(
                SmbdDataTransfer_Flags.SMB_DIRECT_RESPONSE_REQUESTED,
                dataTransfer.Flags,
                "Flags is {0}", dataTransfer.Flags);
            #endregion

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Do not send message to server, let server terminate the connection.");
            Thread.Sleep(TimeSpan.FromSeconds(SmbdConnection.IDLE_CONNECTION_TIMEOUT));

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Check server connection will be terminated.");
            smbdAdapter.WaitRdmaDisconnect();
            BaseTestSite.Assert.IsFalse(smbdAdapter.ClientConnection.Endpoint.IsConnected, "Connection should be terminated.");
        }
        #endregion

        #region Common methods
        /// <summary>
        /// Initialize send SMBDirect data transfer test case. 
        /// In this method, it will connect to server, SMBDirect negotiate with server and SMB2 intiailize.
        /// And generate SMB2 WRITE request according the size
        /// </summary>
        /// <param name="maxSendSize">The maximum single-message size which can be sent by the local peer for this connection.</param>
        /// <param name="maxFragmentSize">The maximum fragmented upper-layer payload receive size supported by the local peer for this connection.</param>
        /// <param name="maxReceiveSize">The maximum single-message size which can be received from the remote peer for this connection.</param>
        /// <param name="smb2WriteRequestSize">Size of SMB2 WRITE request packet</param>
        /// <param name="fileContent">file content according the input file size</param>
        /// <param name="smb2WriteRequestPacket">SMB2 WRITE request packet</param>
        /// <param name="isUseMaxSendSize">
        /// If this flag is true, smb2WriteRequestSize will be data offset
        /// file content size = negotiated MaxSendSize - smb2WriteRequestSize (DataOffset)
        /// </param>
        public void Initialize_SendSmbdDataTransferTestCase(
            uint maxSendSize,
            uint maxFragmentSize,
            uint maxReceiveSize,
            uint smb2WriteRequestSize,
            out byte[] fileContent,
            out byte[] smb2WriteRequestPacket,
            bool isUseMaxSendSize = false)
        {
            string fileName = CreateRandomFileName();
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Initial SMBD connection and open file " + fileName);

            // WHAT: retry the whole connect/negotiate/session setup up to 3 times, waiting between attempts.
            // WHY: multi-scenario NegativeParameter tests reconnect right after the server terminated the previous
            //      connection; the server may still be tearing down the old session/connection, so the new SMB2 session
            //      setup can transiently fail. That is test setup, not the behaviour under test. (A persistent ACCESS_DENIED
            //      here was NOT a teardown race: it was stale client crypto state, now cleared in ConnectToServerOverRDMA.)
            // SPEC: [MS-SMBD] 3.1.7.1 / 3.1.5.8 - the server terminates the connection; the spec gives no bound on how
            //       quickly the upper layer releases the old session, so the client must not assume it is instantaneous.
            NtStatus status = NtStatus.STATUS_SUCCESS;
            SmbdNegotiateResponse response;
            const int SETUP_ATTEMPTS = 3;
            for (int attempt = 1; attempt <= SETUP_ATTEMPTS; attempt++)
            {
                status = smbdAdapter.ConnectToServerOverRDMA();
                BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMBD connection is {0}", status);

                status = smbdAdapter.SmbdNegotiate(maxSendSize, maxReceiveSize, maxFragmentSize, out response);
                BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMBD negotiate is {0}", status);

                status = smbdAdapter.Smb2EstablishSessionAndOpenFile(fileName);
                if (status == NtStatus.STATUS_SUCCESS || attempt == SETUP_ATTEMPTS)
                {
                    break;
                }
                BaseTestSite.Log.Add(LogEntryKind.Debug,
                    "SMB2 setup attempt {0} failed with {1}; reconnecting after delay.", attempt, status);
                smbdAdapter.DisconnectRdma();
                Thread.Sleep(TimeSpan.FromSeconds(5));
            }
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMB2 establish session and open file is {0}", status);

            // calculate file size and generate file content
            int fileContentSize = (int)smb2WriteRequestSize -
                Smb2OverSmbdTestClient.WRITE_REQUEST_HEADER_SIZE;// calculate the file content size
            if (isUseMaxSendSize)
            {
                fileContentSize = (int)(smbdAdapter.ServerConnection.MaxReceiveSize - smb2WriteRequestSize /* if isUseMaxSendSize is true, this field is data offset. */-
                    Smb2OverSmbdTestClient.WRITE_REQUEST_HEADER_SIZE);
            }
            fileContent = Encoding.ASCII.GetBytes(Smb2Utility.CreateRandomStringInByte(fileContentSize));

            // generate SMB2 Write request
            smb2WriteRequestPacket = smbdAdapter.Smb2GetWriteRequest(0, fileContent);
        }

        /// <summary>
        /// Initialize receive SMBDirect data transfer test case
        /// And send the SMB2 READ request to peer
        /// </summary>
        /// <param name="maxSendSize">The maximum single-message size which can be sent by the local peer for this connection.</param>
        /// <param name="maxFragmentSize">The maximum fragmented upper-layer payload receive size supported by the local peer for this connection.</param>
        /// <param name="maxReceiveSize">The maximum single-message size which can be received from the remote peer for this connection.</param>
        /// <param name="smb2ReadResponseSize">The size of SMB2 Read response.</param>
        /// <param name="isUseMaxSendSize">Use client's MaxReceivedSize as smb2ReadResponseSize</param>
        /// <param name="isUseMaxFragmentedSize">Use client's MaxFragmentedSize as smb2ReadResponseSize</param>
        public void Initialize_ReceiveSmbdDataTransferTestCase(
            uint maxSendSize,
            uint maxFragmentSize,
            uint maxReceiveSize,
            uint smb2ReadResponseSize,
            bool isUseMaxSendSize = false,
            bool isUseMaxFragmentedSize = false)
        {
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Connect to server over RDMA");
            NtStatus status = smbdAdapter.ConnectToServerOverRDMA();
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMBD connection is {0}", status);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "SMBD Negotiate");
            SmbdNegotiateResponse response;
            status = smbdAdapter.SmbdNegotiate(maxSendSize, maxReceiveSize, maxFragmentSize, out response);
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMBD negotiate is {0}", status);

            // SMB2 Negotiate, Session Setup, Tree Connect and Create
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Establish SMB2 connection and open file " + smbdAdapter.TestConfig.TestFileName_LargeFile);
            status = smbdAdapter.Smb2EstablishSessionAndOpenFile(smbdAdapter.TestConfig.TestFileName_LargeFile);
            // WHAT: report a missing pre-provisioned file as Inconclusive instead of a protocol failure.
            // WHY: nothing in the suite creates the large file on non-Windows SUTs; a missing file is an environment
            //      problem, not a violation of the behaviour under test.
            // SPEC: [MS-SMB2] 3.3.5.9 Receiving an SMB2 CREATE Request - a nonexistent file with FILE_OPEN
            //       returns STATUS_OBJECT_NAME_NOT_FOUND, which is correct server behaviour.
            if (status == NtStatus.STATUS_OBJECT_NAME_NOT_FOUND)
            {
                BaseTestSite.Assert.Inconclusive(
                    "Pre-provisioned file '{0}' does not exist on the SUT share; create it (see User Guide) and re-run.",
                    smbdAdapter.TestConfig.TestFileName_LargeFile);
            }
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMB2 establish session and open file is {0}", status);

            // calculate file size and generate file content
            int receivedFileSize = (int)smb2ReadResponseSize -
                Smb2OverSmbdTestClient.READ_RESPONSE_HEADER_SIZE;// calculate the file content size
            if (isUseMaxSendSize)
            {
                receivedFileSize = (int)(smbdAdapter.ClientConnection.MaxReceiveSize -
                    Smb2OverSmbdTestClient.READ_RESPONSE_HEADER_SIZE);
            }
            if (isUseMaxFragmentedSize)
            {
                receivedFileSize = (int)(smbdAdapter.ClientConnection.MaxFragmentedSize -
                    Smb2OverSmbdTestClient.READ_RESPONSE_HEADER_SIZE);
            }

            byte[] readRequestPacket = smbdAdapter.Smb2GetReadRequest((uint)receivedFileSize);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Send SMB2 Read Request.");
            status = (NtStatus)smbdAdapter.SmbdSendDataTransferMessage(
                smbdAdapter.ClientConnection.SendCreditTarget,
                1,
                SmbdDataTransfer_Flags.NONE,
                0,
                (uint)SmbdDataTransferMessage.DEFAULT_DATA_OFFSET,
                (uint)readRequestPacket.Length,
                readRequestPacket
                );
            BaseTestSite.Assert.AreEqual<NtStatus>(status, NtStatus.STATUS_SUCCESS, "Status of send SMB2 negotiate request is {0}", status);

        }

        /// <summary>
        /// Receive and validate SMB2 Write Response
        /// </summary>
        /// <param name="fileContent"></param>
        public void ValidateWriteResponse(byte[] fileContent)
        {
            const uint WRITE_RESPONSE_SIZE = 80;

            // receive write response
            SmbdDataTransferMessage transferPackage;
            NtStatus status;

            do
            {
                // Discard data transfer package that only grants credits to client without data
                status = (NtStatus)smbdAdapter.SmbdReceivDataTransferMessage(
                    smbdAdapter.TestConfig.Smb2ConnectionTimeout,
                    out transferPackage);

                BaseTestSite.Assert.AreEqual(NtStatus.STATUS_SUCCESS, status, "Data transfer message should be received with status STATUS_SUCCESS.");

            } while (transferPackage.DataLength == 0);

            #region Check SMBDirect Data Transfer message
            BaseTestSite.Assert.IsTrue(
                transferPackage.CreditsRequested > 0,
                "CreditRequest Should be greater than 0");
            BaseTestSite.Assert.AreEqual<uint>(
                0,
                transferPackage.RemainingDataLength,
                "RemainingDataLength is {0}", transferPackage.RemainingDataLength);
            BaseTestSite.Assert.AreEqual<uint>(
                0,
                transferPackage.DataOffset % 8,
                "DataOffset is {0}", transferPackage.DataOffset);
            BaseTestSite.Assert.AreEqual<uint>(
                WRITE_RESPONSE_SIZE,
                transferPackage.DataLength,
                "DataLength is {0}", transferPackage.DataLength);
            #endregion

            #region Check write resposne
            object endpoint = new object();
            int consumedLength;
            int expectedLength;
            StackPacket[] stackPackets = smbdAdapter.Decoder.Smb2DecodePacketCallback(
                endpoint,
                transferPackage.Buffer,
                out consumedLength,
                out expectedLength);
            Smb2WriteResponsePacket package = (Smb2WriteResponsePacket)stackPackets[0];

            WRITE_Response writeResponse = package.PayLoad;
            BaseTestSite.Assert.AreEqual<NtStatus>(
                NtStatus.STATUS_SUCCESS,
                (NtStatus)package.Header.Status,
                "Status of SMB2 write File is {0}", (NtStatus)package.Header.Status);
            BaseTestSite.Assert.AreEqual<uint>((uint)fileContent.Length, writeResponse.Count, "Size of written file is {0}", writeResponse.Count);

            #endregion
        }

        /// <summary>
        /// Receive and validate SMB2 Read Response
        /// </summary>
        /// <param name="readResponseSize">Size of SMB2 read response</param>
        public void ValidateReadResponse(int readResponseSize)
        {
            // receive read response, maybe in several SMBDirect data transfer
            SmbdDataTransferMessage transferPackage;
            byte[] readResponsePacket = new byte[readResponseSize];
            int offset = 0;

            NtStatus status;
            while (offset < readResponseSize)
            {
                while (smbdAdapter.ClientConnection.ReceiveCredits > 0)
                {
                    status = (NtStatus)smbdAdapter.SmbdReceivDataTransferMessage(
                        smbdAdapter.TestConfig.Smb2ConnectionTimeout,
                        out transferPackage
                        );

                    // WHAT: skip empty Data Transfer messages (DataLength 0 and RemainingDataLength 0) instead of validating them as read data.
                    // WHY: a peer may legally send an empty message purely to grant credits; the old code treated it as a malformed read
                    //      fragment and failed on ksmbd (Windows never sends them here, so the test only passed by accident).
                    // SPEC: [MS-SMBD] 3.1.5.4 (empty message: DataOffset/DataLength/RemainingDataLength = 0) and 3.1.5.8 (receiver credit processing).
                    if (transferPackage.DataLength == 0 && transferPackage.RemainingDataLength == 0)
                    {
                        continue;
                    }

                    #region Assert
                        BaseTestSite.Assert.AreEqual<uint>(
                            (uint)(readResponseSize - offset),
                            transferPackage.DataLength + transferPackage.RemainingDataLength,
                            "Received SMBDirect Data Transfer Message: DataLength {0}, RemainingDataLength {1}", transferPackage.DataLength, transferPackage.RemainingDataLength);
                        BaseTestSite.Assert.AreEqual<uint>(
                            0,
                            transferPackage.DataOffset % 8,
                            "Received SMBDirect Data Transfer Message: DataOffset {0}, which should be 8-byte aligned", transferPackage.DataOffset);
                        #endregion

                        Array.Copy(transferPackage.Buffer, 0, readResponsePacket, offset, transferPackage.DataLength);
                        offset += (int)transferPackage.DataLength;

                        if (transferPackage.RemainingDataLength == 0)
                        {
                            break;
                        }
                }

                #region send empty message to grant credit
                ushort postReceive = 0;
                status = NtStatus.STATUS_SUCCESS;
                while (status == NtStatus.STATUS_SUCCESS)
                {
                    status = smbdAdapter.SmbdPostReceive();
                    if (status != NtStatus.STATUS_SUCCESS)
                    {
                        break;
                    }
                    postReceive++;
                }
                smbdAdapter.SmbdSendDataTransferMessage(
                    smbdAdapter.ClientConnection.SendCreditTarget,
                    postReceive,
                    SmbdDataTransfer_Flags.NONE,
                    0,
                    0,
                    0,
                    new byte[0]);
                #endregion
            }

            #region Decode SMB2 READ response and validate
            object endpoint = new object();
            int consumedLength;
            int expectedLength;
            StackPacket[] stackPackets = smbdAdapter.Decoder.Smb2DecodePacketCallback(
                endpoint,
                readResponsePacket,
                out consumedLength,
                out expectedLength);
            Smb2ReadResponsePacket package = (Smb2ReadResponsePacket)stackPackets[0];

            READ_Response readResponse = package.PayLoad;
            BaseTestSite.Assert.AreEqual<NtStatus>(
                NtStatus.STATUS_SUCCESS,
                (NtStatus)package.Header.Status,
                "Status of SMB2 Read File is {0}", (NtStatus)package.Header.Status);
            #endregion
        }


        /// <summary>
        /// Read back file content and validate whether read content is the same as written content
        /// </summary>
        /// <param name="fileContent"></param>
        public void ValidateFileContent(byte[] fileContent)
        {
            // read back file
            byte[] readFileContent = new byte[fileContent.Length];
            uint length = (uint)fileContent.Length;
            uint offset = 0; // reset offset
            while (offset < fileContent.Length)
            {
                byte[] directMemory = new byte[fileContent.Length];
                SmbdBufferDescriptorV1 descp;
                smbdAdapter.SmbdRegisterBuffer((uint)directMemory.Length, SmbdBufferReadWrite.RDMA_WRITE_PERMISSION_FOR_READ_FILE, out descp);
                byte[] channelInfo = TypeMarshal.ToBytes<SmbdBufferDescriptorV1>(descp);

                length = (uint)fileContent.Length;
                if (offset + length > fileContent.Length)
                {
                    length = (uint)fileContent.Length - offset;
                }
                READ_Response readResponse;
                byte[] readData;
                NtStatus status = (NtStatus)smbdAdapter.Smb2ReadOverRdmaChannel(
                    (UInt64)offset,
                    (uint)length,
                    channelInfo,
                    out readResponse,
                    out readData
                    );
                BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMB2 Read File is {0}", status);

                smbdAdapter.SmbdReadRegisteredBuffer(directMemory, descp);
                Array.Copy(directMemory, 0, readFileContent, offset, length);

                offset += length;
            }

            // check content 
            BaseTestSite.Assert.IsTrue(SmbdUtilities.CompareByteArray(fileContent, readFileContent), "Check content of file");

        }

        /// <summary>
        /// Send multiple segments
        /// 
        /// If isMininum is not set, generate list of number from 128 to 0 and then 0 to ~.
        /// For example, 128, 127, 126 ... 1, 0, 1, 2, ...
        /// Else, generate list of number with all number one: 1, 1, 1, .....
        /// 
        /// Split the input data into slices. Data length of each slice follows the number and number sequence in the list just generated.
        /// 
        /// Send the SMBD Data Transfer messages to server.
        /// </summary>
        /// <param name="data">Data to be sent.</param>
        /// <param name="isMininum">Indicate whether the function is used by test case "SmbdDataTransfer_SmallLengthSegment".</param>
        /// <param name="withRedundancyBytes">With Redundancy Bytes at the end of SMBD Data Transfer messages</param>
        public void SendMultipleSegmentsWithVariableDataLength(
            byte[] data,
            bool isMininum = false,
            bool withRedundancyBytes = false)
        {
            int offset = 0;
            // [MS-SMBD] Section 3.1.5.6: the smallest valid message size is the normative 128-byte MaxReceiveSize floor.
            int startSize = (int)SmbdConnection.FLOOR_MAX_RECEIVE_SIZE;
            bool isAdd = false;
            NtStatus status;

            while (offset < data.Length)
            {
                #region send SMBDirect Data Transfer
                while (offset < data.Length && smbdAdapter.ClientConnection.SendCredits > 0)
                {
                    int currentSize = 0;

                    #region Calculate current segment size
                    if (isMininum)
                    {
                        currentSize = 1;
                    }
                    else
                    {
                        currentSize = startSize;
                        if (isAdd)
                        {
                            startSize++;
                        }
                        else
                        {
                            startSize--;
                            if (startSize == -1)
                            {
                                isAdd = true;
                                startSize = 0;
                            }
                        }
                    }
                    #endregion

                    // if is exceed
                    if (currentSize > smbdAdapter.ClientConnection.MaxReceiveSize)
                    {
                        currentSize = (int)smbdAdapter.ClientConnection.MaxReceiveSize;
                    }
                    if (offset + currentSize > data.Length)
                    {
                        currentSize = data.Length - offset;
                    }

                    byte[] segmentData = new byte[currentSize];
                    Array.Copy(data, offset, segmentData, 0, currentSize);
                    offset += currentSize;

                    SmbdDataTransferMessage smbdDataTransferMessage = new SmbdDataTransferMessage();
                    smbdDataTransferMessage.CreditsRequested = (ushort)SmbdTestConfig.SendCreditTarget; // [MS-SMBD] Section 3.1.5.1
                    smbdDataTransferMessage.CreditsGranted = 1;
                    smbdDataTransferMessage.Flags = SmbdDataTransfer_Flags.NONE;
                    smbdDataTransferMessage.RemainingDataLength = (uint)(data.Length - offset);
                    smbdDataTransferMessage.DataOffset = 24;
                    smbdDataTransferMessage.DataLength = (uint)currentSize;
                    smbdDataTransferMessage.Padding = new byte[4];
                    smbdDataTransferMessage.Buffer = segmentData;
                    byte[] smbdDataTransferData = TypeMarshal.ToBytes<SmbdDataTransferMessage>(smbdDataTransferMessage);
                    if (withRedundancyBytes)
                    {
                        byte[] dataWithMaxSendSize = new byte[smbdAdapter.ServerConnection.MaxReceiveSize];
                        Array.Copy(smbdDataTransferData, dataWithMaxSendSize, smbdDataTransferData.Length);
                        smbdDataTransferData = dataWithMaxSendSize;
                    }
                    status = smbdAdapter.SendDataOverRdma(smbdDataTransferData);
                    smbdAdapter.ClientConnection.SendCredits--;
                    BaseTestSite.Assert.AreEqual<NtStatus>(
                        NtStatus.STATUS_SUCCESS,
                        status,
                        "Status of send segment with length {0}, {1} send credit remaining.",
                        currentSize,
                        smbdAdapter.ClientConnection.SendCredits
                        );
                }
                #endregion

                #region receive credit grant
                if (offset < data.Length)
                {
                    // receive the empty message for granting send credits
                    SmbdDataTransferMessage transferPackage;
                    status = (NtStatus)smbdAdapter.SmbdReceivDataTransferMessage(
                        TimeSpan.FromSeconds(SmbdConnection.KEEP_ALIVE_INTERVAL),
                        out transferPackage
                        );
                    BaseTestSite.Assert.AreEqual<uint>(0, transferPackage.DataLength, "Empty message");

                    #region Check the empty message, which is to grant credit
                    BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of receive SMB2 negotiate response {0}", status);

                    BaseTestSite.Assert.IsTrue(transferPackage.CreditsGranted > 0, "CreditsGranted of Response is {0}", transferPackage.CreditsRequested);
                    BaseTestSite.Assert.IsTrue(transferPackage.CreditsRequested > 0, "CreditsRequested of Response is {0}", transferPackage.CreditsRequested);
                    BaseTestSite.Assert.AreEqual<SmbdDataTransfer_Flags>(SmbdDataTransfer_Flags.NONE, transferPackage.Flags, "Flags of Response is {0}", transferPackage.Flags);
                    BaseTestSite.Assert.AreEqual<ushort>(0, transferPackage.Reserved, "Reserved of Response is {0}", transferPackage.Reserved);
                    BaseTestSite.Assert.AreEqual<uint>(0, transferPackage.RemainingDataLength, "Reserved of Response is {0}", transferPackage.RemainingDataLength);
                    BaseTestSite.Assert.AreEqual<uint>(0, transferPackage.DataOffset, "DataOffset of Response is {0}", transferPackage.DataOffset);
                    BaseTestSite.Assert.AreEqual<uint>(0, transferPackage.DataLength, "DataLength of Response is {0}", transferPackage.DataLength);
                    BaseTestSite.Assert.AreEqual<uint>(0, (uint)transferPackage.Padding.Length, "Padding length is {0}", transferPackage.Padding.Length);
                    #endregion

                    // raise receive request for write response
                    status = smbdAdapter.SmbdPostReceive();
                }
                #endregion
            }
        }

        public void SendWithInvalidRemainingDataLength(
            List<SmbdDataTransferMessage> messages,
            int messageNumber,
            int remainingDataLength,
            bool isModify = false)
        {
            NtStatus status;
            for (int index = 0; index < messageNumber - 1; ++index)
            {
                status = (NtStatus)smbdAdapter.SmbdSendDataTransferMessage(
                        (ushort)(messages.Count),
                        1,
                        SmbdDataTransfer_Flags.NONE,
                        messages[index].RemainingDataLength,
                        messages[index].DataOffset,
                        messages[index].DataLength,
                        messages[index].Buffer
                        );
                BaseTestSite.Assert.AreEqual<NtStatus>(
                    NtStatus.STATUS_SUCCESS,
                    status,
                    "Send SMBDirect Data Transfer message with status {0}", status);
            }

            uint modifiedRemainingDataLength;
            if (isModify)
            {
                modifiedRemainingDataLength = (uint)(messages[messageNumber - 1].RemainingDataLength +
                    remainingDataLength);
            }
            else
            {
                modifiedRemainingDataLength = (uint)remainingDataLength;
            }

            status = (NtStatus)smbdAdapter.SmbdSendDataTransferMessage(
                    (ushort)(messages.Count),
                    1,
                    SmbdDataTransfer_Flags.NONE,
                    modifiedRemainingDataLength,
                    messages[messageNumber - 1].DataOffset,
                    messages[messageNumber - 1].DataLength,
                    messages[messageNumber - 1].Buffer
                    );
            BaseTestSite.Assert.AreEqual<NtStatus>(
                NtStatus.STATUS_SUCCESS,
                status,
                "Send SMBDirect Data Transfer message with status {0}", status);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Verify server connection will be terminated.");
            smbdAdapter.WaitRdmaDisconnect();
            BaseTestSite.Assert.IsFalse(smbdAdapter.ClientConnection.Endpoint.IsConnected, "Connection should be terminated.");
        }

        /// <summary>
        /// Modify DataOffset in SMBDirect Data Transfer message
        /// </summary>
        public void CommonTestMethod_ModifyField_SmbdDataTransfer(
            uint maxSendSize,
            uint maxFragmentSize,
            uint maxReceiveSize,
            uint bufferLength,
            int modifyFieldAddress,
            uint modifyValue,
            bool useMaxSendSize = false
            )
        {
            byte[] smb2WriteRequest;
            byte[] fileContent;
            byte[] orgDataTransferPackage;
            SmbdDataTransferMessage dataTransfer;
            NtStatus status;

            if (useMaxSendSize)
            {
                Initialize_SendSmbdDataTransferTestCase(
                    maxSendSize,
                    maxFragmentSize,
                    maxReceiveSize,
                    24, // data offset
                    out fileContent,
                    out smb2WriteRequest,
                    true);
            }
            else
            {
                Initialize_SendSmbdDataTransferTestCase(
                    maxSendSize,
                    maxFragmentSize,
                    maxReceiveSize,
                    bufferLength,
                    out fileContent,
                    out smb2WriteRequest);
            }
            dataTransfer = new SmbdDataTransferMessage();
            dataTransfer.CreditsRequested = (ushort)SmbdTestConfig.SendCreditTarget; // [MS-SMBD] Section 3.1.5.1
            dataTransfer.CreditsGranted = 1;
            dataTransfer.Flags = SmbdDataTransfer_Flags.NONE;
            dataTransfer.RemainingDataLength = 0;
            dataTransfer.DataOffset = 24;
            dataTransfer.DataLength = (uint)smb2WriteRequest.Length;
            dataTransfer.Padding = new byte[4];
            dataTransfer.Buffer = smb2WriteRequest;

            // Change field value in SMBDirect Data Transfer message
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Change field value in SMBDirect Data Transfer message.");
            orgDataTransferPackage = TypeMarshal.ToBytes<SmbdDataTransferMessage>(dataTransfer);
            byte[] invalidDataTransferPackage = new byte[orgDataTransferPackage.Length];

            if (useMaxSendSize)
            {
                modifyValue += (uint)smb2WriteRequest.Length;
            }
            byte[] dataOffsetByte = TypeMarshal.ToBytes<uint>(modifyValue);
            Array.Copy(orgDataTransferPackage, invalidDataTransferPackage, orgDataTransferPackage.Length);
            Array.Copy(dataOffsetByte, 0, invalidDataTransferPackage, modifyFieldAddress, dataOffsetByte.Length);

            // send data over RDMA
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Send data over RDMA");
            status = smbdAdapter.SendDataOverRdma(invalidDataTransferPackage);
            BaseTestSite.Assert.AreEqual<NtStatus>(status, NtStatus.STATUS_SUCCESS, "Status of send SMBDirect Data Transfer message is {0}", status);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Verify server connection will be terminated.");
            smbdAdapter.WaitRdmaDisconnect();
            BaseTestSite.Assert.IsFalse(smbdAdapter.ClientConnection.Endpoint.IsConnected, "Connection should be terminated.");
        }

        public void CommonTestMethod_RemainingDataLength_AgainstMaxFragmentedSize(
            uint remainingDataLength,
            bool useMaxFragmentedSize = false)
        {
            // define data for test case
            uint MAX_SEND_SIZE = SmbdTestConfig.MaxSendSize;
            uint MAX_FRAGMENT_SIZE = SmbdTestConfig.MaxFragmentedSize;
            uint MAX_RECEIVE_SIZE = SmbdTestConfig.MaxReceiveSize;

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Connect to server over RDMA.");
            NtStatus status = smbdAdapter.ConnectToServerOverRDMA();
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of RDMA connection is {0}", status);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "SMBD Negotiate.");
            SmbdNegotiateResponse response;
            status = smbdAdapter.SmbdNegotiate(MAX_SEND_SIZE, MAX_RECEIVE_SIZE, MAX_FRAGMENT_SIZE, out response);
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMBDirect negotiate is {0}", status);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Send empty SMBDirect message with invalid RemainingDataLength.");
            if (useMaxFragmentedSize)
            {
                remainingDataLength += smbdAdapter.ServerConnection.MaxFragmentedSize;
            }
            status = smbdAdapter.SmbdSendDataTransferMessage(
                smbdAdapter.ClientConnection.SendCreditTarget,
                1,
                SmbdDataTransfer_Flags.NONE,
                remainingDataLength,
                0,
                0,
                new byte[0]);
            BaseTestSite.Assert.AreEqual<NtStatus>(
                NtStatus.STATUS_SUCCESS,
                status,
                "Status of sending empty SMBDirect Data Transfer message is {0}", status);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Verify server connection will be terminated.");
            smbdAdapter.WaitRdmaDisconnect();
            BaseTestSite.Assert.IsFalse(smbdAdapter.ClientConnection.Endpoint.IsConnected, "Connection should be terminated.");
        }

        #endregion
    }
}
