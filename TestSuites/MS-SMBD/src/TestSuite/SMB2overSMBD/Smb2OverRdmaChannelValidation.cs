// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Protocols.TestSuites.Smbd.Adapter;
using Microsoft.Protocols.TestTools;
using Microsoft.Protocols.TestTools.StackSdk;
using Microsoft.Protocols.TestTools.StackSdk.FileAccessService.Smb2;
using Microsoft.Protocols.TestTools.StackSdk.FileAccessService.Smbd;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Net;

namespace Microsoft.Protocol.TestSuites.Smbd.TestSuite
{
    /// <summary>
    /// Negative and end-of-file tests for the SMB2 READ / WRITE request validation that applies when the Channel field
    /// selects an SMB Direct (RDMA) channel. Expectations come from [MS-SMB2] 3.3.5.12 and 3.3.5.13.
    /// </summary>
    [TestClass]
    public class Smb2OverRdmaChannelValidation : Smb2OverSmbdTestBase
    {
        #region Variables
        private const int SeedFileSize = 512;
        private static readonly DialectRevision[] Smb302Only = new[] { DialectRevision.Smb302 };
        private static readonly DialectRevision[] Smb300Only = new[] { DialectRevision.Smb30 };
        private static readonly DialectRevision[] Smb311Only = new[] { DialectRevision.Smb311 };
        private static readonly DialectRevision[] DefaultDialects = new[] { DialectRevision.Smb311, DialectRevision.Smb302 };

        private TestConfig testConfig;
        private Smb2OverSmbdTestClient client;
        private bool clientOverTcp;
        #endregion

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

        #region Test Initialization and Cleanup
        protected override void TestInitialize()
        {
            base.TestInitialize();
            testConfig = new TestConfig(BaseTestSite);
            client = null;
            clientOverTcp = false;
        }

        protected override void TestCleanup()
        {
            if (client != null)
            {
                try
                {
                    if (clientOverTcp)
                    {
                        client.Disconnect();
                    }
                    else
                    {
                        client.DisconnectRdma();
                    }
                }
                catch (Exception ex)
                {
                    BaseTestSite.Log.Add(LogEntryKind.Debug, "Disconnect of validation client failed: " + ex.Message);
                }
            }

            base.TestCleanup();
        }
        #endregion

        #region Channel / dialect validation
        [TestMethod()]
        [TestCategory("Negative")]
        [TestCategory("Smb2OverRdmaChannelValidation")]
        [Description("Verify SMB2 WRITE with Channel SMB2_CHANNEL_RDMA_TRANSFORM on dialect 3.0.2 fails with STATUS_INVALID_PARAMETER.")]
        // WHAT: WRITE with Channel = SMB2_CHANNEL_RDMA_TRANSFORM on a 3.0.2 connection.
        // WHY:  RDMA_TRANSFORM exists only for 3.1.1 ([MS-SMB2] 2.2.21 "not valid for 3.0 and 3.0.2").
        // SPEC: [MS-SMB2] 3.3.5.13 - if Connection.Dialect is "3.0.2" and Channel is not SMB2_CHANNEL_RDMA_V1_INVALIDATE,
        //       SMB2_CHANNEL_RDMA_V1 or SMB2_CHANNEL_NONE, the server MUST fail with STATUS_INVALID_PARAMETER.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.13 Receiving an SMB2 WRITE Request; [MS-SMB2] 2.2.21 SMB2 WRITE Request")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannel_Write_RdmaTransform_Smb302_InvalidParameter()
        {
            WriteWithChannelAndExpectInvalidParameter(Smb302Only, Channel_Values.CHANNEL_RDMA_TRANSFORM);
        }

        [TestMethod()]
        [TestCategory("Negative")]
        [TestCategory("Smb2OverRdmaChannelValidation")]
        [Description("Verify SMB2 WRITE with Channel SMB2_CHANNEL_RDMA_TRANSFORM on dialect 3.0 fails with STATUS_INVALID_PARAMETER.")]
        // WHAT: WRITE with Channel = SMB2_CHANNEL_RDMA_TRANSFORM on a 3.0 connection.
        // WHY:  RDMA_TRANSFORM is not defined for 3.0.
        // SPEC: [MS-SMB2] 3.3.5.13 - if Connection.Dialect is "3.0" and Channel is not SMB2_CHANNEL_RDMA_V1 or
        //       SMB2_CHANNEL_NONE, the server MUST fail with STATUS_INVALID_PARAMETER.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.13 Receiving an SMB2 WRITE Request; [MS-SMB2] 2.2.21 SMB2 WRITE Request")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannel_Write_RdmaTransform_Smb300_InvalidParameter()
        {
            WriteWithChannelAndExpectInvalidParameter(Smb300Only, Channel_Values.CHANNEL_RDMA_TRANSFORM);
        }

        [TestMethod()]
        [TestCategory("Negative")]
        [TestCategory("Smb2OverRdmaChannelValidation")]
        [Description("Verify SMB2 READ with Channel SMB2_CHANNEL_RDMA_TRANSFORM on dialect 3.0.2 fails with STATUS_INVALID_PARAMETER.")]
        // WHAT: READ with Channel = SMB2_CHANNEL_RDMA_TRANSFORM on a 3.0.2 connection.
        // WHY:  READ requests never accept RDMA_TRANSFORM as a Channel value.
        // SPEC: [MS-SMB2] 3.3.5.12 - if Connection.Dialect is "3.0.2" or "3.1.1" and Channel is not
        //       SMB2_CHANNEL_RDMA_V1_INVALIDATE, SMB2_CHANNEL_RDMA_V1 or SMB2_CHANNEL_NONE, the server MUST fail with
        //       STATUS_INVALID_PARAMETER.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.12 Receiving an SMB2 READ Request; [MS-SMB2] 2.2.19 SMB2 READ Request")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannel_Read_RdmaTransform_Smb302_InvalidParameter()
        {
            ReadWithChannelAndExpectInvalidParameter(Smb302Only, Channel_Values.CHANNEL_RDMA_TRANSFORM);
        }

        [TestMethod()]
        [TestCategory("Negative")]
        [TestCategory("Smb2OverRdmaChannelValidation")]
        [Description("Verify SMB2 READ with an undefined Channel value on dialect 3.0.2 fails with STATUS_INVALID_PARAMETER.")]
        // WHAT: READ with Channel = 4 (undefined) on a 3.0.2 connection.
        // WHY:  only NONE, RDMA_V1 and RDMA_V1_INVALIDATE are acceptable for 3.0.2.
        // SPEC: [MS-SMB2] 3.3.5.12 - dialect 3.0.2 and Channel not in {RDMA_V1_INVALIDATE, RDMA_V1, NONE} => MUST fail
        //       with STATUS_INVALID_PARAMETER.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.12 Receiving an SMB2 READ Request; [MS-SMB2] 2.2.19 SMB2 READ Request")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannel_Read_UndefinedChannel_Smb302_InvalidParameter()
        {
            ReadWithChannelAndExpectInvalidParameter(Smb302Only, (Channel_Values)4);
        }

        [TestMethod()]
        [TestCategory("Negative")]
        [TestCategory("Smb2OverRdmaChannelValidation")]
        [Description("Verify SMB2 READ with an undefined Channel value on dialect 3.1.1 fails with STATUS_INVALID_PARAMETER.")]
        // WHAT: READ with Channel = 4 (undefined) on a 3.1.1 connection.
        // WHY:  same rule applies to 3.1.1.
        // SPEC: [MS-SMB2] 3.3.5.12 - dialect 3.0.2 or 3.1.1 and Channel not in {RDMA_V1_INVALIDATE, RDMA_V1, NONE} => MUST
        //       fail with STATUS_INVALID_PARAMETER.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.12 Receiving an SMB2 READ Request; [MS-SMB2] 2.2.19 SMB2 READ Request")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannel_Read_UndefinedChannel_Smb311_InvalidParameter()
        {
            ReadWithChannelAndExpectInvalidParameter(Smb311Only, (Channel_Values)4);
        }

        [TestMethod()]
        [TestCategory("Negative")]
        [TestCategory("Smb2OverRdmaChannelValidation")]
        [Description("Verify SMB2 WRITE with an undefined Channel value on dialect 3.0.2 fails with STATUS_INVALID_PARAMETER.")]
        // WHAT: WRITE with Channel = 4 (undefined) on a 3.0.2 connection.
        // WHY:  only NONE, RDMA_V1 and RDMA_V1_INVALIDATE are acceptable for 3.0.2.
        // SPEC: [MS-SMB2] 3.3.5.13 - dialect 3.0.2 and Channel not in {RDMA_V1_INVALIDATE, RDMA_V1, NONE} => MUST fail with
        //       STATUS_INVALID_PARAMETER.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.13 Receiving an SMB2 WRITE Request; [MS-SMB2] 2.2.21 SMB2 WRITE Request")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannel_Write_UndefinedChannel_Smb302_InvalidParameter()
        {
            WriteWithChannelAndExpectInvalidParameter(Smb302Only, (Channel_Values)4);
        }

        [TestMethod()]
        [TestCategory("Negative")]
        [TestCategory("Smb2OverRdmaChannelValidation")]
        [Description("Verify SMB2 WRITE with an undefined Channel value on dialect 3.1.1 fails with STATUS_INVALID_PARAMETER.")]
        // WHAT: WRITE with Channel = 4 (undefined) on a 3.1.1 connection.
        // WHY:  3.1.1 accepts only TRANSFORM (if supported), V1_INVALIDATE, V1 and NONE.
        // SPEC: [MS-SMB2] 3.3.5.13 - dialect 3.1.1 and Channel not in the permitted set => MUST fail with
        //       STATUS_INVALID_PARAMETER.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.13 Receiving an SMB2 WRITE Request; [MS-SMB2] 2.2.21 SMB2 WRITE Request")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannel_Write_UndefinedChannel_Smb311_InvalidParameter()
        {
            WriteWithChannelAndExpectInvalidParameter(Smb311Only, (Channel_Values)4);
        }
        #endregion

        #region Channel information validation
        [TestMethod()]
        [TestCategory("Negative")]
        [TestCategory("Smb2OverRdmaChannelValidation")]
        [Description("Verify SMB2 READ with Channel SMB2_CHANNEL_RDMA_V1 and ReadChannelInfoLength 0 fails with STATUS_INVALID_PARAMETER.")]
        // WHAT: READ RDMA_V1 with no channel information (ReadChannelInfoOffset = ReadChannelInfoLength = 0).
        // WHY:  the server has no buffer descriptor to RDMA Write the data into.
        // SPEC: [MS-SMB2] 3.3.5.12 - Channel RDMA_V1 and (Length, ReadChannelInfoOffset or ReadChannelInfoLength is 0)
        //       => MUST fail with STATUS_INVALID_PARAMETER.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.12 Receiving an SMB2 READ Request")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannel_Read_RdmaV1_ChannelInfoLengthZero_InvalidParameter()
        {
            OpenClient(DefaultDialects, false, null);

            NtStatus status = RawRead(SeedFileSize, 0, 0, Channel_Values.CHANNEL_RDMA_V1, new byte[0]);

            AssertInvalidParameter(status, "READ RDMA_V1 with empty channel information");
        }

        [TestMethod()]
        [TestCategory("Negative")]
        [TestCategory("Smb2OverRdmaChannelValidation")]
        [Description("Verify SMB2 WRITE with Channel SMB2_CHANNEL_RDMA_V1 and WriteChannelInfoLength 0 fails with STATUS_INVALID_PARAMETER.")]
        // WHAT: WRITE RDMA_V1 with WriteChannelInfoLength = 0.
        // WHY:  the server has no buffer descriptor to RDMA Read the data from.
        // SPEC: [MS-SMB2] 3.3.5.13 - Channel RDMA_V1 and (RemainingBytes, WriteChannelInfoOffset or WriteChannelInfoLength is
        //       0) => MUST fail with STATUS_INVALID_PARAMETER.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.13 Receiving an SMB2 WRITE Request")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannel_Write_RdmaV1_ChannelInfoLengthZero_InvalidParameter()
        {
            OpenClient(DefaultDialects, false, null);

            NtStatus status = RawWrite(SeedFileSize, Channel_Values.CHANNEL_RDMA_V1, new byte[0]);

            AssertInvalidParameter(status, "WRITE RDMA_V1 with WriteChannelInfoLength 0");
        }

        [TestMethod()]
        [TestCategory("Negative")]
        [TestCategory("Smb2OverRdmaChannelValidation")]
        [Description("Verify SMB2 READ with Channel SMB2_CHANNEL_RDMA_V1 and ReadChannelInfoOffset 0 fails with STATUS_INVALID_PARAMETER.")]
        // WHAT: READ RDMA_V1 carrying a valid descriptor but ReadChannelInfoOffset = 0.
        // WHY:  an offset of 0 does not locate the channel information.
        // SPEC: [MS-SMB2] 3.3.5.12 - Channel RDMA_V1 and ReadChannelInfoOffset is 0 => MUST fail with STATUS_INVALID_PARAMETER.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.12 Receiving an SMB2 READ Request")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannel_Read_RdmaV1_ChannelInfoOffsetZero_InvalidParameter()
        {
            OpenClient(DefaultDialects, false, null);
            SmbdBufferDescriptorV1 descp = MakeDescriptor(SeedFileSize, SmbdBufferReadWrite.RDMA_WRITE_PERMISSION_FOR_READ_FILE);
            byte[] channelInfo = TypeMarshal.ToBytes<SmbdBufferDescriptorV1>(descp);

            ulong messageId, sessionId;
            NextIds(1, out messageId, out sessionId);
            Smb2ReadRequestPacket request = new Smb2ReadRequestPacket();
            request.Header.CreditCharge = 1;
            request.Header.Command = Smb2Command.READ;
            request.Header.CreditRequestResponse = 64;
            request.Header.Flags = Packet_Header_Flags_Values.FLAGS_SIGNED;
            request.Header.MessageId = messageId;
            request.Header.TreeId = client.TreeId;
            request.Header.SessionId = sessionId;
            request.PayLoad.Length = SeedFileSize;
            request.PayLoad.Offset = 0;
            request.PayLoad.FileId = client.FileId;
            request.PayLoad.Channel = Channel_Values.CHANNEL_RDMA_V1;
            request.PayLoad.ReadChannelInfoOffset = 0;
            request.PayLoad.ReadChannelInfoLength = (ushort)channelInfo.Length;
            request.Buffer = channelInfo;

            client.SendPacket(request);
            Smb2ReadResponsePacket response = client.ExpectPacket<Smb2ReadResponsePacket>(messageId);

            AssertInvalidParameter((NtStatus)response.Header.Status, "READ RDMA_V1 with ReadChannelInfoOffset 0");
        }

        [TestMethod()]
        [TestCategory("Negative")]
        [TestCategory("Smb2OverRdmaChannelValidation")]
        [Description("Verify SMB2 WRITE with Channel SMB2_CHANNEL_RDMA_V1 and WriteChannelInfoOffset 0 fails with STATUS_INVALID_PARAMETER.")]
        // WHAT: WRITE RDMA_V1 carrying a valid descriptor but WriteChannelInfoOffset = 0.
        // WHY:  an offset of 0 does not locate the channel information.
        // SPEC: [MS-SMB2] 3.3.5.13 - Channel RDMA_V1 and WriteChannelInfoOffset is 0 => MUST fail with STATUS_INVALID_PARAMETER.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.13 Receiving an SMB2 WRITE Request")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannel_Write_RdmaV1_ChannelInfoOffsetZero_InvalidParameter()
        {
            OpenClient(DefaultDialects, false, null);
            SmbdBufferDescriptorV1 descp = MakeDescriptor(SeedFileSize, SmbdBufferReadWrite.RDMA_READ_PERMISSION_FOR_WRITE_FILE);
            byte[] channelInfo = TypeMarshal.ToBytes<SmbdBufferDescriptorV1>(descp);

            Smb2WriteRequestPacket request = BuildRawWriteRequest(SeedFileSize, channelInfo);
            request.PayLoad.WriteChannelInfoOffset = 0;

            NtStatus status = SendRawWrite(request);

            AssertInvalidParameter(status, "WRITE RDMA_V1 with WriteChannelInfoOffset 0");
        }

        [TestMethod()]
        [TestCategory("Negative")]
        [TestCategory("Smb2OverRdmaChannelValidation")]
        [Description("Verify SMB2 READ with Channel SMB2_CHANNEL_RDMA_V1 and request Length 0 fails with STATUS_INVALID_PARAMETER.")]
        // WHAT: READ RDMA_V1 with a valid descriptor and Length = 0.
        // WHY:  a zero-length RDMA read request is malformed.
        // SPEC: [MS-SMB2] 3.3.5.12 - Channel RDMA_V1 and Length is 0 => MUST fail with STATUS_INVALID_PARAMETER.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.12 Receiving an SMB2 READ Request")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannel_Read_RdmaV1_LengthZero_InvalidParameter()
        {
            OpenClient(DefaultDialects, false, (int)SeedFileSize);
            SmbdBufferDescriptorV1 descp = MakeDescriptor(SeedFileSize, SmbdBufferReadWrite.RDMA_WRITE_PERMISSION_FOR_READ_FILE);
            byte[] channelInfo = TypeMarshal.ToBytes<SmbdBufferDescriptorV1>(descp);

            NtStatus status = RawRead(0, 0, 0, Channel_Values.CHANNEL_RDMA_V1, channelInfo);

            AssertInvalidParameter(status, "READ RDMA_V1 with Length 0");
        }

        [TestMethod()]
        [TestCategory("Negative")]
        [TestCategory("Smb2OverRdmaChannelValidation")]
        [Description("Verify SMB2 WRITE with Channel SMB2_CHANNEL_RDMA_V1 and RemainingBytes 0 fails with STATUS_INVALID_PARAMETER.")]
        // WHAT: WRITE RDMA_V1 with a valid descriptor and RemainingBytes = 0.
        // WHY:  RemainingBytes carries the number of bytes to fetch over RDMA.
        // SPEC: [MS-SMB2] 3.3.5.13 - Channel RDMA_V1 and RemainingBytes is 0 => MUST fail with STATUS_INVALID_PARAMETER.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.13 Receiving an SMB2 WRITE Request")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannel_Write_RdmaV1_RemainingBytesZero_InvalidParameter()
        {
            OpenClient(DefaultDialects, false, null);
            SmbdBufferDescriptorV1 descp = MakeDescriptor(SeedFileSize, SmbdBufferReadWrite.RDMA_READ_PERMISSION_FOR_WRITE_FILE);
            byte[] channelInfo = TypeMarshal.ToBytes<SmbdBufferDescriptorV1>(descp);

            NtStatus status = RawWrite(0, Channel_Values.CHANNEL_RDMA_V1, channelInfo);

            AssertInvalidParameter(status, "WRITE RDMA_V1 with RemainingBytes 0");
        }

        [TestMethod()]
        [TestCategory("Negative")]
        [TestCategory("Smb2OverRdmaChannelValidation")]
        [Description("Verify SMB2 WRITE over RDMA with a non-zero DataOffset and Length fails with STATUS_INVALID_PARAMETER.")]
        // WHAT: WRITE RDMA_V1 carrying a valid descriptor plus a non-zero DataOffset / Length (inline data).
        // WHY:  data is transferred over RDMA, so the inline data fields must be 0.
        // SPEC: [MS-SMB2] 3.3.5.13 - Channel RDMA_V1 and (Length or DataOffset is not 0) => MUST fail with
        //       STATUS_INVALID_PARAMETER.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.13 Receiving an SMB2 WRITE Request")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannel_Write_RdmaV1_NonZeroDataOffsetAndLength_InvalidParameter()
        {
            OpenClient(DefaultDialects, false, null);
            SmbdBufferDescriptorV1 descp = MakeDescriptor(SeedFileSize, SmbdBufferReadWrite.RDMA_READ_PERMISSION_FOR_WRITE_FILE);
            byte[] channelInfo = TypeMarshal.ToBytes<SmbdBufferDescriptorV1>(descp);
            const int inlineLength = 8;

            byte[] buffer = new byte[channelInfo.Length + inlineLength];
            Array.Copy(channelInfo, buffer, channelInfo.Length);
            Smb2WriteRequestPacket request = BuildRawWriteRequest(SeedFileSize, channelInfo);
            request.Buffer = buffer;
            request.PayLoad.DataOffset = (ushort)(request.BufferOffset + channelInfo.Length);
            request.PayLoad.Length = inlineLength;

            NtStatus status = SendRawWrite(request);

            AssertInvalidParameter(status, "WRITE RDMA_V1 with non-zero DataOffset and Length");
        }
        #endregion

        #region Buffer descriptor validation (WRITE)
        [TestMethod()]
        [TestCategory("Negative")]
        [TestCategory("Smb2OverRdmaChannelValidation")]
        [Description("Verify SMB2 WRITE over RDMA_V1 whose first buffer descriptor has Length 0 fails with STATUS_INVALID_PARAMETER.")]
        // WHAT: WRITE RDMA_V1 whose only (first) descriptor has Length = 0.
        // WHY:  the server cannot RDMA Read from a zero-length buffer.
        // SPEC: [MS-SMB2] 3.3.5.13 - if the Length of the first SMB_DIRECT_BUFFER_DESCRIPTOR_V1 is 0 the server MUST fail with
        //       STATUS_INVALID_PARAMETER.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.13 Receiving an SMB2 WRITE Request")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannel_Write_RdmaV1_FirstDescriptorLengthZero_InvalidParameter()
        {
            SkipWhereRdmaV1WriteIsUnsupported();
            OpenClient(DefaultDialects, false, null);
            SmbdBufferDescriptorV1 descp = MakeDescriptor(SeedFileSize, SmbdBufferReadWrite.RDMA_READ_PERMISSION_FOR_WRITE_FILE);
            descp.Length = 0;

            WRITE_Response writeResponse;
            NtStatus status = (NtStatus)client.Smb2WriteOverRdmaChannel(
                0,
                TypeMarshal.ToBytes<SmbdBufferDescriptorV1>(descp),
                SeedFileSize,
                out writeResponse);

            AssertInvalidParameter(status, "WRITE RDMA_V1 with first descriptor Length 0");
        }

        [TestMethod()]
        [TestCategory("Negative")]
        [TestCategory("Smb2OverRdmaChannelValidation")]
        [Description("Verify SMB2 WRITE over RDMA_V1 whose descriptor lengths sum to less than RemainingBytes fails with STATUS_INVALID_PARAMETER.")]
        // WHAT: WRITE RDMA_V1 with one descriptor of SeedFileSize bytes but RemainingBytes = 2 * SeedFileSize.
        // WHY:  the descriptors cannot supply the number of bytes announced in RemainingBytes.
        // SPEC: [MS-SMB2] 3.3.5.13 - if the sum of the descriptor Lengths is less than RemainingBytes the server MUST fail with
        //       STATUS_INVALID_PARAMETER.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.13 Receiving an SMB2 WRITE Request")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannel_Write_RdmaV1_DescriptorLengthSumLessThanRemainingBytes_InvalidParameter()
        {
            SkipWhereRdmaV1WriteIsUnsupported();
            OpenClient(DefaultDialects, false, null);
            SmbdBufferDescriptorV1 descp = MakeDescriptor(SeedFileSize, SmbdBufferReadWrite.RDMA_READ_PERMISSION_FOR_WRITE_FILE);

            WRITE_Response writeResponse;
            NtStatus status = (NtStatus)client.Smb2WriteOverRdmaChannel(
                0,
                TypeMarshal.ToBytes<SmbdBufferDescriptorV1>(descp),
                2 * SeedFileSize,
                out writeResponse);

            AssertInvalidParameter(status, "WRITE RDMA_V1 with descriptor length sum < RemainingBytes");
        }

        [TestMethod()]
        [TestCategory("Negative")]
        [TestCategory("Smb2OverRdmaChannelValidation")]
        [Description("Verify SMB2 WRITE over RDMA_V1 with RemainingBytes greater than MaxWriteSize fails with STATUS_INVALID_PARAMETER.")]
        // WHAT: WRITE RDMA_V1 with RemainingBytes = MaxWriteSize + 1, backed by a descriptor large enough for the data.
        // WHY:  the descriptor is valid, so only the size limit is violated.
        // SPEC: [MS-SMB2] 3.3.5.13 - if RemainingBytes is greater than Connection.MaxWriteSize the server MUST fail with
        //       STATUS_INVALID_PARAMETER.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.13 Receiving an SMB2 WRITE Request")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannel_Write_RdmaV1_RemainingBytesExceedsMaxWriteSize_InvalidParameter()
        {
            SkipWhereRdmaV1WriteIsUnsupported();
            OpenClient(DefaultDialects, false, null);
            uint length = client.Smb2MaxWriteSize + 1;
            SmbdBufferDescriptorV1 descp = MakeDescriptor(length, SmbdBufferReadWrite.RDMA_READ_PERMISSION_FOR_WRITE_FILE);

            WRITE_Response writeResponse;
            NtStatus status = (NtStatus)client.Smb2WriteOverRdmaChannel(
                0,
                TypeMarshal.ToBytes<SmbdBufferDescriptorV1>(descp),
                length,
                out writeResponse);

            AssertInvalidParameter(status, "WRITE RDMA_V1 with RemainingBytes > MaxWriteSize");
        }
        #endregion

        #region Length validation (READ)
        [TestMethod()]
        [TestCategory("Negative")]
        [TestCategory("Smb2OverRdmaChannelValidation")]
        [Description("Verify SMB2 READ over RDMA_V1 with Length greater than MaxReadSize fails with STATUS_INVALID_PARAMETER.")]
        // WHAT: READ RDMA_V1 with Length = MaxReadSize + 1 and a descriptor large enough for the data.
        // WHY:  the descriptor is valid, so only the size limit is violated.
        // SPEC: [MS-SMB2] 3.3.5.12 - if Length is greater than Connection.MaxReadSize the server SHOULD (not MUST, see
        //       product behavior note <361>) fail with STATUS_INVALID_PARAMETER.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.12 Receiving an SMB2 READ Request")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannel_Read_RdmaV1_LengthExceedsMaxReadSize_InvalidParameter()
        {
            OpenClient(DefaultDialects, false, (int)SeedFileSize);
            uint length = client.Smb2MaxReadSize + 1;
            SmbdBufferDescriptorV1 descp = MakeDescriptor(length, SmbdBufferReadWrite.RDMA_WRITE_PERMISSION_FOR_READ_FILE);

            READ_Response readResponse;
            byte[] readData;
            NtStatus status = (NtStatus)client.Smb2ReadOverRdmaChannel(
                0,
                length,
                TypeMarshal.ToBytes<SmbdBufferDescriptorV1>(descp),
                out readResponse,
                out readData);

            // [MS-SMB2] 3.3.5.12 <361>: rejecting Length > MaxReadSize is only a SHOULD, so any other outcome is not a violation.
            if (status != NtStatus.STATUS_INVALID_PARAMETER)
            {
                BaseTestSite.Assert.Inconclusive("Server did not reject READ Length > MaxReadSize (status {0}); the spec only says SHOULD.", status);
            }
            AssertInvalidParameter(status, "READ RDMA_V1 with Length > MaxReadSize");
        }
        #endregion

        #region RDMA channel over a non-RDMA connection
        [TestMethod()]
        [TestCategory("Negative")]
        [TestCategory("Smb2OverRdmaChannelValidation")]
        [Description("Verify SMB2 READ with Channel SMB2_CHANNEL_RDMA_V1 on a TCP (non-RDMA) connection fails with STATUS_INVALID_PARAMETER.")]
        // WHAT: READ RDMA_V1 sent on an SMB2 connection that runs over TCP.
        // WHY:  RDMA channels are meaningful only on RDMA connections.
        // SPEC: [MS-SMB2] 3.3.5.12 - Channel RDMA_V1 and the underlying connection is not RDMA => MUST fail with
        //       STATUS_INVALID_PARAMETER.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.12 Receiving an SMB2 READ Request")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannel_Read_RdmaV1_OverTcpConnection_InvalidParameter()
        {
            OpenClient(DefaultDialects, true, null);
            SmbdBufferDescriptorV1 descp = MakeDescriptor(SeedFileSize, SmbdBufferReadWrite.RDMA_WRITE_PERMISSION_FOR_READ_FILE);

            READ_Response readResponse;
            byte[] readData;
            NtStatus status = (NtStatus)client.Smb2ReadOverRdmaChannel(
                0,
                SeedFileSize,
                TypeMarshal.ToBytes<SmbdBufferDescriptorV1>(descp),
                out readResponse,
                out readData);

            AssertInvalidParameter(status, "READ RDMA_V1 over TCP");
        }

        [TestMethod()]
        [TestCategory("Negative")]
        [TestCategory("Smb2OverRdmaChannelValidation")]
        [Description("Verify SMB2 WRITE with Channel SMB2_CHANNEL_RDMA_V1 on a TCP (non-RDMA) connection fails with STATUS_INVALID_PARAMETER.")]
        // WHAT: WRITE RDMA_V1 sent on an SMB2 connection that runs over TCP.
        // WHY:  RDMA channels are meaningful only on RDMA connections.
        // SPEC: [MS-SMB2] 3.3.5.13 - Channel RDMA_V1 and the underlying connection is not RDMA => MUST fail with
        //       STATUS_INVALID_PARAMETER.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.13 Receiving an SMB2 WRITE Request")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannel_Write_RdmaV1_OverTcpConnection_InvalidParameter()
        {
            SkipWhereRdmaV1WriteIsUnsupported();
            OpenClient(DefaultDialects, true, null);
            SmbdBufferDescriptorV1 descp = MakeDescriptor(SeedFileSize, SmbdBufferReadWrite.RDMA_READ_PERMISSION_FOR_WRITE_FILE);

            WRITE_Response writeResponse;
            NtStatus status = (NtStatus)client.Smb2WriteOverRdmaChannel(
                0,
                TypeMarshal.ToBytes<SmbdBufferDescriptorV1>(descp),
                SeedFileSize,
                out writeResponse);

            AssertInvalidParameter(status, "WRITE RDMA_V1 over TCP");
        }
        #endregion

        #region END_OF_FILE handling
        [TestMethod()]
        [TestCategory("Smb2OverRdmaChannelValidation")]
        [Description("Verify SMB2 READ over RDMA_V1 starting exactly at end of file fails with STATUS_END_OF_FILE.")]
        // WHAT: READ RDMA_V1 at Offset = file size of a SeedFileSize-byte file.
        // WHY:  no byte is available at or beyond EOF.
        // SPEC: [MS-SMB2] 3.3.5.12 - the server fails the request with the error code received from the object store read,
        //       which for a read at end of file is STATUS_END_OF_FILE ([MS-FSA] 2.1.5.2).
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.12 Receiving an SMB2 READ Request; [MS-FSA] 2.1.5.2 Server Requests a Read")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannel_Read_RdmaV1_AtEndOfFile_EndOfFile()
        {
            ReadAtOffsetAndExpectEndOfFile(SeedFileSize);
        }

        [TestMethod()]
        [TestCategory("Smb2OverRdmaChannelValidation")]
        [Description("Verify SMB2 READ over RDMA_V1 starting beyond end of file fails with STATUS_END_OF_FILE.")]
        // WHAT: READ RDMA_V1 at Offset = file size + 4096.
        // WHY:  no byte is available beyond EOF.
        // SPEC: [MS-SMB2] 3.3.5.12 - error code from the object store read, STATUS_END_OF_FILE ([MS-FSA] 2.1.5.2).
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.12 Receiving an SMB2 READ Request; [MS-FSA] 2.1.5.2 Server Requests a Read")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannel_Read_RdmaV1_PastEndOfFile_EndOfFile()
        {
            ReadAtOffsetAndExpectEndOfFile(SeedFileSize + 4096);
        }

        [TestMethod()]
        [TestCategory("Smb2OverRdmaChannelValidation")]
        [Description("Verify SMB2 READ over RDMA_V1 whose MinimumCount exceeds the bytes available fails with STATUS_END_OF_FILE.")]
        // WHAT: READ RDMA_V1 of SeedFileSize bytes starting at SeedFileSize / 2 with MinimumCount = SeedFileSize; only
        //       SeedFileSize / 2 bytes remain in the file.
        // WHY:  the object store returns fewer bytes than MinimumCount.
        // SPEC: [MS-SMB2] 3.3.5.12 - if the number of bytes read is less than MinimumCount the server MUST fail the READ with
        //       STATUS_END_OF_FILE.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.12 Receiving an SMB2 READ Request")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannel_Read_RdmaV1_MinimumCountExceedsAvailable_EndOfFile()
        {
            OpenClient(DefaultDialects, false, SeedFileSize);
            SmbdBufferDescriptorV1 descp = MakeDescriptor(SeedFileSize, SmbdBufferReadWrite.RDMA_WRITE_PERMISSION_FOR_READ_FILE);
            byte[] channelInfo = TypeMarshal.ToBytes<SmbdBufferDescriptorV1>(descp);

            NtStatus status = RawRead(SeedFileSize, SeedFileSize / 2, SeedFileSize, Channel_Values.CHANNEL_RDMA_V1, channelInfo);

            BaseTestSite.Assert.AreEqual<NtStatus>(
                NtStatus.STATUS_END_OF_FILE,
                status,
                "READ RDMA_V1 with MinimumCount larger than the available bytes should fail with STATUS_END_OF_FILE, actual {0}.",
                status);
        }
        #endregion

        #region Helpers
        private void ReadAtOffsetAndExpectEndOfFile(ulong offset)
        {
            OpenClient(DefaultDialects, false, SeedFileSize);
            SmbdBufferDescriptorV1 descp = MakeDescriptor(SeedFileSize, SmbdBufferReadWrite.RDMA_WRITE_PERMISSION_FOR_READ_FILE);

            READ_Response readResponse;
            byte[] readData;
            NtStatus status = (NtStatus)client.Smb2ReadOverRdmaChannel(
                offset,
                SeedFileSize,
                TypeMarshal.ToBytes<SmbdBufferDescriptorV1>(descp),
                out readResponse,
                out readData);

            BaseTestSite.Assert.AreEqual<NtStatus>(
                NtStatus.STATUS_END_OF_FILE,
                status,
                "READ RDMA_V1 at offset {0} of a {1}-byte file should fail with STATUS_END_OF_FILE, actual {2}.",
                offset,
                SeedFileSize,
                status);
        }

        private void ReadWithChannelAndExpectInvalidParameter(DialectRevision[] dialects, Channel_Values channel)
        {
            OpenClient(dialects, false, (int)SeedFileSize); // seeded so STATUS_END_OF_FILE cannot mask the channel validation
            SmbdBufferDescriptorV1 descp = MakeDescriptor(SeedFileSize, SmbdBufferReadWrite.RDMA_WRITE_PERMISSION_FOR_READ_FILE);

            READ_Response readResponse;
            byte[] readData;
            NtStatus status = (NtStatus)client.Smb2ReadOverRdmaChannel(
                0,
                SeedFileSize,
                TypeMarshal.ToBytes<SmbdBufferDescriptorV1>(descp),
                out readResponse,
                out readData,
                channel);

            AssertInvalidParameter(status, "READ with Channel " + (uint)channel);
        }

        private void WriteWithChannelAndExpectInvalidParameter(DialectRevision[] dialects, Channel_Values channel)
        {
            OpenClient(dialects, false, null);
            SmbdBufferDescriptorV1 descp = MakeDescriptor(SeedFileSize, SmbdBufferReadWrite.RDMA_READ_PERMISSION_FOR_WRITE_FILE);

            WRITE_Response writeResponse;
            NtStatus status = (NtStatus)client.Smb2WriteOverRdmaChannel(
                0,
                TypeMarshal.ToBytes<SmbdBufferDescriptorV1>(descp),
                SeedFileSize,
                out writeResponse,
                channel);

            AssertInvalidParameter(status, "WRITE with Channel " + (uint)channel);
        }

        private void AssertInvalidParameter(NtStatus status, string request)
        {
            BaseTestSite.Assert.AreEqual<NtStatus>(
                NtStatus.STATUS_INVALID_PARAMETER,
                status,
                "{0} should fail with STATUS_INVALID_PARAMETER, actual {1}.",
                request,
                status);
        }

        /// <summary>
        /// Connect (RDMA or TCP), negotiate one of the dialects, set up a session, tree connect and create a file.
        /// When seedSize is set the file is filled with that many bytes through an inline WRITE.
        /// </summary>
        private void OpenClient(DialectRevision[] dialects, bool overTcp, int? seedSize)
        {
            client = new Smb2OverSmbdTestClient(testConfig.Smb2ConnectionTimeout);
            client.ClientMaxReadWriteSize = testConfig.ClientMaxReadWriteSize;
            client.QueryNetworkInterfaceMaxOutputResponse = testConfig.QueryNetworkInterfaceMaxOutputResponse;
            clientOverTcp = overTcp;

            NtStatus status;
            if (overTcp)
            {
                string serverIp = string.IsNullOrEmpty(testConfig.ServerNonRNicIp) ? testConfig.ServerRNicIp : testConfig.ServerNonRNicIp;
                string clientIp = string.IsNullOrEmpty(testConfig.ClientNonRNicIp) ? testConfig.ClientRNicIp : testConfig.ClientNonRNicIp;
                if (string.IsNullOrEmpty(serverIp) || string.IsNullOrEmpty(clientIp))
                {
                    BaseTestSite.Assert.Inconclusive("Server/client NIC IP addresses are required to open an SMB2 connection over TCP.");
                }

                client.ConnectOverTCP(IPAddress.Parse(serverIp), IPAddress.Parse(clientIp));
            }
            else
            {
                IPAddress clientRnicIp = IPAddress.Parse(testConfig.ClientRNicIp);
                status = client.ConnectToServerOverRDMA(
                    testConfig.ClientRNicIp,
                    testConfig.ServerRNicIp,
                    testConfig.SmbdTcpPort,
                    clientRnicIp.AddressFamily,
                    testConfig.InboundEntries,
                    testConfig.OutboundEntries,
                    testConfig.InboundReadLimit,
                    testConfig.MaxReceiveSize,
                    testConfig.NDVersion);
                BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of ConnectToServerOverRDMA is {0}", status);

                SmbdNegotiateResponse negotiateResponse;
                status = client.SmbdNegotiate(
                    SmbdVersion.V1,
                    SmbdVersion.V1,
                    0,
                    (ushort)testConfig.SendCreditTarget,
                    (ushort)testConfig.ReceiveCreditMax,
                    (uint)testConfig.MaxSendSize,
                    (uint)testConfig.MaxReceiveSize,
                    (uint)testConfig.MaxFragmentedSize,
                    out negotiateResponse);
                BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SmbdNegotiate is {0}", status);
            }

            DialectRevision selectedDialect;
            status = (NtStatus)client.Smb2Negotiate(dialects, out selectedDialect);
            if (status != NtStatus.STATUS_SUCCESS || Array.IndexOf(dialects, selectedDialect) < 0)
            {
                BaseTestSite.Assert.Inconclusive("The SUT does not support the required SMB2 dialect(s) (negotiate status {0}, selected {1}).", status, selectedDialect);
            }

            status = (NtStatus)client.Smb2SessionSetup(
                testConfig.SecurityPackageForSmb2UserAuthentication,
                testConfig.DomainName,
                testConfig.UserName,
                testConfig.Password,
                testConfig.ServerName);
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMB2 Session Setup is {0}", status);

            status = (NtStatus)client.Smb2TreeConnect(testConfig.ServerName, testConfig.ShareFolder);
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMB2 Tree Connect is {0}", status);

            string fileName = CreateRandomFileName();
            status = (NtStatus)client.Smb2Create(fileName);
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMB2 Create is {0}", status);

            if (seedSize.HasValue)
            {
                WRITE_Response writeResponse;
                status = (NtStatus)client.Smb2Write(0, Smb2Utility.CreateRandomByteArray(seedSize.Value), out writeResponse);
                BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of the inline WRITE that seeds the file is {0}", status);
            }
        }

        /// <summary>
        /// Registers an RDMA buffer on an RDMA connection; on a TCP connection there is no RDMA provider, so a
        /// well-formed but unregistered descriptor is returned (the server must reject the request before using it).
        /// </summary>
        private SmbdBufferDescriptorV1 MakeDescriptor(uint length, SmbdBufferReadWrite flag)
        {
            if (clientOverTcp)
            {
                SmbdBufferDescriptorV1 dummy = new SmbdBufferDescriptorV1();
                dummy.Offset = 0;
                dummy.Token = 0x1234;
                dummy.Length = length;
                return dummy;
            }

            SmbdBufferDescriptorV1 descriptor;
            NtStatus status = client.SmbdRegisterBuffer(length, flag, testConfig.ReversedBufferDescriptor, out descriptor);
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "SmbdRegisterBuffer failed with status {0}", status);
            return descriptor;
        }

        /// <summary>
        /// The client keeps MessageId and SessionId private. Building (without sending) a one-credit READ request consumes
        /// the next MessageId, which is then used for a hand-built request.
        /// SMB2 header: MessageId at offset 24, SessionId at offset 40.
        /// </summary>
        private void NextIds(uint length, out ulong messageId, out ulong sessionId)
        {
            byte[] probe = client.Smb2GetReadRequestPackage(length);
            messageId = BitConverter.ToUInt64(probe, 24);
            sessionId = BitConverter.ToUInt64(probe, 40);
        }

        private NtStatus RawRead(uint length, ulong offset, uint minimumCount, Channel_Values channel, byte[] channelInfo)
        {
            ulong messageId, sessionId;
            NextIds(1, out messageId, out sessionId);

            byte[] content;
            Packet_Header header;
            READ_Response response;
            return (NtStatus)client.Read(
                1,
                64,
                Packet_Header_Flags_Values.FLAGS_SIGNED,
                messageId,
                sessionId,
                client.TreeId,
                length,
                offset,
                client.FileId,
                minimumCount,
                channel,
                0,
                channelInfo,
                out content,
                out header,
                out response);
        }

        /// <summary>
        /// Sends an RDMA-channel WRITE with RemainingBytes = remainingBytes (inline data fields 0).
        /// </summary>
        private NtStatus RawWrite(uint remainingBytes, Channel_Values channel, byte[] channelInfo)
        {
            if (channel == Channel_Values.CHANNEL_RDMA_V1 || channel == Channel_Values.CHANNEL_RDMA_V1_INVALIDATE)
            {
                SkipWhereRdmaV1WriteIsUnsupported();
            }

            ulong messageId, sessionId;
            NextIds(1, out messageId, out sessionId);

            Packet_Header header;
            WRITE_Response response;
            return (NtStatus)client.Write(
                1,
                64,
                Packet_Header_Flags_Values.FLAGS_SIGNED,
                messageId,
                sessionId,
                client.TreeId,
                0,
                client.FileId,
                channel,
                WRITE_Request_Flags_Values.None,
                channelInfo,
                new byte[remainingBytes],
                out header,
                out response);
        }

        private Smb2WriteRequestPacket BuildRawWriteRequest(uint remainingBytes, byte[] channelInfo)
        {
            ulong messageId, sessionId;
            NextIds(1, out messageId, out sessionId);

            Smb2WriteRequestPacket request = new Smb2WriteRequestPacket();
            request.Header.CreditCharge = 1;
            request.Header.Command = Smb2Command.WRITE;
            request.Header.CreditRequestResponse = 64;
            request.Header.Flags = Packet_Header_Flags_Values.FLAGS_SIGNED;
            request.Header.MessageId = messageId;
            request.Header.TreeId = client.TreeId;
            request.Header.SessionId = sessionId;
            request.PayLoad.Channel = Channel_Values.CHANNEL_RDMA_V1;
            request.PayLoad.WriteChannelInfoOffset = request.BufferOffset;
            request.PayLoad.WriteChannelInfoLength = (ushort)channelInfo.Length;
            request.PayLoad.RemainingBytes = remainingBytes;
            request.PayLoad.DataOffset = 0;
            request.PayLoad.Length = 0;
            request.PayLoad.Offset = 0;
            request.PayLoad.FileId = client.FileId;
            request.PayLoad.Flags = WRITE_Request_Flags_Values.None;
            request.Buffer = channelInfo;
            return request;
        }

        private NtStatus SendRawWrite(Smb2WriteRequestPacket request)
        {
            SkipWhereRdmaV1WriteIsUnsupported();
            client.SendPacket(request);
            Smb2WriteResponsePacket response = client.ExpectPacket<Smb2WriteResponsePacket>(request.Header.MessageId);
            return (NtStatus)response.Header.Status;
        }

        // WHAT: skip (Inconclusive) the RDMA_V1 WRITE negative tests on a Windows Server 2025 SUT.
        // WHY: that product rejects every RDMA_V1 WRITE with STATUS_INVALID_PARAMETER, so an expected
        //      STATUS_INVALID_PARAMETER cannot show that the rule under test was applied. Other implementations are unaffected.
        // SPEC: [MS-SMB2] 3.3.5.13 - the rule under test is only observable when a valid V1 WRITE is accepted.
        private void SkipWhereRdmaV1WriteIsUnsupported()
        {
            if (smbdAdapter.TestConfig.Platform >= Platform.WindowsServer2025)
            {
                BaseTestSite.Assert.Inconclusive("RDMA_V1 WRITE is rejected for every request by this Windows Server 2025 SUT; the negative case is not observable.");
            }
        }
        #endregion
    }
}
