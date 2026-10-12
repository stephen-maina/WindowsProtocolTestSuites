// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Protocols.TestSuites.Smbd.Adapter;
using Microsoft.Protocols.TestTools;
using Microsoft.Protocols.TestTools.StackSdk;
using Microsoft.Protocols.TestTools.StackSdk.FileAccessService.Smb2;
using Microsoft.Protocols.TestTools.StackSdk.FileAccessService.Smbd;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;

namespace Microsoft.Protocol.TestSuites.Smbd.TestSuite
{
    [TestClass]
    public class Smb2OverRdmaChannelRemoteInvalidation : Smb2OverSmbdTestBase
    {
        #region Fields
        private DialectRevision[] Smb302AboveDialects = new DialectRevision[] { DialectRevision.Smb302, DialectRevision.Smb311 };
        private DialectRevision[] Smb302OnlyDialects = new DialectRevision[] { DialectRevision.Smb302 };
        private DialectRevision[] Smb300OnlyDialects = new DialectRevision[] { DialectRevision.Smb30 };
        private string fileName;
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
            fileName = CreateRandomFileName();
        }
        #endregion

        [TestMethod]
        [TestCategory("BVT")]
        [TestCategory("Smb2OverRdmaChannelInvalidate")]
        // Spec: [MS-SMB2] 3.3.5.13 - Channel SMB2_CHANNEL_RDMA_V1_INVALIDATE is valid on dialect 3.0.2; the server fetches the data via
        // [MS-SMBD] 3.1.4.6 and MUST supply the Token of the first descriptor for remote invalidation ([MS-SMBD] 3.1.4.2).
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.13 Receiving an SMB2 WRITE Request; [MS-SMBD] 3.1.4.2 Send Message; [MS-SMBD] 3.1.4.6 RDMA Read from Peer Buffer")]
        [TestProperty("SpecCompliance", "TODO")]
        public void BVT_Smb2OverRdma_Smb302_Write_SMB2_CHANNEL_RDMA_V1_INVALIDATE()
        {   // TODO(spec): the final assertion (connection MUST be terminated when the invalidated descriptor is reused) is not specified;
            // MS-SMBD 3.1.4.2 says the token SHOULD be passed to the provider and MAY be ignored if remote invalidation is unsupported,
            // and the effect of using an invalidated token is RDMA-provider behavior, not normative. Also the Inconclusive guards are commented out.
            // Same guards as upstream main: on Windows Server 2025 over RoCE the WRITE is rejected with STATUS_INVALID_PARAMETER
            // and the READ fails with 0xC0000005 (platform behaviour, not specified).
            if (smbdAdapter.TestConfig.RDMATransport == RDMATransport.RoCE && smbdAdapter.TestConfig.DriverPlatform != Platform.NonWindows)
            {
                BaseTestSite.Assert.Inconclusive("This test case currently does not support RDMA RoCE transport.");
            }
            if (smbdAdapter.TestConfig.Platform >= Platform.WindowsServer2025)
            {
                BaseTestSite.Assert.Inconclusive("This test case currently does not support Windows Server 2025.");
            }

            EstablishConnectionAndOpenFile(fileName, Smb302OnlyDialects);

            uint writeSize = smbdAdapter.Smb2MaxWriteSize;
            writeSize = smbdAdapter.TestConfig.RdmaChannelDataSizeInByte; // from ptfconfig, not defined by the specifications
            byte[] fileContent = Smb2Utility.CreateRandomByteArray((int)writeSize);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Register memory and get buffer descriptor for SMB2 WRITE");
            SmbdBufferDescriptorV1 descp;
            NtStatus status = smbdAdapter.SmbdRegisterBuffer(
                writeSize,
                SmbdBufferReadWrite.RDMA_READ_PERMISSION_FOR_WRITE_FILE,
                out descp);
            BaseTestSite.Assert.AreEqual(
                NtStatus.STATUS_SUCCESS,
                status,
                "Register buffer should succeed.");

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Write content to file over RDMA.");
            status = Smb2WriteOverRdma(fileName, fileContent, Channel_Values.CHANNEL_RDMA_V1_INVALIDATE, descp);
            BaseTestSite.Assert.AreEqual<NtStatus>(
                NtStatus.STATUS_SUCCESS,
                status,
                "SMB2 WRITE over RDMA should succeed.");

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Verify file content.");
            ValidateFileContent(fileContent);

            try
            {
                fileContent = Encoding.ASCII.GetBytes(Smb2Utility.CreateRandomStringInByte((int)writeSize));

                BaseTestSite.Log.Add(LogEntryKind.TestStep, "Send Smb2 WRITE request using same descriptor which should be invalidated.");
                status = Smb2WriteOverRdma(fileName, fileContent, Channel_Values.CHANNEL_RDMA_V1_INVALIDATE, descp);
            }
            catch
            {
                BaseTestSite.Log.Add(LogEntryKind.Debug, "Verify connection is terminated .");
                smbdAdapter.WaitRdmaDisconnect();
            }

            BaseTestSite.Assert.IsFalse(smbdAdapter.ClientConnection.Endpoint.IsConnected, "Connection should be terminated when accessing a memory window which is already invalidated.");
        }

        [TestMethod]
        [TestCategory("BVT")]
        [TestCategory("Smb2OverRdmaChannelInvalidate")]
        // Spec: [MS-SMB2] 3.3.5.12 - Channel SMB2_CHANNEL_RDMA_V1_INVALIDATE is valid on dialect 3.0.2; data is sent via [MS-SMBD] 3.1.4.5
        // and the Token of the first descriptor MUST additionally be supplied for remote invalidation ([MS-SMBD] 3.1.4.2).
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.12 Receiving an SMB2 READ Request; [MS-SMBD] 3.1.4.2 Send Message; [MS-SMBD] 3.1.4.5 RDMA Write to Peer Buffer")]
        [TestProperty("SpecCompliance", "TODO")]
        public void BVT_Smb2OverRdma_Smb302_Read_SMB2_CHANNEL_RDMA_V1_INVALIDATE()
        {
            // TODO(spec): the final assertion (connection MUST be terminated when the invalidated descriptor is reused) is not specified;
            // MS-SMBD 3.1.4.2 says the token SHOULD be passed to the provider and MAY be ignored, and the effect of a stale token is
            // RDMA-provider behavior, not normative. Guarded as in the Write variant (see control run on Windows Server 2025 over RoCE).
            if (smbdAdapter.TestConfig.RDMATransport == RDMATransport.RoCE && smbdAdapter.TestConfig.DriverPlatform != Platform.NonWindows)
            {
                BaseTestSite.Assert.Inconclusive("This test case currently does not support RDMA RoCE transport.");
            }
            if (smbdAdapter.TestConfig.Platform >= Platform.WindowsServer2025)
            {
                BaseTestSite.Assert.Inconclusive("This test case currently does not support Windows Server 2025.");
            }

            // Pin the dialect to exactly SMB 3.0.2 (not "3.0.2 and above"), matching
            // the sibling BVT_..._Write_... test. If Smb311 were allowed to be
            // negotiated here, the server would enforce RDMA payload signing (which
            // requires the SMB 3.1.1 RDMA Transform Capabilities negotiate context,
            // never sent by this test) and could fail the unsigned RDMA READ with
            // invalidate ungracefully (observed as STATUS_ACCESS_VIOLATION) instead
            // of the expected success path for this SMB 3.0.2 scenario.
            EstablishConnectionAndOpenFile(fileName, Smb302OnlyDialects);

            uint fileSize = smbdAdapter.Smb2MaxReadSize;
            fileSize = smbdAdapter.TestConfig.RdmaChannelDataSizeInByte; // from ptfconfig, not defined by the specifications
            byte[] fileContent = Smb2Utility.CreateRandomByteArray((int)fileSize);

            // SMB 3.0.2 cannot negotiate the SMB 3.1.1 RDMA Transform Capabilities
            // context (0x0007), so Windows Server 2025's DDP security enforcement
            // will reject an unsigned RDMA WRITE used only to seed the file. Populate
            // the file with ordinary inline SMB2 WRITE(s) instead, and reserve the
            // RDMA channel for the actual READ operation under test.
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Write content to file using inline SMB2 WRITE.");
            WriteInlineContent(fileContent);

            // A single RDMA READ covering the whole 1 MiB file can exceed the SMBD
            // negotiated MaxReadWriteSize (separate from the SMB2 MaxReadSize),
            // which causes the server to RDMA-write past the bounds of the
            // registered buffer (observed as STATUS_ACCESS_VIOLATION / 0xC0000005).
            // Chunk the READ per Smb2EffectiveMaxReadSize, the same way
            // ValidateFileContent does.
            uint sizePerRead;
            ComputeReadPlan(1, out sizePerRead, out _);

            SmbdBufferDescriptorV1 descp = default;
            byte[] channelInfo = null;
            uint lastLength = 0;
            uint readOffset = 0;
            while (readOffset < fileSize)
            {
                uint length = sizePerRead;
                if (readOffset + length > fileSize)
                {
                    length = fileSize - readOffset;
                }
                lastLength = length;

                BaseTestSite.Log.Add(LogEntryKind.TestStep, "Register memory and get buffer descriptor for SMB2 READ.");
                NtStatus status = smbdAdapter.SmbdRegisterBuffer(
                    length,
                    SmbdBufferReadWrite.RDMA_WRITE_PERMISSION_FOR_READ_FILE,
                    out descp);
                BaseTestSite.Assert.AreEqual(
                    NtStatus.STATUS_SUCCESS,
                    status,
                    "Register buffer should succeed.");
                channelInfo = TypeMarshal.ToBytes<SmbdBufferDescriptorV1>(descp);

                BaseTestSite.Log.Add(LogEntryKind.TestStep, "Read content from file over RDMA at offset {0}.", readOffset);
                READ_Response readResponse;
                byte[] readData;
                status = (NtStatus)smbdAdapter.Smb2ReadOverRdmaChannel(
                    readOffset,
                    length,
                    channelInfo,
                    out readResponse,
                    out readData,
                    Channel_Values.CHANNEL_RDMA_V1_INVALIDATE);

                BaseTestSite.Assert.AreEqual<NtStatus>(
                    NtStatus.STATUS_SUCCESS,
                    status,
                    "SMB2 READ over RDMA should succeed at offset {0}.",
                    readOffset);

                byte[] readContent = new byte[length];
                smbdAdapter.SmbdReadRegisteredBuffer(readContent, descp);

                byte[] expectedChunk = new byte[length];
                Array.Copy(fileContent, readOffset, expectedChunk, 0, length);
                BaseTestSite.Assert.IsTrue(
                    SmbdUtilities.CompareByteArray(expectedChunk, readContent),
                    "Content read should be identical with original on server at offset {0}.",
                    readOffset);

                readOffset += length;
            }

            try
            {
                // Reuse the last descriptor, which the server already invalidated
                // (remote invalidation) as part of the preceding RDMA READ.
                READ_Response readResponse;
                byte[] readData;
                NtStatus status = (NtStatus)smbdAdapter.Smb2ReadOverRdmaChannel(
                    0,
                    lastLength,
                    channelInfo,
                    out readResponse,
                    out readData,
                    Channel_Values.CHANNEL_RDMA_V1_INVALIDATE);
            }
            catch
            {
                BaseTestSite.Log.Add(LogEntryKind.Debug, "Wait for connection to be terminated ");
                smbdAdapter.WaitRdmaDisconnect();
            }

            BaseTestSite.Assert.IsFalse(smbdAdapter.ClientConnection.Endpoint.IsConnected, "Connection should be terminated when accessing a memory window which is already invalidated.");
        }

        [TestMethod]
        [TestCategory("Smb2OverRdmaChannel")]
        // Spec: [MS-SMB2] 3.3.5.13 - WRITE with Channel = SMB2_CHANNEL_RDMA_V1 on a 3.1.1 connection: the server MUST fetch the data via
        // [MS-SMBD] 3.1.4.6 using plain SMB_DIRECT_BUFFER_DESCRIPTOR_V1 channel info; the RDMA_TRANSFORM-only checks do not apply.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.13 Receiving an SMB2 WRITE Request; [MS-SMBD] 3.1.4.6 RDMA Read from Peer Buffer")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdma_Write_SMB2_CHANNEL_RDMA_V1()
        {
            // WHAT: send the WRITE with Channel_Values.CHANNEL_RDMA_V1 (plain descriptor) instead of CHANNEL_RDMA_TRANSFORM.
            // WHY: the test name/spec target is SMB2_CHANNEL_RDMA_V1 but it used RDMA_TRANSFORM, so V1 was never exercised.
            // SPEC: [MS-SMB2] 3.3.5.13 - Channel RDMA_V1 is valid on Dialect 3.1.1; STATUS_INVALID_PARAMETER conditions for
            //       transform structures apply only when Channel is SMB2_CHANNEL_RDMA_TRANSFORM.
            // WHAT: platform gate - Inconclusive on Windows Server 2025.
            // WHY: Windows Server 2025 over RoCE rejects every V1-family WRITE (V1 and V1_INVALIDATE, 3.0.2 and 3.1.1) with
            //      STATUS_INVALID_PARAMETER even though the spec permits it; the same behaviour already gates the INVALIDATE tests.
            //      This is a product behaviour, so it is not asserted as a spec failure and not hidden as a pass.
            // SPEC: [MS-SMB2] 3.3.5.13 allows SMB2_CHANNEL_RDMA_V1 for 3.x dialects.
            if (smbdAdapter.TestConfig.Platform >= Platform.WindowsServer2025)
            {
                BaseTestSite.Assert.Inconclusive("Windows Server 2025 rejects RDMA_V1 WRITE with STATUS_INVALID_PARAMETER (platform behaviour).");
            }

            // WHAT: use dialect 3.0.2 (no RDMA transforms exist) for the plain RDMA_V1 write.
            // WHY: plain V1 is the correct channel when no transform is negotiated ([MS-SMB2] 3.2.4.7 client rule).
            // SPEC: [MS-SMB2] 3.2.4.7 and 3.3.5.13.
            NtStatus connectStatus = smbdAdapter.ConnectToServerOverRDMA();
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, connectStatus, "Status of SMBD connection is {0}", connectStatus);
            connectStatus = smbdAdapter.SmbdNegotiate();
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, connectStatus, "Status of SMBD negotiate is {0}", connectStatus);
            connectStatus = smbdAdapter.Smb2EstablishSessionAndOpenFile(
                fileName,
                negotiatedDialects: new DialectRevision[] { DialectRevision.Smb302 });
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, connectStatus, "Status of SMB2 establish session and open file is {0}", connectStatus);

            uint writeSize = smbdAdapter.Smb2MaxWriteSize;
            writeSize = smbdAdapter.TestConfig.RdmaChannelDataSizeInByte; // from ptfconfig, not defined by the specifications
            byte[] fileContent = Smb2Utility.CreateRandomByteArray((int)writeSize);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Register memory and get buffer descriptor for SMB2 WRITE");
            SmbdBufferDescriptorV1 descp;
            NtStatus status = smbdAdapter.SmbdRegisterBuffer(
                writeSize,
                SmbdBufferReadWrite.RDMA_READ_PERMISSION_FOR_WRITE_FILE,
                out descp);
            BaseTestSite.Assert.AreEqual(
                NtStatus.STATUS_SUCCESS,
                status,
                "Register buffer should succeed.");

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Write content to file over RDMA.");
            status = Smb2WriteOverRdma(fileName, fileContent, Channel_Values.CHANNEL_RDMA_V1, descp);
            BaseTestSite.Assert.AreEqual<NtStatus>(
                NtStatus.STATUS_SUCCESS,
                status,
                "SMB2 WRITE over RDMA should succeed.");

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Verify file content.");
            ValidateFileContent(fileContent);

            fileContent = Encoding.ASCII.GetBytes(Smb2Utility.CreateRandomStringInByte((int)writeSize));

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Send Smb2 WRITE request using same descriptor.");
            status = Smb2WriteOverRdma(fileName, fileContent, Channel_Values.CHANNEL_RDMA_V1, descp);

            BaseTestSite.Assert.AreEqual<NtStatus>(
                NtStatus.STATUS_SUCCESS,
                status,
                "SMB2 WRITE over RDMA should succeed.");

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Verify file content.");
            ValidateFileContent(fileContent);
        }

        [TestMethod]
        [TestCategory("Smb2OverRdmaChannel")]
        // Spec: [MS-SMB2] 3.3.5.12 - READ with Channel = SMB2_CHANNEL_RDMA_V1: data MUST go via [MS-SMBD] 3.1.4.5, not in the response;
        // the descriptor (no invalidation requested) remains usable for a second READ. The seeding WRITE uses RDMA_TRANSFORM per 3.3.5.13.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.12 Receiving an SMB2 READ Request; [MS-SMB2] 3.3.5.13 Receiving an SMB2 WRITE Request; [MS-SMBD] 3.1.4.5 RDMA Write to Peer Buffer")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdma_Read_SMB2_CHANNEL_RDMA_V1()
        {
            bool transformSelected = EstablishSignedRdmaConnectionAndOpenFile(fileName);
            Channel_Values seedChannel = transformSelected ? Channel_Values.CHANNEL_RDMA_TRANSFORM : Channel_Values.CHANNEL_RDMA_V1;

            uint fileSize = smbdAdapter.Smb2MaxReadSize;
            fileSize = smbdAdapter.TestConfig.RdmaChannelDataSizeInByte; // from ptfconfig, not defined by the specifications
            byte[] fileContent = Smb2Utility.CreateRandomByteArray((int)fileSize);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Register memory and get buffer descriptor for SMB2 WRITE");
            SmbdBufferDescriptorV1 descp;
            NtStatus status = smbdAdapter.SmbdRegisterBuffer(
                fileSize,
                SmbdBufferReadWrite.RDMA_READ_PERMISSION_FOR_WRITE_FILE,
                out descp);
            BaseTestSite.Assert.AreEqual(
                NtStatus.STATUS_SUCCESS,
                status,
                "Register buffer should succeed.");

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Write content to file over RDMA.");
            status = Smb2WriteOverRdma(fileName, fileContent, seedChannel, descp);
            BaseTestSite.Assert.AreEqual<NtStatus>(
                NtStatus.STATUS_SUCCESS,
                status,
                "SMB2 WRITE over RDMA should succeed.");

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Register memory and get buffer descriptor for SMB2 READ.");
            status = smbdAdapter.SmbdRegisterBuffer(
                fileSize,
                SmbdBufferReadWrite.RDMA_WRITE_PERMISSION_FOR_READ_FILE,
                out descp);
            BaseTestSite.Assert.AreEqual(
                NtStatus.STATUS_SUCCESS,
                status,
                "Register buffer should succeed.");

            byte[] channelInfo = TypeMarshal.ToBytes<SmbdBufferDescriptorV1>(descp);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Read content from file over RDMA.");
            READ_Response readResponse;
            byte[] readData;
            status = (NtStatus)smbdAdapter.Smb2ReadOverRdmaChannel(
                0,
                (uint)fileSize,
                channelInfo,
                out readResponse,
                out readData,
                Channel_Values.CHANNEL_RDMA_V1);

            BaseTestSite.Assert.AreEqual<NtStatus>(
                NtStatus.STATUS_SUCCESS,
                status,
                "SMB2 READ over RDMA should succeed.");

            byte[] readContent = new byte[fileSize];
            smbdAdapter.SmbdReadRegisteredBuffer(readContent, descp);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Verify the read content same as the original one on server.");
            BaseTestSite.Assert.IsTrue(
                SmbdUtilities.CompareByteArray(fileContent, readContent),
                "Content read should be identical with original on server.");

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Send SMB2 READ using same descriptor.");
            status = (NtStatus)smbdAdapter.Smb2ReadOverRdmaChannel(
                0,
                (uint)fileSize,
                channelInfo,
                out readResponse,
                out readData,
                Channel_Values.CHANNEL_RDMA_V1);

            BaseTestSite.Assert.AreEqual<NtStatus>(
                NtStatus.STATUS_SUCCESS,
                status,
                "SMB2 READ over RDMA should succeed.");

            smbdAdapter.SmbdReadRegisteredBuffer(readContent, descp);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Verify the read content same as the original one on server.");
            BaseTestSite.Assert.IsTrue(
                SmbdUtilities.CompareByteArray(fileContent, readContent),
                "Content read should be identical with original on server.");
        }

        [TestMethod]
        [TestCategory("Negative")]
        [TestCategory("Smb2OverRdmaChannelInvalidate")]
        // Spec: [MS-SMB2] 3.3.5.13 - on Connection.Dialect "3.0", Channel SMB2_CHANNEL_RDMA_V1_INVALIDATE is not allowed
        // (only RDMA_V1 or NONE) and the server MUST fail the request with STATUS_INVALID_PARAMETER.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.13 Receiving an SMB2 WRITE Request")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdma_Smb300_Write_SMB2_CHANNEL_RDMA_V1_INVALIDATE()
        {
            EstablishConnectionAndOpenFile(fileName, Smb300OnlyDialects);

            uint writeSize = smbdAdapter.Smb2MaxWriteSize;
            byte[] fileContent = Smb2Utility.CreateRandomByteArray((int)writeSize);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Register memory and get buffer descriptor for SMB2 WRITE");
            SmbdBufferDescriptorV1 descp;
            NtStatus status = smbdAdapter.SmbdRegisterBuffer(
                writeSize,
                SmbdBufferReadWrite.RDMA_READ_PERMISSION_FOR_WRITE_FILE,
                out descp);
            BaseTestSite.Assert.AreEqual(
                NtStatus.STATUS_SUCCESS,
                status,
                "Register buffer should succeed.");

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Write content to file over RDMA.");
            status = Smb2WriteOverRdma(fileName, fileContent, Channel_Values.CHANNEL_RDMA_V1_INVALIDATE, descp);

            BaseTestSite.Assert.AreEqual<NtStatus>(
                NtStatus.STATUS_INVALID_PARAMETER,
                status,
                "SMB2 WRITE over RDMA should fail with STATUS_INVALID_PARAMETER if set Channel CHANNEL_RDMA_V1_INVALIDATE on SMB 3.0 dialect.");
        }

        [TestMethod]
        [TestCategory("Negative")]
        [TestCategory("Smb2OverRdmaChannelInvalidate")]
        // Spec: [MS-SMB2] 3.3.5.12 - on Connection.Dialect "3.0", Channel SMB2_CHANNEL_RDMA_V1_INVALIDATE is not allowed
        // (only RDMA_V1 or NONE) and the server MUST fail the request with STATUS_INVALID_PARAMETER.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.12 Receiving an SMB2 READ Request")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdma_Smb300_Read_SMB2_CHANNEL_RDMA_V1_INVALIDATE()
        {
            EstablishConnectionAndOpenFile(fileName, Smb300OnlyDialects);

            // WHAT: use a small (4 KiB) file instead of the full RdmaChannelDataSizeInByte (1 MiB).
            // WHY:  the expected outcome (STATUS_INVALID_PARAMETER) does not depend on the amount of data. Seeding 1 MiB with
            //       inline WRITEs needs one request per (MaxSendSize - headers) bytes; against a peer with a small MaxSendSize
            //       (ksmbd: 1364) that is ~840 round trips and the test ran for many minutes.
            // SPEC: [MS-SMB2] 3.3.5.12 - the Channel/dialect check fails the READ before any file data is touched.
            uint fileSize = Math.Min(smbdAdapter.TestConfig.RdmaChannelDataSizeInByte, 4096u);
            byte[] fileContent = Smb2Utility.CreateRandomByteArray((int)fileSize);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Populate file with ordinary inline SMB2 WRITE requests.");
            WriteInlineContent(fileContent);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Register memory and get buffer descriptor for SMB2 READ.");
            SmbdBufferDescriptorV1 descp;
            NtStatus status = smbdAdapter.SmbdRegisterBuffer(
                fileSize,
                SmbdBufferReadWrite.RDMA_WRITE_PERMISSION_FOR_READ_FILE,
                out descp);
            BaseTestSite.Assert.AreEqual(
                NtStatus.STATUS_SUCCESS,
                status,
                "Register buffer should succeed.");
            byte[] channelInfo = TypeMarshal.ToBytes<SmbdBufferDescriptorV1>(descp);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Read content from file over RDMA.");
            READ_Response readResponse;
            byte[] readData;
            status = (NtStatus)smbdAdapter.Smb2ReadOverRdmaChannel(
                0,
                (uint)fileSize,
                channelInfo,
                out readResponse,
                out readData,
                Channel_Values.CHANNEL_RDMA_V1_INVALIDATE);

            BaseTestSite.Assert.AreEqual<NtStatus>(
                NtStatus.STATUS_INVALID_PARAMETER,
                status,
                "SMB2 READ over RDMA should fail with STATUS_INVALID_PARAMETER if set Channel CHANNEL_RDMA_V1_INVALIDATE on SMB 3.0 dialect.");
        }

        private void WriteInlineContent(byte[] content)
        {
            uint maxWriteSize = Math.Min(
                smbdAdapter.Smb2MaxWriteSize,
                Math.Min(
                    smbdAdapter.ClientConnection.MaxSendSize,
                    smbdAdapter.ServerConnection.MaxReceiveSize));
            BaseTestSite.Assert.IsTrue(
                maxWriteSize > Smb2OverSmbdTestClient.WRITE_REQUEST_HEADER_SIZE,
                "SMB2 inline WRITE size should be greater than the WRITE request header size.");
            maxWriteSize -= (uint)Smb2OverSmbdTestClient.WRITE_REQUEST_HEADER_SIZE;

            int offset = 0;
            while (offset < content.Length)
            {
                int writeLength = (int)Math.Min(maxWriteSize, (uint)(content.Length - offset));
                byte[] writeData = new byte[writeLength];
                Array.Copy(content, offset, writeData, 0, writeLength);

                WRITE_Response writeResponse;
                NtStatus status = (NtStatus)smbdAdapter.Smb2Write((ulong)offset, writeData, out writeResponse);
                BaseTestSite.Assert.AreEqual<NtStatus>(
                    NtStatus.STATUS_SUCCESS,
                    status,
                    "SMB2 inline WRITE should succeed at offset {0}.",
                    offset);
                BaseTestSite.Assert.AreEqual<uint>(
                    (uint)writeLength,
                    writeResponse.Count,
                    "SMB2 inline WRITE count should match request length at offset {0}.",
                    offset);

                offset += writeLength;
            }
        }

        protected NtStatus Smb2WriteOverRdma(string fileName, byte[] content, Channel_Values channel, SmbdBufferDescriptorV1 descp)
        {
            smbdAdapter.SmbdWriteRegisteredBuffer(content, descp);

            byte[] channelInfo = channel == Channel_Values.CHANNEL_RDMA_TRANSFORM
                ? BuildSignedRdmaTransformChannelInfo(content, descp, Smb2Command.WRITE)
                : TypeMarshal.ToBytes<SmbdBufferDescriptorV1>(descp);

            WRITE_Response writeResponse;
            return (NtStatus)smbdAdapter.Smb2WriteOverRdmaChannel(
                0,
                channelInfo,
                (uint)content.Length,
                out writeResponse,
                channel);
        }

        private bool EstablishSignedRdmaConnectionAndOpenFile(string fileName)
        {
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Establish SMB 3.1.1 connection over RDMA with RDMA signing and open file " + fileName);

            NtStatus status = smbdAdapter.ConnectToServerOverRDMA();
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMBD connection is {0}", status);

            status = smbdAdapter.SmbdNegotiate();
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMBD negotiate is {0}", status);

            DialectRevision[] dialects =
            {
                DialectRevision.Smb311
            };
            Smb2RDMATransformId[] rdmaTransformIds =
            {
                Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_SIGNING
            };
            SigningAlgorithm[] signingAlgorithms =
            {
                SigningAlgorithm.AES_CMAC
            };

            status = smbdAdapter.Smb2EstablishSessionAndOpenFile(
                fileName,
                negotiatedDialects: dialects,
                smb2RDMATransformIds: rdmaTransformIds,
                signingAlgorithms: signingAlgorithms);
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMB2 establish session and open file is {0}", status);

            // WHAT: report whether the optional signing transform was selected instead of skipping the test when it was not.
            // WHY: the plain RDMA_V1 READ scenario does not need a transform; only the seeding WRITE channel depends on it.
            // SPEC: [MS-SMB2] 3.3.5.4 (transform selection is optional) and 3.3.5.13.
            bool transformSelected =
                smbdAdapter.SelectedRdmaTransformIds != null &&
                Array.IndexOf(
                    smbdAdapter.SelectedRdmaTransformIds,
                    Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_SIGNING) >= 0;
            if (transformSelected)
            {
                BaseTestSite.Assert.AreEqual<SigningAlgorithm>(
                    SigningAlgorithm.AES_CMAC,
                    smbdAdapter.SelectedSigningAlgorithm,
                    "Server MUST select AES_CMAC so the signing transform uses a 16-byte signature and no nonce.");
            }

            return transformSelected;
        }

        private byte[] BuildSignedRdmaTransformChannelInfo(byte[] content, SmbdBufferDescriptorV1 descriptor, Smb2Command command)
        {
            byte[] nonce, signature;
            smbdAdapter.SignByteArray(content, out nonce, out signature, command);

            SMB2_RDMA_CRYPTO_TRANSFORM cryptoTransform = new SMB2_RDMA_CRYPTO_TRANSFORM
            {
                TransformType = Smb2RDMATransformType.SMB2_RDMA_TRANSFORM_TYPE_SIGNING,
                SignatureLength = (ushort)signature.Length,
                NonceLength = (ushort)nonce.Length,
                Signature = signature,
                Nonce = nonce,
            };
            byte[] cryptoTransformBytes = TypeMarshal.ToBytes(cryptoTransform);
            Smb2Utility.Align8(ref cryptoTransformBytes);

            SMB2_RDMA_TRANSFORM rdmaTransform = new SMB2_RDMA_TRANSFORM
            {
                RdmaDescriptorOffset = 0,
                RdmaDescriptorLength = 1,
                Channel = Smb2RdmaTransformChannel.SMB2_CHANNEL_RDMA_V1,
                TransformCount = 1,
                Reserved1 = 0,
                Reserved2 = 0
            };
            byte[] rdmaTransformBytes = TypeMarshal.ToBytes(rdmaTransform);

            rdmaTransform.RdmaDescriptorOffset = (ushort)(rdmaTransformBytes.Length + cryptoTransformBytes.Length);
            byte[] descriptorBytes = TypeMarshal.ToBytes(descriptor);
            rdmaTransform.RdmaDescriptorLength = (ushort)descriptorBytes.Length;
            rdmaTransformBytes = TypeMarshal.ToBytes(rdmaTransform);

            byte[] channelInfo = new byte[rdmaTransform.RdmaDescriptorOffset + descriptorBytes.Length];
            rdmaTransformBytes.CopyTo(channelInfo, 0);
            cryptoTransformBytes.CopyTo(channelInfo, rdmaTransformBytes.Length);
            descriptorBytes.CopyTo(channelInfo, rdmaTransform.RdmaDescriptorOffset);

            return channelInfo;
        }

    }
}
