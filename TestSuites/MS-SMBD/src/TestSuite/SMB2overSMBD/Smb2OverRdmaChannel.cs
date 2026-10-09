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
    public class Smb2OverRdmaChannel : Smb2OverSmbdTestBase
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
        [TestCategory("Smb2OverRdmaChannel")]
        [Description("Verify SMB2 can read file with the effective maximum single RDMA READ size over RDMA channel")]
        // Spec: [MS-SMB2] 3.3.5.12 - for Channel SMB2_CHANNEL_RDMA_V1 the server MUST NOT copy the data into the
        // response (DataLength = 0, DataRemaining = bytes read) and MUST send it via [MS-SMBD] 3.1.4.5 (RDMA Write)
        // using the buffer descriptors from the request.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.12 Receiving an SMB2 READ Request; [MS-SMBD] 3.1.4.5 RDMA Write to Peer Buffer")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void BVT_Smb2OverRdmaChannel_ReadLargeFile()
        {
            ReadOverRdma();
        }

        [TestMethod()]
        [TestCategory("BVT")]
        [TestCategory("Smb2OverRdmaChannel")]
        [Description("Verify SMB2 can write file with the effective maximum single RDMA WRITE size over RDMA channel")]
        // Spec: [MS-SMB2] 3.3.5.13 - with Channel SMB2_CHANNEL_RDMA_V1/_TRANSFORM the server MUST fetch the data via
        // [MS-SMBD] 3.1.4.6 (RDMA Read) using the descriptors in WriteChannelInfo/RdmaDescriptor*; on success Count = bytes written.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.13 Receiving an SMB2 WRITE Request; [MS-SMBD] 3.1.4.6 RDMA Read from Peer Buffer")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void BVT_Smb2OverRdmaChannel_WriteLargeFile()
        {
            WriteOverRdma();
        }

        [TestMethod()]
        [TestCategory("Smb2OverRdmaChannel")]
        [Description("Verify SMB2 can read file with the effective maximum single RDMA READ size over RDMA channel with multiple SMBD READ requests and responses.")]
        // Spec: [MS-SMB2] 3.3.5.12 - repeated RDMA_V1 reads; each response MUST carry DataLength = 0 and
        // DataRemaining = bytes read, data delivered through [MS-SMBD] 3.1.4.5.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.12 Receiving an SMB2 READ Request; [MS-SMBD] 3.1.4.5 RDMA Write to Peer Buffer")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannel_ReadMultipleOperation()
        {
            const uint OPERATION_COUNT = 64;
            ReadOverRdma(OPERATION_COUNT);
        }

        [TestMethod()]
        [TestCategory("Smb2OverRdmaChannel")]
        [Description("Verify SMB2 can write file with the effective maximum single RDMA WRITE size over RDMA channel with multiple SMBD WRITE requests and responses.")]
        // Spec: [MS-SMB2] 3.3.5.13 - repeated RDMA writes (SMB2_CHANNEL_RDMA_TRANSFORM with signing negotiated on 3.1.1);
        // server MUST obtain data via [MS-SMBD] 3.1.4.6, verify the signature and return Count = bytes written.
        // The Windows Server 2025 Inconclusive guard is a SUT-specific skip, not a spec requirement.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.13 Receiving an SMB2 WRITE Request; [MS-SMBD] 3.1.4.6 RDMA Read from Peer Buffer")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannel_WriteMultipleOperation()
        {
            if (smbdAdapter.TestConfig.Platform >= Platform.WindowsServer2025)
            {
                BaseTestSite.Assert.Inconclusive("This test case currently does not support Windows Server 2025.");
            }

            const uint OPERATION_COUNT = 64;
            WriteOverRdma(OPERATION_COUNT);
        }

        [TestMethod()]
        [TestCategory("Smb2OverRdmaChannel")]
        [Description("Verify server can work with SMB2 READ and WRITE over RDMA channel with multiple buffer descriptors in channel information.")]
        // Spec: [MS-SMB2] 3.3.5.13 - the data is gathered from an ARRAY of SMB_DIRECT_BUFFER_DESCRIPTOR_V1; server MUST fail
        // with STATUS_INVALID_PARAMETER only if the first descriptor Length is 0 or the sum of Lengths < RemainingBytes.
        // [MS-SMB2] 3.3.5.12 - on a 3.1.1 connection with RDMATransformIds non-empty the READ response Buffer carries
        // SMB2_RDMA_TRANSFORM + SMB2_RDMA_CRYPTO_TRANSFORM (signing when the request is signed), flag
        // SMB2_READFLAG_RESPONSE_RDMA_TRANSFORM set, DataLength = size of those structures.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.13 Receiving an SMB2 WRITE Request; [MS-SMB2] 3.3.5.12 Receiving an SMB2 READ Request; [MS-SMB2] 2.2.43 SMB2_RDMA_TRANSFORM; [MS-SMBD] 2.2.3.1 Buffer Descriptor V1 Structure")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannel_ReadWriteMultipleBufferDescriptorList()
        {
            if (smbdAdapter.TestConfig.Platform >= Platform.WindowsServer2025)
            {
                BaseTestSite.Assert.Inconclusive("This test case currently does not support Windows Server 2025.");
            }

            // Advertise RDMA signing via the SMB2_RDMA_TRANSFORM_CAPABILITIES (0x0007) negotiate
            // context, and verify the server selects it, before sending a transformed WRITE.
            Smb2RDMATransformId[] rdmaTransformIds =
            {
                Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_SIGNING
            };
            SigningAlgorithm[] signingAlgorithms =
            {
                SigningAlgorithm.AES_CMAC
            };

            InitSmbdConnectionForTestCases(
                smbdAdapter.TestConfig.TestFileName_LargeFile,
                rdmaTransformIds,
                signingAlgorithms);
            // RDMA transform is optional ([MS-SMB2] 2.2.3.1.7 / 3.3.5.4): skip when the server does not select it.
            BaseTestSite.Assume.IsTrue(
                smbdAdapter.SelectedRdmaTransformIds != null &&
                Array.IndexOf(
                    smbdAdapter.SelectedRdmaTransformIds,
                    Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_SIGNING) >= 0,
                "Server does not select SMB2_RDMA_TRANSFORM_SIGNING in the SMB2_RDMA_TRANSFORM_CAPABILITIES negotiate context.");
            BaseTestSite.Assert.AreEqual<SigningAlgorithm>(
                SigningAlgorithm.AES_CMAC,
                smbdAdapter.SelectedSigningAlgorithm,
                "Server MUST select AES_CMAC so the signing transform contains a 16-byte signature and no nonce.");

            uint size = smbdAdapter.Smb2MaxReadSize;
            if (size > smbdAdapter.Smb2MaxWriteSize)
            {
                size = smbdAdapter.Smb2MaxWriteSize;
            }
            // Data size is not defined by the specifications; it comes from the RdmaChannelDataSizeInByte ptfconfig
            // property and should be large enough to test multiple buffer descriptors in channel info.
            size = smbdAdapter.TestConfig.RdmaChannelDataSizeInByte;
            const int rdmaTransformHeaderSize = 16;
            const int rdmaCryptoHeaderSize = 8;
            const int signatureSize = 16;
            const int rdmaDescriptorOffset =
                rdmaTransformHeaderSize +
                rdmaCryptoHeaderSize +
                signatureSize;

            int bufferCount =
                (ushort.MaxValue - rdmaDescriptorOffset) /
                SmbdBufferDescriptorV1.SIZE;
            int descriptorListLength = SmbdBufferDescriptorV1.SIZE * bufferCount;
            byte[] descriptorListBytes = new byte[descriptorListLength];

            // Distribute the data over every descriptor without describing bytes beyond the 1 MiB payload.
            int baseBufferLength = (int)size / bufferCount;
            int extraBytes = (int)size % bufferCount;
            uint[] bufferLengths = new uint[bufferCount];
            for (int i = 0; i < bufferCount; ++i)
            {
                bufferLengths[i] = (uint)(baseBufferLength + (i < extraBytes ? 1 : 0));
            }

            byte[] writeContent = Encoding.ASCII.GetBytes(Smb2Utility.CreateRandomStringInByte((int)size));
            byte[] readContent = new byte[size];
            NtStatus status;

            #region SMB2 Write file
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Register memory and get buffer descriptor for SMB2 WRITE");
            SmbdBufferDescriptorV1[] writeDescp = new SmbdBufferDescriptorV1[bufferCount];
            for (int i = 0; i < bufferCount; ++i)
            {
                writeDescp[i] = RegisterBufferAndAssert(
                    bufferLengths[i],
                    SmbdBufferReadWrite.RDMA_READ_PERMISSION_FOR_WRITE_FILE);
                byte[] descriptorBlock = TypeMarshal.ToBytes<SmbdBufferDescriptorV1>(writeDescp[i]);
                Array.Copy(
                    descriptorBlock,
                    0,
                    descriptorListBytes,
                    SmbdBufferDescriptorV1.SIZE * i,
                    SmbdBufferDescriptorV1.SIZE);
            }
            // copy write content
            int writeOffset = 0;
            for (int index = 0; index < bufferCount; ++index)
            {
                int length = (int)bufferLengths[index];
                byte[] buffer = new byte[length];
                Array.Copy(writeContent, writeOffset, buffer, 0, length);
                smbdAdapter.SmbdWriteRegisteredBuffer(buffer, writeDescp[index]);
                writeOffset += length;
            }

            // Since the connection negotiated SMB2_RDMA_TRANSFORM_SIGNING and the session is signed,
            // the WRITE request MUST wrap the (multiple) buffer descriptors in an SMB2_RDMA_TRANSFORM
            // header followed by a signing SMB2_RDMA_CRYPTO_TRANSFORM with a valid signature, and be
            // sent using Channel = SMB2_CHANNEL_RDMA_TRANSFORM (0x00000003).
            byte[] nonce, signature;
            smbdAdapter.SignByteArray(writeContent, out nonce, out signature, Smb2Command.WRITE);

            SMB2_RDMA_CRYPTO_TRANSFORM writeCryptoTransform = new SMB2_RDMA_CRYPTO_TRANSFORM
            {
                TransformType = Smb2RDMATransformType.SMB2_RDMA_TRANSFORM_TYPE_SIGNING,
                SignatureLength = (ushort)signature.Length,
                NonceLength = (ushort)nonce.Length,
                Signature = signature,
                Nonce = nonce,
            };
            byte[] writeCryptoTransformBytes = TypeMarshal.ToBytes(writeCryptoTransform);
            Smb2Utility.Align8(ref writeCryptoTransformBytes);
            BaseTestSite.Assert.AreEqual<int>(
                rdmaCryptoHeaderSize + signatureSize,
                writeCryptoTransformBytes.Length,
                "Aligned SMB2_RDMA_CRYPTO_TRANSFORM length is {0}.",
                writeCryptoTransformBytes.Length);

            SMB2_RDMA_TRANSFORM writeRdmaTransform = new SMB2_RDMA_TRANSFORM
            {
                RdmaDescriptorOffset = (ushort)rdmaDescriptorOffset,
                RdmaDescriptorLength = (ushort)descriptorListLength,
                Channel = Smb2RdmaTransformChannel.SMB2_CHANNEL_RDMA_V1,
                TransformCount = 1,
                Reserved1 = 0,
                Reserved2 = 0
            };
            byte[] writeRdmaTransformBytes = TypeMarshal.ToBytes(writeRdmaTransform);

            byte[] writeChannelInfo = new byte[rdmaDescriptorOffset + descriptorListLength];
            writeRdmaTransformBytes.CopyTo(writeChannelInfo, 0);
            writeCryptoTransformBytes.CopyTo(writeChannelInfo, writeRdmaTransformBytes.Length);
            descriptorListBytes.CopyTo(writeChannelInfo, rdmaDescriptorOffset);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Write content to file over RDMA.");
            WRITE_Response writeResponse;
            status = (NtStatus)smbdAdapter.Smb2WriteOverRdmaChannel(
                0,
                writeChannelInfo,
                size,
                out writeResponse,
                Channel_Values.CHANNEL_RDMA_TRANSFORM
                );
            BaseTestSite.Assert.AreEqual<NtStatus>(
                NtStatus.STATUS_SUCCESS,
                status,
                "Status of SMB2 Write File is {0}", status);
            BaseTestSite.Assert.AreEqual<uint>(
                (uint)size,
                writeResponse.Count,
                "DataLength in WRITE response is {0}", writeResponse.Count);

            #endregion


            #region Read file from server
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Register memory and get buffer descriptor for SMB2 READ");
            SmbdBufferDescriptorV1[] readDescp = new SmbdBufferDescriptorV1[bufferCount];
            byte[] readDescriptorListBytes = new byte[descriptorListLength];
            for (int i = 0; i < bufferCount; ++i)
            {
                readDescp[i] = RegisterBufferAndAssert(
                    bufferLengths[i],
                    SmbdBufferReadWrite.RDMA_WRITE_PERMISSION_FOR_READ_FILE);
                byte[] descriptorBlock = TypeMarshal.ToBytes<SmbdBufferDescriptorV1>(readDescp[i]);
                Array.Copy(
                    descriptorBlock,
                    0,
                    readDescriptorListBytes,
                    SmbdBufferDescriptorV1.SIZE * i,
                    SmbdBufferDescriptorV1.SIZE);
            }

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Read content from file over RDMA.");
            READ_Response readResponse;
            byte[] readData;
            // Per MS-SMB2 3.3.5.12, the server transforms (signs) the RDMA READ payload and reports
            // it in the response Buffer whenever Connection.RDMATransformIds is not empty and the
            // request is signed - the request's channel info itself remains a plain buffer descriptor
            // list over SMB2_CHANNEL_RDMA_V1 (the default channel).
            status = (NtStatus)smbdAdapter.Smb2ReadOverRdmaChannel(
                0,
                size,
                readDescriptorListBytes,
                out readResponse,
                out readData
                );
            BaseTestSite.Assert.AreEqual<NtStatus>(
                NtStatus.STATUS_SUCCESS,
                status,
                "Status of SMB2 Read File is {0}", status);
            BaseTestSite.Assert.AreEqual<byte>(
                80,
                readResponse.DataOffset,
                "DataOffset in response is {0}", readResponse.DataOffset);
            BaseTestSite.Assert.AreEqual<uint>(
                size,
                readResponse.DataRemaining,
                "DataRemaining in response is {0}", readResponse.DataRemaining);

            // Since the connection negotiated SMB2_RDMA_TRANSFORM_SIGNING and the session is signed,
            // the server signs the RDMA READ payload and appends an SMB2_RDMA_TRANSFORM followed by
            // a signing SMB2_RDMA_CRYPTO_TRANSFORM to the response Buffer, flagged by
            // SMB2_READFLAG_RESPONSE_RDMA_TRANSFORM, instead of returning an empty Buffer.
            BaseTestSite.Assert.AreEqual<READ_Response_Flags_Values2>(
                READ_Response_Flags_Values2.SMB2_READFLAG_RESPONSE_RDMA_TRANSFORM,
                readResponse.Reserved2,
                "SMB2_READFLAG_RESPONSE_RDMA_TRANSFORM bit MUST be set in the Flags field of the READ response. Flags is {0}",
                readResponse.Reserved2);
            BaseTestSite.Assert.IsTrue(
                readData.Length > rdmaTransformHeaderSize,
                "Data length of content in response is {0}", readData.Length);
            BaseTestSite.Assert.AreEqual<uint>(
                (uint)readData.Length,
                readResponse.DataLength,
                "DataLength in response is {0}", readResponse.DataLength);

            byte[] rdmaTransformBytes = new byte[rdmaTransformHeaderSize];
            Array.Copy(readData, 0, rdmaTransformBytes, 0, rdmaTransformHeaderSize);
            SMB2_RDMA_TRANSFORM rdmaTransform = TypeMarshal.ToStruct<SMB2_RDMA_TRANSFORM>(rdmaTransformBytes);
            BaseTestSite.Assert.AreEqual<int>(
                1,
                rdmaTransform.TransformCount,
                "SMB2_RDMA_TRANSFORM TransformCount is {0}", rdmaTransform.TransformCount);

            byte[] readCryptoTransformBytes = new byte[readData.Length - rdmaTransformHeaderSize];
            Array.Copy(readData, rdmaTransformHeaderSize, readCryptoTransformBytes, 0, readCryptoTransformBytes.Length);
            SMB2_RDMA_CRYPTO_TRANSFORM readCryptoTransform = TypeMarshal.ToStruct<SMB2_RDMA_CRYPTO_TRANSFORM>(readCryptoTransformBytes);
            BaseTestSite.Assert.AreEqual<Smb2RDMATransformType>(
                Smb2RDMATransformType.SMB2_RDMA_TRANSFORM_TYPE_SIGNING,
                readCryptoTransform.TransformType,
                "SMB2_RDMA_CRYPTO_TRANSFORM TransformType is {0}", readCryptoTransform.TransformType);

            // read content 
            int readOffset = 0;
            for (int index = 0; index < bufferCount; ++index)
            {
                int length = (int)bufferLengths[index];
                byte[] buffer = new byte[length];
                smbdAdapter.SmbdReadRegisteredBuffer(buffer, readDescp[index]);
                Array.Copy(buffer, 0, readContent, readOffset, length);
                readOffset += length;
            }
            #endregion

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Check the read content is same as the one written into the file.");
            BaseTestSite.Assert.IsTrue(
                    SmbdUtilities.CompareByteArray(writeContent, readContent),
                    "Check content of file");

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Close file.");
            smbdAdapter.Smb2CloseFile();
        }

        [TestMethod()]
        [TestCategory("Smb2OverRdmaChannel")]
        [Description("Verify server will not crash if Offset in Buffer Descriptor is not correct.")]
        // Spec: [MS-SMB2] 3.3.5.12 / [MS-SMBD] 3.1.4.5 - the server RDMA-writes into the client-supplied descriptor; an
        // invalid descriptor (Offset beyond the registered buffer) makes the RDMA op fail at the provider.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.12 Receiving an SMB2 READ Request; [MS-SMBD] 3.1.4.5 RDMA Write to Peer Buffer")]
        [TestProperty("SpecCompliance", "TODO")]
        public void Smb2OverRdmaChannel_InvalidBufferDescriptor_Offset()
        {
            // TODO(spec): neither MS-SMB2 3.3.5.12 nor MS-SMBD 3.1.4.5 defines the server's response (status, no response, or
            // connection termination) to an invalid buffer descriptor; this test asserts only a non-success/no-response outcome
            // plus server survivability (implementation-specific robustness check). Mark as non-normative or negative/robustness.
            InitSmbdConnectionForTestCases(smbdAdapter.TestConfig.TestFileName_LargeFile);

            // SMB2 Read file
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Register memory and get buffer descriptor for SMB2 READ.");
            uint bufferSize = smbdAdapter.Smb2MaxReadSize;
            SmbdBufferDescriptorV1 descp = RegisterBufferAndAssert(
                bufferSize,
                SmbdBufferReadWrite.RDMA_WRITE_PERMISSION_FOR_READ_FILE);

            // modify offset to overrun buffer size which is invalid
            descp.Offset = bufferSize + 1;

            byte[] channelInfo = TypeMarshal.ToBytes<SmbdBufferDescriptorV1>(descp);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Read content from file over RDMA.");
            READ_Response readResponse;
            byte[] readData;
            try
            {
                NtStatus status = (NtStatus)smbdAdapter.Smb2ReadOverRdmaChannel(
                    0,
                    smbdAdapter.Smb2MaxReadSize,
                    channelInfo,
                    out readResponse,
                    out readData
                    );
                BaseTestSite.Assert.AreNotEqual<NtStatus>(
                        NtStatus.STATUS_SUCCESS,
                        status,
                        "Status of SMB2 Read File is {0}", status);
            }
            catch (TimeoutException)
            {
                BaseTestSite.Assert.Pass("No SMB2 READ response received");
            }

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Disconnect and reconnect to verify server is available.");
            smbdAdapter.DisconnectRdma();
            smbdAdapter.ConnectToServerOverRDMA();
        }

        [TestMethod()]
        [TestCategory("Smb2OverRdmaChannel")]
        [Description("Verify server will not crash if Length in Buffer Descriptor is not correct.")]
        // Spec: [MS-SMB2] 3.3.5.12 / [MS-SMBD] 3.1.4.5 - descriptor Length (one byte larger than the registered buffer) is invalid.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.12 Receiving an SMB2 READ Request; [MS-SMBD] 3.1.4.5 RDMA Write to Peer Buffer")]
        [TestProperty("SpecCompliance", "TODO")]
        public void Smb2OverRdmaChannel_InvalidBufferDescriptor_Length()
        {
            // TODO(spec): the specs do not define server behavior for a descriptor whose Length exceeds the registered buffer;
            // the test asserts only non-success/no-response and server survivability (implementation-specific robustness check).
            InitSmbdConnectionForTestCases(smbdAdapter.TestConfig.TestFileName_LargeFile);

            // SMB2 Read file
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Register memory and get buffer descriptor for SMB2 WRITE");
            SmbdBufferDescriptorV1 descp = RegisterBufferAndAssert(
                smbdAdapter.Smb2MaxReadSize - 1,
                SmbdBufferReadWrite.RDMA_WRITE_PERMISSION_FOR_READ_FILE);
            // modify offset to make it invalid
            descp.Length++;

            byte[] channelInfo = TypeMarshal.ToBytes<SmbdBufferDescriptorV1>(descp);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Read content from file over RDMA.");
            READ_Response readResponse;
            byte[] readData;
            try
            {
                NtStatus status = (NtStatus)smbdAdapter.Smb2ReadOverRdmaChannel(
                    0,
                    smbdAdapter.Smb2MaxReadSize,
                    channelInfo,
                    out readResponse,
                    out readData
                    );
                BaseTestSite.Assert.AreNotEqual<NtStatus>(
                        NtStatus.STATUS_SUCCESS,
                        status,
                        "Status of SMB2 Read File is {0}", status);
            }
            catch (TimeoutException)
            {
                BaseTestSite.Assert.Pass("No SMB2 READ response received");
            }

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Disconnect and reconnect to verify server is available.");
            smbdAdapter.DisconnectRdma();
            smbdAdapter.ConnectToServerOverRDMA();
        }

        [TestMethod()]
        [TestCategory("Smb2OverRdmaChannel")]
        [Description("Verify server will not crash if Token in Buffer Descriptor is not correct.")]
        // Spec: [MS-SMB2] 3.3.5.12 / [MS-SMBD] 3.1.4.5 - descriptor Token (remote key) does not match the registered buffer.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.12 Receiving an SMB2 READ Request; [MS-SMBD] 3.1.4.5 RDMA Write to Peer Buffer")]
        [TestProperty("SpecCompliance", "TODO")]
        public void Smb2OverRdmaChannel_InvalidBufferDescriptor_Token()
        {
            // TODO(spec): the specs do not define server behavior for an unknown/invalid descriptor Token (RDMA access error);
            // the test asserts only non-success/no-response and server survivability (implementation-specific robustness check).
            InitSmbdConnectionForTestCases(smbdAdapter.TestConfig.TestFileName_LargeFile);

            // SMB2 Read file
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Register memory and get buffer descriptor for SMB2 WRITE");
            SmbdBufferDescriptorV1 descp = RegisterBufferAndAssert(
                smbdAdapter.Smb2MaxReadSize,
                SmbdBufferReadWrite.RDMA_WRITE_PERMISSION_FOR_READ_FILE);
            // modify offset to make it invalid
            descp.Token++;

            byte[] channelInfo = TypeMarshal.ToBytes<SmbdBufferDescriptorV1>(descp);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Read content from file over RDMA.");
            READ_Response readResponse;
            byte[] readData;
            try
            {
                NtStatus status = (NtStatus)smbdAdapter.Smb2ReadOverRdmaChannel(
                    0,
                    smbdAdapter.Smb2MaxReadSize,
                    channelInfo,
                    out readResponse,
                    out readData
                    );
                BaseTestSite.Assert.AreNotEqual<NtStatus>(
                        NtStatus.STATUS_SUCCESS,
                        status,
                        "Status of SMB2 Read File is {0}", status);
            }
            catch (TimeoutException)
            {
                BaseTestSite.Assert.Pass("No SMB2 READ response received");
            }

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Disconnect and reconnect to verify server is available.");
            smbdAdapter.DisconnectRdma();
            smbdAdapter.ConnectToServerOverRDMA();
        }

        [TestMethod()]
        [TestCategory("Smb2OverRdmaChannel")]
        [Description("Verify server will not crash if buffer descriptor in channel info is deregistered.")]
        // Spec: [MS-SMB2] 3.3.5.12 / [MS-SMBD] 3.1.4.4 - the client deregisters the buffer, so the descriptor no longer refers to valid memory.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.12 Receiving an SMB2 READ Request; [MS-SMBD] 3.1.4.4 Deregister Buffer; [MS-SMBD] 3.1.4.5 RDMA Write to Peer Buffer")]
        [TestProperty("SpecCompliance", "TODO")]
        public void Smb2OverRdmaChannel_InvalidBufferDescriptor_DeregisteredBuffer()
        {
            // TODO(spec): the specs do not define server behavior when the descriptor refers to a deregistered buffer;
            // the test asserts only non-success/no-response and server survivability (implementation-specific robustness check).
            InitSmbdConnectionForTestCases(smbdAdapter.TestConfig.TestFileName_LargeFile);

            // SMB2 Read file
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Register memory and get buffer descriptor for SMB2 WRITE");
            SmbdBufferDescriptorV1 descp = RegisterBufferAndAssert(
                smbdAdapter.Smb2MaxReadSize,
                SmbdBufferReadWrite.RDMA_WRITE_PERMISSION_FOR_READ_FILE);
            smbdAdapter.SmbdDeregisterBuffer(descp);
            byte[] channelInfo = TypeMarshal.ToBytes<SmbdBufferDescriptorV1>(descp);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Read content from file over RDMA.");
            READ_Response readResponse;
            byte[] readData;
            try
            {
                NtStatus status = (NtStatus)smbdAdapter.Smb2ReadOverRdmaChannel(
                    0,
                    smbdAdapter.Smb2MaxReadSize,
                    channelInfo,
                    out readResponse,
                    out readData
                    );
                BaseTestSite.Assert.AreNotEqual<NtStatus>(
                        NtStatus.STATUS_SUCCESS,
                        status,
                        "Status of SMB2 Read File is {0}", status);
            }
            catch (TimeoutException)
            {
                BaseTestSite.Assert.Pass("No SMB2 READ response received");
            }

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Disconnect and reconnect to verify server is available.");
            smbdAdapter.DisconnectRdma();
            smbdAdapter.ConnectToServerOverRDMA();
        }

        #endregion

        #region Common Methods

        /// <summary>
        /// Read file content over RDMA. The file content will be read with a specific number of operations.
        /// The total size of the read content is the effective maximum single RDMA READ size, which is the
        /// smaller of the SMB2 negotiated MaxReadSize and the SMBD negotiated MaxReadWriteSize. Content size
        /// in each SMB2 READ request is ( effectiveMaxReadSize / operationCount ).
        /// </summary>
        /// <param name="operationCount">Count of SMB2 READ operations.</param>
        public void ReadOverRdma(uint operationCount = 1)
        {
            InitSmbdConnectionForTestCases(smbdAdapter.TestConfig.TestFileName_LargeFile);

            uint readSize;
            uint effectiveOperationCount;
            ComputeReadPlan(operationCount, out readSize, out effectiveOperationCount);
            uint maxSize = smbdAdapter.Smb2MaxReadSize;
            uint totalSize = (uint)Math.Min((ulong)readSize * effectiveOperationCount, maxSize);
            BaseTestSite.Log.Add(LogEntryKind.Debug, "ReadSize is {0}", readSize);
            BaseTestSite.Log.Add(LogEntryKind.Debug, "Read operation count: {0}", effectiveOperationCount);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Send each read request according to SMB2 read file limit.");
            for (int i = 0; i < effectiveOperationCount; ++i)
            {
                BaseTestSite.Log.Add(LogEntryKind.Debug,
                    "DIAGNOSTIC BUILD: ReadOverRdma loop iteration {0} of {1}", i, effectiveOperationCount);
                // SMB2 Read file. The last request covers any remainder so the
                // total read equals the effective maximum single RDMA READ size.
                uint length = (uint)Math.Min(readSize, totalSize - (uint)i * readSize);
                SmbdBufferDescriptorV1 descp = RegisterBufferAndAssert(
                    length,
                    SmbdBufferReadWrite.RDMA_WRITE_PERMISSION_FOR_READ_FILE);
                byte[] channelInfo = TypeMarshal.ToBytes<SmbdBufferDescriptorV1>(descp);

                BaseTestSite.Log.Add(LogEntryKind.Debug,
                    "SMB2 READ descriptor: Offset=0x{0:X16}, Token=0x{1:X8}, Length={2}",
                    descp.Offset, descp.Token, descp.Length);
                BaseTestSite.Log.Add(LogEntryKind.Debug,
                    "SMB2 READ channel info bytes: {0}",
                    BitConverter.ToString(channelInfo).Replace("-", " "));

                BaseTestSite.Log.Add(LogEntryKind.TestStep, "Read content from file over RDMA.");
                READ_Response readResponse;
                byte[] readData;
                NtStatus status = (NtStatus)smbdAdapter.Smb2ReadOverRdmaChannel(
                    (UInt64)i * readSize,
                    length,
                    channelInfo,
                    out readResponse,
                    out readData
                    );
                BaseTestSite.Log.Add(LogEntryKind.Debug,
                    "SMB2 READ response status: {0}, DataRemaining={1}, DataOffset={2}, DataLength={3}",
                    status, readResponse.DataRemaining, readResponse.DataOffset, readResponse.DataLength);
                BaseTestSite.Assert.AreEqual<NtStatus>(
                    NtStatus.STATUS_SUCCESS,
                    status,
                    "Status of SMB2 Read File is {0}", status);
                BaseTestSite.Assert.AreEqual<uint>(
                    length,
                    readResponse.DataRemaining,
                    "DataRemaining in READ response is {0}", readResponse.DataRemaining);
                BaseTestSite.Assert.AreEqual<int>(
                    0,
                    readData.Length,
                    "Data length of content in response is {0}", readData.Length);
                BaseTestSite.Assert.AreEqual<byte>(
                    80,
                    readResponse.DataOffset,
                    "DataOffset in response is {0}", readResponse.DataOffset);
                BaseTestSite.Assert.AreEqual<uint>(
                    0,
                    readResponse.DataLength,
                    "DataLength in response is {0}", readResponse.DataLength);

            }

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Close file.");
            smbdAdapter.Smb2CloseFile();
        }

        /// <summary>
        /// Write file content over RDMA. The file content will be written with a specific number of operations.
        /// The total size of the write content is the effective maximum single RDMA WRITE size, which is the
        /// smaller of the SMB2 negotiated MaxWriteSize and the SMBD negotiated MaxReadWriteSize. Content size
        /// in each SMB2 WRITE request is ( effectiveMaxWriteSize / operationCount ).
        /// </summary>
        /// <param name="operationCount">count of SMB2 WRITE operation</param>
        public void WriteOverRdma(uint operationCount = 1)
        {
            string fileName = CreateRandomFileName();
            Smb2RDMATransformId[] rdmaTransformIds =
            {
                Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_SIGNING
            };

            InitSmbdConnectionForTestCases(fileName, rdmaTransformIds);
            // RDMA transform is optional ([MS-SMB2] 2.2.3.1.7 / 3.3.5.4): skip when the server does not select it.
            BaseTestSite.Assume.IsTrue(
                smbdAdapter.SelectedRdmaTransformIds != null &&
                Array.IndexOf(
                    smbdAdapter.SelectedRdmaTransformIds,
                    Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_SIGNING) >= 0,
                "Server does not select SMB2_RDMA_TRANSFORM_SIGNING in the SMB2_RDMA_TRANSFORM_CAPABILITIES negotiate context.");

            uint writeSize;
            uint effectiveOperationCount;
            ComputeWritePlan(operationCount, out writeSize, out effectiveOperationCount);
            uint totalSize = (uint)Math.Min((ulong)writeSize * effectiveOperationCount, smbdAdapter.Smb2MaxWriteSize);

            // SMB2 Write file
            byte[] fileContent = Encoding.ASCII.GetBytes(Smb2Utility.CreateRandomStringInByte((int)writeSize));

            // Check if session has signing enabled by checking if the decoder has crypto info
            bool needsSigning = smbdAdapter.Decoder.CryptoInfoTable.Count > 0;

            // Sign the content once before the loop if needed
            byte[] nonce = null;
            byte[] signature = null;
            if (needsSigning)
            {
                smbdAdapter.SignByteArray(fileContent, out nonce, out signature, Smb2Command.WRITE);
            }

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Send each write request according SMB2 write file limit.");
            for (int i = 0; i < effectiveOperationCount; ++i)
            {
                // register memory and get buffer descriptor
                SmbdBufferDescriptorV1 descp = RegisterBufferAndAssert(
                    writeSize,
                    SmbdBufferReadWrite.RDMA_READ_PERMISSION_FOR_WRITE_FILE);

                byte[] channelInfo;

                // If signing is required, wrap descriptor in SMB2_RDMA_TRANSFORM
                if (needsSigning)
                {
                    // Build RDMA_CRYPTO_TRANSFORM
                    SMB2_RDMA_CRYPTO_TRANSFORM cryptoTransform = new SMB2_RDMA_CRYPTO_TRANSFORM
                    {
                        TransformType = Smb2RDMATransformType.SMB2_RDMA_TRANSFORM_TYPE_SIGNING,
                        SignatureLength = (ushort)signature.Length,
                        NonceLength = (ushort)nonce.Length,
                        Signature = signature,
                        Nonce = nonce,
                    };
                    var cryptoTransformBytes = TypeMarshal.ToBytes(cryptoTransform);
                    Smb2Utility.Align8(ref cryptoTransformBytes);

                    // Build RDMA_TRANSFORM with initial offset values
                    SMB2_RDMA_TRANSFORM rdmaTransform = new SMB2_RDMA_TRANSFORM
                    {
                        RdmaDescriptorOffset = 0,
                        RdmaDescriptorLength = 1,
                        Channel = Smb2RdmaTransformChannel.SMB2_CHANNEL_RDMA_V1,
                        TransformCount = 1,
                        Reserved1 = 0,
                        Reserved2 = 0
                    };
                    var rdmaTransformBytes = TypeMarshal.ToBytes(rdmaTransform);

                    // Calculate the offset where the buffer descriptor will start
                    rdmaTransform.RdmaDescriptorOffset = (ushort)(cryptoTransformBytes.Length + rdmaTransformBytes.Length);

                    // Write registered buffer and get buffer descriptor bytes
                    smbdAdapter.SmbdWriteRegisteredBuffer(fileContent, descp);
                    byte[] bufferDescriptorBytes = TypeMarshal.ToBytes(descp);
                    rdmaTransform.RdmaDescriptorLength = (ushort)bufferDescriptorBytes.Length;

                    // Re-marshal RDMA_TRANSFORM with correct offsets
                    rdmaTransformBytes = TypeMarshal.ToBytes(rdmaTransform);

                    // Build the complete channel info: rdmaTransform + cryptoTransform + bufferDescriptor
                    ushort totalLength = (ushort)(bufferDescriptorBytes.Length + rdmaTransform.RdmaDescriptorOffset);
                    byte[] totalBytes = new byte[totalLength];
                    rdmaTransformBytes.CopyTo(totalBytes, 0);
                    cryptoTransformBytes.CopyTo(totalBytes, rdmaTransformBytes.Length);
                    bufferDescriptorBytes.CopyTo(totalBytes, cryptoTransformBytes.Length + rdmaTransformBytes.Length);

                    channelInfo = totalBytes;
                }
                else
                {
                    smbdAdapter.SmbdWriteRegisteredBuffer(fileContent, descp);
                    channelInfo = TypeMarshal.ToBytes<SmbdBufferDescriptorV1>(descp);
                }

                BaseTestSite.Log.Add(LogEntryKind.TestStep, "Write content to file over RDMA.");
                WRITE_Response writeResponse;
                Channel_Values channel = needsSigning ? Channel_Values.CHANNEL_RDMA_TRANSFORM : Channel_Values.CHANNEL_RDMA_V1;
                NtStatus status = (NtStatus)smbdAdapter.Smb2WriteOverRdmaChannel(
                    (UInt64)i * writeSize,
                    channelInfo,
                    writeSize,
                    out writeResponse,
                    channel
                    );
                BaseTestSite.Assert.AreEqual<NtStatus>(
                    NtStatus.STATUS_SUCCESS,
                    status,
                    "Status of SMB2 Write File offset {0} is {1}", i * writeSize, status);
                BaseTestSite.Assert.AreEqual<uint>(
                    (uint)writeSize,
                    writeResponse.Count,
                    "DataLength in WRITE response is {0}", writeResponse.Count);
            }

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Validate file content.");
            ValidateFileContent(fileContent, totalSize);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Close file.");
            smbdAdapter.Smb2CloseFile();
        }


        public void ValidateFileContent(byte[] content, uint fileSize)
        {
            uint readSize = (uint)content.Length;
            // SMB2 Read file
            SmbdBufferDescriptorV1 descp = RegisterBufferAndAssert(
                readSize,
                SmbdBufferReadWrite.RDMA_WRITE_PERMISSION_FOR_READ_FILE);

            // Per MS-SMB2 3.3.5.12, the server only transforms (signs) the RDMA READ payload when
            // Connection.RDMATransformIds is not empty and the request is signed. Determine whether
            // that applies to this connection/session so the response can be validated correctly
            // whether or not a transform was negotiated and/or signing is enabled.
            bool expectRdmaTransform =
                smbdAdapter.SelectedRdmaTransformIds != null &&
                Array.IndexOf(smbdAdapter.SelectedRdmaTransformIds, Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_SIGNING) >= 0 &&
                smbdAdapter.Decoder.CryptoInfoTable.Count > 0;

            const int rdmaTransformSize = 16; // sizeof(SMB2_RDMA_TRANSFORM)

            // send each read request according to SMB2 read file limit
            uint offset = 0;
            while (offset < fileSize)
            {
                byte[] channelInfo = TypeMarshal.ToBytes<SmbdBufferDescriptorV1>(descp);

                uint length = readSize;
                if (offset + length > fileSize)
                {
                    length = fileSize - offset;
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
                BaseTestSite.Assert.AreEqual<NtStatus>(
                    NtStatus.STATUS_SUCCESS,
                    status,
                    "Status of SMB2 Read File is {0}", status);
                BaseTestSite.Assert.AreEqual<uint>(
                    (uint)length,
                    readResponse.DataRemaining,
                    "DataRemaining in READ response is {0}", readResponse.DataRemaining);
                BaseTestSite.Assert.AreEqual<byte>(
                    80,
                    readResponse.DataOffset,
                    "DataOffset in response is {0}", readResponse.DataOffset);

                if (expectRdmaTransform)
                {
                    // Per MS-SMB2 3.3.5.12 the server signs the RDMA payload and appends an
                    // SMB2_RDMA_TRANSFORM followed by an SMB2_RDMA_CRYPTO_TRANSFORM to the READ
                    // response Buffer, flagged by SMB2_READFLAG_RESPONSE_RDMA_TRANSFORM. DataLength
                    // reflects the length of that inline Buffer (not the RDMA-transferred file data).
                    BaseTestSite.Assert.AreEqual<READ_Response_Flags_Values2>(
                        READ_Response_Flags_Values2.SMB2_READFLAG_RESPONSE_RDMA_TRANSFORM,
                        readResponse.Reserved2,
                        "SMB2_READFLAG_RESPONSE_RDMA_TRANSFORM bit MUST be set in the Flags field of the READ response. Flags is {0}",
                        readResponse.Reserved2);
                    BaseTestSite.Assert.IsTrue(
                        readData.Length > rdmaTransformSize,
                        "Data length of content in response is {0}", readData.Length);
                    BaseTestSite.Assert.AreEqual<uint>(
                        (uint)readData.Length,
                        readResponse.DataLength,
                        "DataLength in response is {0}", readResponse.DataLength);

                    byte[] rdmaTransformBytes = new byte[rdmaTransformSize];
                    Array.Copy(readData, 0, rdmaTransformBytes, 0, rdmaTransformSize);
                    SMB2_RDMA_TRANSFORM rdmaTransform = TypeMarshal.ToStruct<SMB2_RDMA_TRANSFORM>(rdmaTransformBytes);
                    BaseTestSite.Assert.AreEqual<int>(
                        1,
                        rdmaTransform.TransformCount,
                        "SMB2_RDMA_TRANSFORM TransformCount is {0}", rdmaTransform.TransformCount);

                    byte[] cryptoTransformBytes = new byte[readData.Length - rdmaTransformSize];
                    Array.Copy(readData, rdmaTransformSize, cryptoTransformBytes, 0, cryptoTransformBytes.Length);
                    SMB2_RDMA_CRYPTO_TRANSFORM cryptoTransform = TypeMarshal.ToStruct<SMB2_RDMA_CRYPTO_TRANSFORM>(cryptoTransformBytes);
                    BaseTestSite.Assert.AreEqual<Smb2RDMATransformType>(
                        Smb2RDMATransformType.SMB2_RDMA_TRANSFORM_TYPE_SIGNING,
                        cryptoTransform.TransformType,
                        "SMB2_RDMA_CRYPTO_TRANSFORM TransformType is {0}", cryptoTransform.TransformType);
                }
                else
                {
                    // No transform negotiated (or session not signed): the server returns an empty Buffer.
                    BaseTestSite.Assert.AreEqual<int>(
                        0,
                        readData.Length,
                        "Data length of content in response is {0}", readData.Length);
                    BaseTestSite.Assert.AreEqual<uint>(
                        0,
                        readResponse.DataLength,
                        "DataLength in response is {0}", readResponse.DataLength);
                }

                byte[] readFileContent = new byte[readSize];
                smbdAdapter.SmbdReadRegisteredBuffer(readFileContent, descp);
                BaseTestSite.Assert.IsTrue(
                    SmbdUtilities.CompareByteArray(content, readFileContent),
                    "Check content of file");


                offset += readSize;
            }
        }

        private SmbdBufferDescriptorV1 RegisterBufferAndAssert(
            uint length,
            SmbdBufferReadWrite flag)
        {
            SmbdBufferDescriptorV1 descriptor;
            NtStatus registerStatus = smbdAdapter.SmbdRegisterBuffer(
                length,
                flag,
                out descriptor);
            BaseTestSite.Assert.AreEqual<NtStatus>(
                NtStatus.STATUS_SUCCESS,
                registerStatus,
                "SmbdRegisterBuffer failed with status {0}",
                registerStatus);
            return descriptor;
        }

        public void InitSmbdConnectionForTestCases(
            string fileName,
            Smb2RDMATransformId[] rdmaTransformIds = null,
            SigningAlgorithm[] signingAlgorithms = null)
        {
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Initial SMBD connection and open file " + fileName);

            uint size = smbdAdapter.TestConfig.LargeFileSizeInByte;
            // Connect to server over RDMA
            NtStatus status = smbdAdapter.ConnectToServerOverRDMA();
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMBD connection is {0}", status);

            // SMBD Negotiate
            status = smbdAdapter.SmbdNegotiate();
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMBD negotiate is {0}", status);

            DialectRevision[] dialects = rdmaTransformIds == null
                ? null
                : new[] { DialectRevision.Smb311 };
            status = smbdAdapter.Smb2EstablishSessionAndOpenFile(
                fileName,
                negotiatedDialects: dialects,
                smb2RDMATransformIds: rdmaTransformIds,
                signingAlgorithms: signingAlgorithms);
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMB2 establish session and open file is {0}", status);
        }
        #endregion
    }
}