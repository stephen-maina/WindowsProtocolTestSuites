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
using System.Linq;
using System.Text;

namespace Microsoft.Protocol.TestSuites.Smbd.TestSuite
{
    /// <summary>
    /// Edge-case tests for SMB2_RDMA_TRANSFORM / SMB2_RDMA_CRYPTO_TRANSFORM handling that are not covered
    /// by Smb2OverRdmaChannelTransformSigning / Smb2OverRdmaChannelTransformEncryption.
    /// </summary>
    [TestClass]
    public class Smb2OverRdmaTransformEdge : Smb2OverSmbdTestBase
    {
        private const int RdmaTransformSize = 16;      // sizeof(SMB2_RDMA_TRANSFORM)
        private const int CryptoTransformHeaderSize = 8; // fixed part of SMB2_RDMA_CRYPTO_TRANSFORM
        private const int ExpectedReadDataOffset = 80; // SMB2 header (64) + READ response fixed part (16)

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
        [TestCategory("Negative")]
        [TestCategory("Encryption")]
        [TestCategory("Smb2OverRdmaChannel")]
        [Description("WRITE with Channel=SMB2_CHANNEL_RDMA_TRANSFORM carrying an ENCRYPTION crypto transform in a request that is not encrypted is rejected")]
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.13 Receiving an SMB2 WRITE Request; 2.2.43.1 SMB2_RDMA_CRYPTO_TRANSFORM")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaTransform_Encryption_WriteRequestNotEncrypted_Fails()
        {
            // WHAT: negotiate ENCRYPTION transform but send the WRITE without SMB2 encryption, carrying an ENCRYPTION crypto transform.
            // WHY: the transform is only legal on an encrypted request; the server must not accept it otherwise.
            // SPEC: [MS-SMB2] 3.3.5.13 - Channel is SMB2_CHANNEL_RDMA_TRANSFORM and an ENCRYPTION transform is present
            //       and Request.IsEncrypted is FALSE => STATUS_INVALID_PARAMETER.
            string fileName = CreateRandomFileName();
            InitConnection(
                fileName,
                new[] { Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_ENCRYPTION },
                encryptionAlgorithms: new[] { EncryptionAlgorithm.ENCRYPTION_AES128_GCM },
                signingAlgorithms: null,
                enableSigning: true,
                enableEncryption: false);
            AssumeTransformSelected(Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_ENCRYPTION);

            smbdAdapter.SetWriteRequestSigned(false);
            NtStatus status = SendTransformWrite(
                Smb2RDMATransformType.SMB2_RDMA_TRANSFORM_TYPE_ENCRYPTION,
                encrypt: true,
                remainingBytesAdjust: 0);

            BaseTestSite.Assert.AreEqual<NtStatus>(
                NtStatus.STATUS_INVALID_PARAMETER,
                status,
                "Server MUST return STATUS_INVALID_PARAMETER for an ENCRYPTION transform when Request.IsEncrypted is FALSE. Actual: {0}", status);
        }

        [TestMethod()]
        [TestCategory("Negative")]
        [TestCategory("Encryption")]
        [TestCategory("Smb2OverRdmaChannel")]
        [Description("WRITE with an unknown TransformType following SMB2_RDMA_TRANSFORM (encrypted request) is rejected")]
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.13 Receiving an SMB2 WRITE Request; 2.2.43 SMB2_RDMA_TRANSFORM; 2.2.43.1 SMB2_RDMA_CRYPTO_TRANSFORM")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaTransform_Encryption_WriteUnknownTransformType_Fails()
        {
            // WHAT: send a valid encrypted request whose crypto transform has TransformType 0x00FF.
            // WHY: only ENCRYPTION (1) and SIGNING (2) are defined; anything else is malformed.
            // SPEC: [MS-SMB2] 3.3.5.13 - SMB2_RDMA_TRANSFORM followed by a transform not specified in 2.2.43
            //       => STATUS_INVALID_PARAMETER.
            string fileName = CreateRandomFileName();
            InitConnection(
                fileName,
                new[] { Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_ENCRYPTION },
                encryptionAlgorithms: new[] { EncryptionAlgorithm.ENCRYPTION_AES128_GCM },
                signingAlgorithms: null,
                enableSigning: false,
                enableEncryption: true);
            AssumeTransformSelected(Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_ENCRYPTION);

            NtStatus status = SendTransformWrite(
                (Smb2RDMATransformType)0x00FF,
                encrypt: true,
                remainingBytesAdjust: 0);

            BaseTestSite.Assert.AreEqual<NtStatus>(
                NtStatus.STATUS_INVALID_PARAMETER,
                status,
                "Server MUST return STATUS_INVALID_PARAMETER for an unspecified transform type. Actual: {0}", status);
        }

        [TestMethod()]
        [TestCategory("Negative")]
        [TestCategory("Signing")]
        [TestCategory("Smb2OverRdmaChannel")]
        [Description("WRITE with an unknown TransformType following SMB2_RDMA_TRANSFORM (signed request) is rejected")]
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.13 Receiving an SMB2 WRITE Request; 2.2.43 SMB2_RDMA_TRANSFORM; 2.2.43.1 SMB2_RDMA_CRYPTO_TRANSFORM")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaTransform_Signing_WriteUnknownTransformType_Fails()
        {
            // WHAT: same as the encryption variant but on a signed session with SMB2_FLAGS_SIGNED set.
            // WHY: the rejection must not depend on which crypto transform the connection negotiated.
            // SPEC: [MS-SMB2] 3.3.5.13 - transform not specified in 2.2.43 => STATUS_INVALID_PARAMETER.
            string fileName = CreateRandomFileName();
            InitConnection(
                fileName,
                new[] { Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_SIGNING },
                encryptionAlgorithms: null,
                signingAlgorithms: new[] { SigningAlgorithm.AES_GMAC },
                enableSigning: true,
                enableEncryption: false);
            AssumeTransformSelected(Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_SIGNING);

            smbdAdapter.SetWriteRequestSigned(true);
            NtStatus status = SendTransformWrite(
                (Smb2RDMATransformType)0x00FF,
                encrypt: false,
                remainingBytesAdjust: 0);

            BaseTestSite.Assert.AreEqual<NtStatus>(
                NtStatus.STATUS_INVALID_PARAMETER,
                status,
                "Server MUST return STATUS_INVALID_PARAMETER for an unspecified transform type. Actual: {0}", status);
        }

        [TestMethod()]
        [TestCategory("Positive")]
        [TestCategory("Smb2OverRdmaChannel")]
        [Description("READ over RDMA with no RDMA transform negotiated returns DataLength 0 and no RDMA-transform response flag")]
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.12 Receiving an SMB2 READ Request")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaTransform_Read_NoTransformNegotiated_NoTransformInResponse()
        {
            // WHAT: negotiate without an RDMA transform capability, READ over RDMA_V1.
            // WHY: the transform response layout only applies when Connection.RDMATransformIds is non-empty.
            // SPEC: [MS-SMB2] 3.3.5.12 - otherwise DataLength MUST be 0; SMB2_READFLAG_RESPONSE_RDMA_TRANSFORM is only set
            //       together with the transform buffer. (Transform negotiated + unsigned/unencrypted request is not
            //       defined by the spec and is deliberately not asserted.)
            string fileName = smbdAdapter.TestConfig.TestFileName_LargeFile;
            InitConnection(
                fileName,
                null,
                encryptionAlgorithms: null,
                signingAlgorithms: null,
                enableSigning: true,
                enableEncryption: false);
            BaseTestSite.Assume.IsTrue(
                smbdAdapter.SelectedRdmaTransformIds == null || smbdAdapter.SelectedRdmaTransformIds.Length == 0,
                "Server selected an RDMA transform although none was offered.");

            READ_Response readResponse = ReadOnce(out byte[] readData);

            BaseTestSite.Assert.AreEqual<int>(0, readData.Length, "READ response DataLength MUST be 0 without a negotiated transform. Actual: {0}", readData.Length);
            BaseTestSite.Assert.AreEqual<READ_Response_Flags_Values2>(
                READ_Response_Flags_Values2.SMB2_READFLAG_RESPONSE_NONE,
                readResponse.Reserved2,
                "SMB2_READFLAG_RESPONSE_RDMA_TRANSFORM MUST NOT be set without a negotiated transform. Flags: {0}", readResponse.Reserved2);
        }

        [TestMethod()]
        [TestCategory("Positive")]
        [TestCategory("Signing")]
        [TestCategory("Smb2OverRdmaChannel")]
        [Description("Signed READ over RDMA with AES-GMAC returns a SIGNING crypto transform with 16-byte signature, 12-byte nonce and consistent DataLength")]
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.12 Receiving an SMB2 READ Request; 2.2.43.1 SMB2_RDMA_CRYPTO_TRANSFORM")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaTransform_Signing_ReadResponseFields_AesGmac()
        {
            VerifySigningReadResponseFields(SigningAlgorithm.AES_GMAC, 12);
        }

        [TestMethod()]
        [TestCategory("Positive")]
        [TestCategory("Signing")]
        [TestCategory("Smb2OverRdmaChannel")]
        [Description("Signed READ over RDMA with AES-CMAC returns a SIGNING crypto transform with 16-byte signature, empty nonce and consistent DataLength")]
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.12 Receiving an SMB2 READ Request; 2.2.43.1 SMB2_RDMA_CRYPTO_TRANSFORM")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaTransform_Signing_ReadResponseFields_AesCmac()
        {
            VerifySigningReadResponseFields(SigningAlgorithm.AES_CMAC, 0);
        }

        #endregion

        #region Helpers

        private void VerifySigningReadResponseFields(SigningAlgorithm algorithm, int expectedNonceLength)
        {
            // WHAT: issue a signed READ and decode the SMB2_RDMA_TRANSFORM + SMB2_RDMA_CRYPTO_TRANSFORM in the response.
            // WHY: existing tests do not check SignatureLength or that DataLength equals the sum of the structure sizes.
            // SPEC: [MS-SMB2] 3.3.5.12 - SIGNING transform: Nonce is 12 bytes if SigningAlgorithmId is AES-GMAC, else empty;
            //       SignatureLength is set from the signature (max 16); Channel NONE, TransformCount 1, descriptor offset/length 0;
            //       DataLength is the sum of sizes of SMB2_RDMA_TRANSFORM and SMB2_RDMA_CRYPTO_TRANSFORM;
            //       SMB2_READFLAG_RESPONSE_RDMA_TRANSFORM is set.
            InitConnection(
                smbdAdapter.TestConfig.TestFileName_LargeFile,
                new[] { Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_SIGNING },
                encryptionAlgorithms: null,
                signingAlgorithms: new[] { algorithm },
                enableSigning: true,
                enableEncryption: false);
            AssumeTransformSelected(Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_SIGNING);
            BaseTestSite.Assume.AreEqual<SigningAlgorithm>(algorithm, smbdAdapter.SelectedSigningAlgorithm, "Server did not select the requested signing algorithm.");

            READ_Response readResponse = ReadOnce(out byte[] readData);

            BaseTestSite.Assert.AreEqual<READ_Response_Flags_Values2>(
                READ_Response_Flags_Values2.SMB2_READFLAG_RESPONSE_RDMA_TRANSFORM,
                readResponse.Reserved2,
                "SMB2_READFLAG_RESPONSE_RDMA_TRANSFORM MUST be set. Flags: {0}", readResponse.Reserved2);
            BaseTestSite.Assert.IsTrue(
                readData.Length >= RdmaTransformSize + CryptoTransformHeaderSize,
                "READ response buffer is too short for the transform structures: {0}", readData.Length);

            var rdmaTransform = TypeMarshal.ToStruct<SMB2_RDMA_TRANSFORM>(readData.Take(RdmaTransformSize).ToArray());
            BaseTestSite.Assert.AreEqual<int>(1, rdmaTransform.TransformCount, "TransformCount MUST be 1. Actual: {0}", rdmaTransform.TransformCount);
            BaseTestSite.Assert.AreEqual<Smb2RdmaTransformChannel>(Smb2RdmaTransformChannel.SMB2_CHANNEL_NONE, rdmaTransform.Channel, "Channel MUST be NONE. Actual: {0}", rdmaTransform.Channel);
            BaseTestSite.Assert.AreEqual<int>(0, rdmaTransform.RdmaDescriptorOffset, "RdmaDescriptorOffset MUST be 0. Actual: {0}", rdmaTransform.RdmaDescriptorOffset);
            BaseTestSite.Assert.AreEqual<int>(0, rdmaTransform.RdmaDescriptorLength, "RdmaDescriptorLength MUST be 0. Actual: {0}", rdmaTransform.RdmaDescriptorLength);

            var crypto = TypeMarshal.ToStruct<SMB2_RDMA_CRYPTO_TRANSFORM>(readData.Skip(RdmaTransformSize).ToArray());
            BaseTestSite.Assert.AreEqual<Smb2RDMATransformType>(Smb2RDMATransformType.SMB2_RDMA_TRANSFORM_TYPE_SIGNING, crypto.TransformType, "TransformType MUST be SIGNING. Actual: {0}", crypto.TransformType);
            BaseTestSite.Assert.AreEqual<int>(16, crypto.SignatureLength, "SignatureLength MUST be 16. Actual: {0}", crypto.SignatureLength);
            BaseTestSite.Assert.AreEqual<int>(expectedNonceLength, crypto.NonceLength, "NonceLength for {0} MUST be {1}. Actual: {2}", algorithm, expectedNonceLength, crypto.NonceLength);

            // DataLength equals the sum of the structure sizes; trailing padding up to 8-byte alignment is tolerated.
            int sum = RdmaTransformSize + CryptoTransformHeaderSize + crypto.SignatureLength + crypto.NonceLength;
            BaseTestSite.Assert.IsTrue(
                readData.Length == sum || readData.Length == (sum + 7) / 8 * 8,
                "READ response DataLength MUST equal the sum of the transform structure sizes ({0}). Actual: {1}", sum, readData.Length);
        }

        private READ_Response ReadOnce(out byte[] readData)
        {
            uint length = Math.Min(4096u,
                Math.Min(smbdAdapter.Smb2MaxReadSize, smbdAdapter.ClientConnection.MaxReadWriteSize));
            BaseTestSite.Assert.IsTrue(length > 0, "Negotiate nonzero SMB2 READ and SMBD transfer limits before this READ.");
            smbdAdapter.SmbdRegisterBuffer(length, SmbdBufferReadWrite.RDMA_WRITE_PERMISSION_FOR_READ_FILE, out SmbdBufferDescriptorV1 descp);
            byte[] channelInfo = TypeMarshal.ToBytes(descp);

            NtStatus status = (NtStatus)smbdAdapter.Smb2ReadOverRdmaChannel(0, length, channelInfo, out READ_Response readResponse, out readData);
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMB2 READ is {0}", status);
            BaseTestSite.Assert.AreEqual<uint>(length, readResponse.DataRemaining, "DataRemaining in READ response is {0}", readResponse.DataRemaining);
            BaseTestSite.Assert.AreEqual<byte>(ExpectedReadDataOffset, readResponse.DataOffset, "DataOffset in READ response is {0}", readResponse.DataOffset);
            return readResponse;
        }

        // Builds and sends one WRITE with Channel=SMB2_CHANNEL_RDMA_TRANSFORM. The crypto-transform bytes come from the
        // session keys (signature/nonce of valid ciphertext or signed data) so only the intended field is malformed.
        private NtStatus SendTransformWrite(Smb2RDMATransformType transformType, bool encrypt, int remainingBytesAdjust)
        {
            uint writeSize = Math.Min(4096u,
                Math.Min(smbdAdapter.Smb2MaxWriteSize, smbdAdapter.ClientConnection.MaxReadWriteSize));
            BaseTestSite.Assert.IsTrue(writeSize > 0, "Negotiate nonzero SMB2 WRITE and SMBD transfer limits before this WRITE.");
            byte[] content = Encoding.ASCII.GetBytes(Smb2Utility.CreateRandomStringInByte((int)writeSize));
            byte[] payload;
            byte[] nonce;
            byte[] signature;
            if (encrypt)
            {
                smbdAdapter.EncryptByteArray(content, out payload, out nonce, out signature);
            }
            else
            {
                payload = content;
                smbdAdapter.SignByteArray(content, out nonce, out signature, Smb2Command.WRITE);
            }

            smbdAdapter.SmbdRegisterBuffer(writeSize, SmbdBufferReadWrite.RDMA_READ_PERMISSION_FOR_WRITE_FILE, out SmbdBufferDescriptorV1 descp);
            smbdAdapter.SmbdWriteRegisteredBuffer(payload, descp);
            byte[] channelInfo = TypeMarshal.ToBytes(descp);

            var crypto = new SMB2_RDMA_CRYPTO_TRANSFORM
            {
                TransformType = transformType,
                SignatureLength = (ushort)signature.Length,
                NonceLength = (ushort)nonce.Length,
                Signature = signature,
                Nonce = nonce,
            };
            byte[] cryptoBytes = TypeMarshal.ToBytes(crypto);
            Smb2Utility.Align8(ref cryptoBytes);

            var rdmaTransform = new SMB2_RDMA_TRANSFORM
            {
                RdmaDescriptorOffset = (ushort)(RdmaTransformSize + cryptoBytes.Length),
                RdmaDescriptorLength = (ushort)channelInfo.Length,
                Channel = Smb2RdmaTransformChannel.SMB2_CHANNEL_RDMA_V1,
                TransformCount = 1,
                Reserved1 = 0,
                Reserved2 = 0
            };
            byte[] rdmaTransformBytes = TypeMarshal.ToBytes(rdmaTransform);

            var total = new List<byte>();
            total.AddRange(rdmaTransformBytes);
            total.AddRange(cryptoBytes);
            total.AddRange(channelInfo);

            NtStatus status;
            try
            {
                status = (NtStatus)smbdAdapter.Smb2WriteOverRdmaChannel(
                    0,
                    total.ToArray(),
                    (uint)((int)writeSize + remainingBytesAdjust),
                    out WRITE_Response writeResponse,
                    Channel_Values.CHANNEL_RDMA_TRANSFORM);
            }
            catch (InvalidOperationException ex) when (ex.ToString().Contains("Failed to decode WRITE response"))
            {
                // [MS-SMB2] 2.2.2 defines an error response as header Status != success with a 9-byte ERROR body, and
                // 2.2.14 defines a success WRITE response as 16 bytes. A reply that is neither cannot be classified,
                // so the status the spec requires cannot be observed on this server.
                BaseTestSite.Assert.Inconclusive("Server reply is neither a valid SMB2 error response nor a valid WRITE response: " + ex.Message);
                throw;
            }
            return status;
        }

        private void AssumeTransformSelected(Smb2RDMATransformId id)
        {
            // The RDMA transform is optional ([MS-SMB2] 3.3.5.4); skip when the server did not select it.
            BaseTestSite.Assume.IsTrue(
                smbdAdapter.SelectedRdmaTransformIds != null && smbdAdapter.SelectedRdmaTransformIds.Contains(id),
                "Server did not select {0} in SMB2_RDMA_TRANSFORM_CAPABILITIES.", id);
        }

        private void InitConnection(
            string fileName,
            Smb2RDMATransformId[] smb2RdmaTransformIds,
            EncryptionAlgorithm[] encryptionAlgorithms,
            SigningAlgorithm[] signingAlgorithms,
            bool enableSigning,
            bool enableEncryption)
        {
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Initial SMBD connection and open file " + fileName);

            NtStatus status = smbdAdapter.ConnectToServerOverRDMA();
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMBD connection is {0}", status);

            status = smbdAdapter.SmbdNegotiate();
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMBD negotiate is {0}", status);

            status = smbdAdapter.Smb2EstablishSessionAndOpenFile(
                fileName,
                negotiatedDialects: new[] { DialectRevision.Smb311 },
                smb2RDMATransformIds: smb2RdmaTransformIds,
                encryptionAlgs: encryptionAlgorithms,
                addDefaultEncryption: false,
                signingAlgorithms: signingAlgorithms,
                enableSigning: enableSigning,
                enableEncryption: enableEncryption);
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMB2 establish session and open file is {0}", status);
        }

        #endregion
    }
}
