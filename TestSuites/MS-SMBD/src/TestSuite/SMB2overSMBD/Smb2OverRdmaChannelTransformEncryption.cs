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
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace Microsoft.Protocol.TestSuites.Smbd.TestSuite
{
    [TestClass]
    public class Smb2OverRdmaChannelTransformEncryption : Smb2OverSmbdTestBase
    {
        #region Variables
        // Length of Smb2 Packet Header + Smb2 READ Response before Buffer
        private const int EXPECTED_READ_DATA_OFFSET = 80;
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

        #region Test Cases

        [TestMethod()]
        [TestCategory("BVT")]
        [TestCategory("Positive")]
        [TestCategory("Encryption")]
        [TestCategory("Smb2OverRdmaChannel")]
        [Description("Verify SMB2 can read file with the effective maximum single RDMA READ size over RDMA channel encrypted with AES128_CCM")]
        // [MS-SMB2] 3.3.5.12: when Request.IsEncrypted and Connection.RDMATransformIds includes ENCRYPTION, the READ response
        // Buffer MUST be SMB2_RDMA_TRANSFORM + SMB2_RDMA_CRYPTO_TRANSFORM (type ENCRYPTION, 11-byte nonce for CCM / 12-byte for GCM).
        // 2.2.43/2.2.43.1: TransformCount > 0; Signature <= 16 bytes. 3.2.5.11: client decrypts the registered buffer.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.12 Receiving an SMB2 READ Request; 2.2.43 SMB2_RDMA_TRANSFORM; 2.2.43.1 SMB2_RDMA_CRYPTO_TRANSFORM; 3.2.5.11 Receiving an SMB2 READ Response")]
        [TestProperty("SpecCompliance", "TODO")]
        public void BVT_Smb2OverRdmaChannelTransform_Encryption_ReadLargeFile_AES128CCM()
        {
            // TODO(spec): ReadOverRdma_Encryption asserts the response Buffer length equals the 8-byte-padded crypto transform.
            // 2.2.43.1 Padding exists only so that following channel information is 8-byte aligned (none in a READ response), so exact
            // padded length is Windows-specific. Also the RDMA payload is not decrypted/authenticated (3.2.5.11 3.2) and the nonce length is not checked against CipherId.
            Smb2RDMATransformId[] smb2RdmaTransformIds = new Smb2RDMATransformId[] { Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_ENCRYPTION };
            ReadOverRdma_Encryption(smb2RdmaTransformIds: smb2RdmaTransformIds, encryptionAlgorithm: EncryptionAlgorithm.ENCRYPTION_AES128_CCM);
        }

        [TestMethod()]
        [TestCategory("Positive")]
        [TestCategory("Encryption")]
        [TestCategory("Smb2OverRdmaChannel")]
        [Description("Verify SMB2 can read file with the effective maximum single RDMA READ size over RDMA channel encrypted with AES128_GCM")]
        // [MS-SMB2] 3.3.5.12: encrypted READ over RDMA returns SMB2_RDMA_TRANSFORM + SMB2_RDMA_CRYPTO_TRANSFORM (ENCRYPTION, 12-byte nonce for GCM).
        // 2.2.43/2.2.43.1: TransformCount > 0; Signature <= 16 bytes. 3.2.5.11: client decrypts the registered buffer.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.12 Receiving an SMB2 READ Request; 2.2.43 SMB2_RDMA_TRANSFORM; 2.2.43.1 SMB2_RDMA_CRYPTO_TRANSFORM; 3.2.5.11 Receiving an SMB2 READ Response")]
        [TestProperty("SpecCompliance", "TODO")]
        public void Smb2OverRdmaChannelTransform_Encryption_ReadLargeFile_AES128GCM()
        {
            // TODO(spec): same as BVT_..._ReadLargeFile_AES128CCM - exact 8-byte-padded Buffer length is not mandated for a READ response
            // (2.2.43.1 Padding), and the payload is not decrypted/authenticated; nonce length (12 for GCM) not checked.
            Smb2RDMATransformId[] smb2RdmaTransformIds = new Smb2RDMATransformId[] { Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_ENCRYPTION };
            ReadOverRdma_Encryption(smb2RdmaTransformIds: smb2RdmaTransformIds, encryptionAlgorithm: EncryptionAlgorithm.ENCRYPTION_AES128_GCM);
        }

        [TestMethod()]
        [TestCategory("Positive")]
        [TestCategory("Encryption")]
        [TestCategory("Smb2OverRdmaChannel")]
        [Description("Verify SMB2 can read file with the effective maximum single RDMA READ size over RDMA channel encrypted with AES256_CCM")]
        // [MS-SMB2] 3.3.5.12: encrypted READ over RDMA returns SMB2_RDMA_TRANSFORM + SMB2_RDMA_CRYPTO_TRANSFORM (ENCRYPTION, 11-byte nonce for CCM).
        // 2.2.43/2.2.43.1: TransformCount > 0; Signature <= 16 bytes. 3.2.5.11: client decrypts the registered buffer.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.12 Receiving an SMB2 READ Request; 2.2.43 SMB2_RDMA_TRANSFORM; 2.2.43.1 SMB2_RDMA_CRYPTO_TRANSFORM; 3.2.5.11 Receiving an SMB2 READ Response")]
        [TestProperty("SpecCompliance", "TODO")]
        public void Smb2OverRdmaChannelTransform_Encryption_ReadLargeFile_AES256CCM()
        {
            // TODO(spec): same as BVT_..._ReadLargeFile_AES128CCM - exact 8-byte-padded Buffer length is not mandated for a READ response
            // (2.2.43.1 Padding), and the payload is not decrypted/authenticated; nonce length (11 for CCM) not checked.
            Smb2RDMATransformId[] smb2RdmaTransformIds = new Smb2RDMATransformId[] { Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_ENCRYPTION };
            ReadOverRdma_Encryption(smb2RdmaTransformIds: smb2RdmaTransformIds, encryptionAlgorithm: EncryptionAlgorithm.ENCRYPTION_AES256_CCM);
        }

        [TestMethod()]
        [TestCategory("Positive")]
        [TestCategory("Encryption")]
        [TestCategory("Smb2OverRdmaChannel")]
        [Description("Verify SMB2 can read file with the effective maximum single RDMA READ size over RDMA channel encrypted with AES256_GCM")]
        // [MS-SMB2] 3.3.5.12: encrypted READ over RDMA returns SMB2_RDMA_TRANSFORM + SMB2_RDMA_CRYPTO_TRANSFORM (ENCRYPTION, 12-byte nonce for GCM).
        // 2.2.43/2.2.43.1: TransformCount > 0; Signature <= 16 bytes. 3.2.5.11: client decrypts the registered buffer.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.12 Receiving an SMB2 READ Request; 2.2.43 SMB2_RDMA_TRANSFORM; 2.2.43.1 SMB2_RDMA_CRYPTO_TRANSFORM; 3.2.5.11 Receiving an SMB2 READ Response")]
        [TestProperty("SpecCompliance", "TODO")]
        public void Smb2OverRdmaChannelTransform_Encryption_ReadLargeFile_AES256GCM()
        {
            // TODO(spec): same as BVT_..._ReadLargeFile_AES128CCM - exact 8-byte-padded Buffer length is not mandated for a READ response
            // (2.2.43.1 Padding), and the payload is not decrypted/authenticated; nonce length (12 for GCM) not checked.
            Smb2RDMATransformId[] smb2RdmaTransformIds = new Smb2RDMATransformId[] { Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_ENCRYPTION };
            ReadOverRdma_Encryption(smb2RdmaTransformIds: smb2RdmaTransformIds, encryptionAlgorithm: EncryptionAlgorithm.ENCRYPTION_AES256_GCM);
        }

        [TestMethod()]
        [TestCategory("Positive")]
        [TestCategory("Encryption")]
        [TestCategory("Smb2OverRdmaChannel")]
        [Description("Verify SMB2 can read file with the effective maximum single RDMA READ size over R" +
            "DMA channel with multiple SMBD READ requests and responses encrypted with AES128_CCM.")]
        // [MS-SMB2] 3.3.5.12: each encrypted READ over RDMA returns SMB2_RDMA_TRANSFORM + SMB2_RDMA_CRYPTO_TRANSFORM (ENCRYPTION).
        // 2.2.43.1: Nonce MUST NOT be reused within a session. 3.2.5.11: client decrypts the registered buffer.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.12 Receiving an SMB2 READ Request; 2.2.43 SMB2_RDMA_TRANSFORM; 2.2.43.1 SMB2_RDMA_CRYPTO_TRANSFORM; 3.2.5.11 Receiving an SMB2 READ Response")]
        [TestProperty("SpecCompliance", "TODO")]
        public void Smb2OverRdmaChannelTransform_Encryption_ReadMultipleOperation()
        {
            // TODO(spec): same as BVT_..._ReadLargeFile_AES128CCM (padded-length assertion, no decryption). Nonce uniqueness across the
            // 64 responses (2.2.43.1) is also not verified.
            Smb2RDMATransformId[] smb2RdmaTransformIds = new Smb2RDMATransformId[] { Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_ENCRYPTION };
            const uint OPERATION_COUNT = 64;
            ReadOverRdma_Encryption(OPERATION_COUNT, smb2RdmaTransformIds: smb2RdmaTransformIds);
        }

        [TestMethod()]
        [TestCategory("BVT")]
        [TestCategory("Positive")]
        [TestCategory("Encryption")]
        [TestCategory("Smb2OverRdmaChannel")]
        [Description("Verify SMB2 can write file with the effective maximum single RDMA WRITE size over RDMA channel encrypted with AES128_CCM")]
        // [MS-SMB2] 3.2.4.7 / 3.3.5.13: client sends WRITE with Channel=SMB2_CHANNEL_RDMA_TRANSFORM, SMB2_RDMA_TRANSFORM + one ENCRYPTION
        // SMB2_RDMA_CRYPTO_TRANSFORM (nonce 11 bytes for CCM) + descriptors at an 8-byte aligned offset; server MUST RDMA-read, decrypt with
        // Connection.CipherId and succeed.
        [TestProperty("SpecSection", "[MS-SMB2] 3.2.4.7 Application Requests Writing to a File or Named Pipe; 3.3.5.13 Receiving an SMB2 WRITE Request; 2.2.43 SMB2_RDMA_TRANSFORM; 2.2.43.1 SMB2_RDMA_CRYPTO_TRANSFORM")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void BVT_Smb2OverRdmaChannelTransform_Encryption_WriteLargeFile_AES128CCM()
        {
            Smb2RDMATransformId[] smb2RdmaTransformIds = new Smb2RDMATransformId[] { Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_ENCRYPTION };
            WriteOverRdma_Encryption(
                smb2RdmaTransformIds: smb2RdmaTransformIds,
                channel: Channel_Values.CHANNEL_RDMA_TRANSFORM,
                encryptionAlgorithm: EncryptionAlgorithm.ENCRYPTION_AES128_CCM);
        }

        [TestMethod()]
        [TestCategory("Positive")]
        [TestCategory("Encryption")]
        [TestCategory("Smb2OverRdmaChannel")]
        [Description("Verify SMB2 can write file with the effective maximum single RDMA WRITE size over RDMA channel encrypted with AES128_GCM")]
        // [MS-SMB2] 3.2.4.7 / 3.3.5.13: client sends WRITE with Channel=SMB2_CHANNEL_RDMA_TRANSFORM, SMB2_RDMA_TRANSFORM + one ENCRYPTION
        // SMB2_RDMA_CRYPTO_TRANSFORM (nonce 12 bytes for GCM) + descriptors at an 8-byte aligned offset; server MUST RDMA-read, decrypt with
        // Connection.CipherId and succeed.
        [TestProperty("SpecSection", "[MS-SMB2] 3.2.4.7 Application Requests Writing to a File or Named Pipe; 3.3.5.13 Receiving an SMB2 WRITE Request; 2.2.43 SMB2_RDMA_TRANSFORM; 2.2.43.1 SMB2_RDMA_CRYPTO_TRANSFORM")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannelTransform_Encryption_WriteLargeFile_AES128GCM()
        {
            Smb2RDMATransformId[] smb2RdmaTransformIds = new Smb2RDMATransformId[] { Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_ENCRYPTION };
            WriteOverRdma_Encryption(
                smb2RdmaTransformIds: smb2RdmaTransformIds,
                channel: Channel_Values.CHANNEL_RDMA_TRANSFORM,
                encryptionAlgorithm: EncryptionAlgorithm.ENCRYPTION_AES128_GCM);
        }

        [TestMethod()]
        [TestCategory("Positive")]
        [TestCategory("Encryption")]
        [TestCategory("Smb2OverRdmaChannel")]
        [Description("Verify SMB2 can write file with the effective maximum single RDMA WRITE size over RDMA channel encrypted with AES256_CCM")]
        // [MS-SMB2] 3.2.4.7 / 3.3.5.13: client sends WRITE with Channel=SMB2_CHANNEL_RDMA_TRANSFORM, SMB2_RDMA_TRANSFORM + one ENCRYPTION
        // SMB2_RDMA_CRYPTO_TRANSFORM (nonce 11 bytes for CCM) + descriptors at an 8-byte aligned offset; server MUST RDMA-read, decrypt with
        // Connection.CipherId and succeed.
        [TestProperty("SpecSection", "[MS-SMB2] 3.2.4.7 Application Requests Writing to a File or Named Pipe; 3.3.5.13 Receiving an SMB2 WRITE Request; 2.2.43 SMB2_RDMA_TRANSFORM; 2.2.43.1 SMB2_RDMA_CRYPTO_TRANSFORM")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannelTransform_Encryption_WriteLargeFile_AES256CCM()
        {
            Smb2RDMATransformId[] smb2RdmaTransformIds = new Smb2RDMATransformId[] { Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_ENCRYPTION };
            WriteOverRdma_Encryption(
                smb2RdmaTransformIds: smb2RdmaTransformIds,
                channel: Channel_Values.CHANNEL_RDMA_TRANSFORM,
                encryptionAlgorithm: EncryptionAlgorithm.ENCRYPTION_AES256_CCM);
        }

        [TestMethod()]
        [TestCategory("Positive")]
        [TestCategory("Encryption")]
        [TestCategory("Smb2OverRdmaChannel")]
        [Description("Verify SMB2 can write file with the effective maximum single RDMA WRITE size over RDMA channel encrypted with AES256_GCM")]
        // [MS-SMB2] 3.2.4.7 / 3.3.5.13: client sends WRITE with Channel=SMB2_CHANNEL_RDMA_TRANSFORM, SMB2_RDMA_TRANSFORM + one ENCRYPTION
        // SMB2_RDMA_CRYPTO_TRANSFORM (nonce 12 bytes for GCM) + descriptors at an 8-byte aligned offset; server MUST RDMA-read, decrypt with
        // Connection.CipherId and succeed.
        [TestProperty("SpecSection", "[MS-SMB2] 3.2.4.7 Application Requests Writing to a File or Named Pipe; 3.3.5.13 Receiving an SMB2 WRITE Request; 2.2.43 SMB2_RDMA_TRANSFORM; 2.2.43.1 SMB2_RDMA_CRYPTO_TRANSFORM")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannelTransform_Encryption_WriteLargeFile_AES256GCM()
        {
            Smb2RDMATransformId[] smb2RdmaTransformIds = new Smb2RDMATransformId[] { Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_ENCRYPTION };
            WriteOverRdma_Encryption(
                smb2RdmaTransformIds: smb2RdmaTransformIds,
                channel: Channel_Values.CHANNEL_RDMA_TRANSFORM,
                encryptionAlgorithm: EncryptionAlgorithm.ENCRYPTION_AES256_GCM);
        }

        [TestMethod()]
        [TestCategory("Positive")]
        [TestCategory("Encryption")]
        [TestCategory("Smb2OverRdmaChannel")]
        [Description("Verify SMB2 can write file with the effective maximum single RDMA WRITE size over RDMA channel encrypted with AES128_CCM " +
            "with multiple SMBD WRITE requests and responses.")]
        // [MS-SMB2] 3.2.4.7 / 3.3.5.13 with 2.2.43.1: same as the single WRITE case, repeated 64 times; Nonce "MUST NOT be reused ... within a session".
        [TestProperty("SpecSection", "[MS-SMB2] 3.2.4.7 Application Requests Writing to a File or Named Pipe; 3.3.5.13 Receiving an SMB2 WRITE Request; 2.2.43.1 SMB2_RDMA_CRYPTO_TRANSFORM")]
        [TestProperty("SpecCompliance", "TODO")]
        public void Smb2OverRdmaChannelTransform_Encryption_WriteMultipleOperation()
        {
            // TODO(spec): WriteOverRdma_Encryption encrypts once and reuses the same ciphertext, Nonce and Signature for every operation,
            // violating 2.2.43.1 (Nonce MUST NOT be reused within a session). Generate a fresh nonce/ciphertext per WRITE.
            Smb2RDMATransformId[] smb2RdmaTransformIds = new Smb2RDMATransformId[] { Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_ENCRYPTION };
            const uint OPERATION_COUNT = 64;
            WriteOverRdma_Encryption(OPERATION_COUNT, smb2RdmaTransformIds: smb2RdmaTransformIds, channel: Channel_Values.CHANNEL_RDMA_TRANSFORM);
        }

        [TestMethod()]
        [TestCategory("Encryption")]
        [TestCategory("Smb2OverRdmaChannel")]
        [Description("Verify SMB2 can write file with the effective maximum single RDMA WRITE size over RDMA channel encrypted with AES128_CCM fails " +
            "if RDMATransformId is not specified on Connection Open")]
        // [MS-SMB2] 3.3.5.13 step 1.1: Dialect 3.1.1, Channel=SMB2_CHANNEL_RDMA_TRANSFORM and Connection.RDMATransformIds empty -> STATUS_INVALID_PARAMETER.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.13 Receiving an SMB2 WRITE Request")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannelTransform_Encryption_WriteLargeFile_NoTransformIds_Fails()
        {
            WriteOverRdma_Encryption(channel: Channel_Values.CHANNEL_RDMA_TRANSFORM);
        }

        [TestMethod()]
        [TestCategory("Encryption")]
        [TestCategory("Smb2OverRdmaChannel")]
        [Description("Verify SMB2 can write file with the effective maximum single RDMA WRITE size over RDMA channel encrypted with AES128_CCM fails " +
            "if RDMA_TRANSFORM TransformCount is set to zero")]
        // [MS-SMB2] 3.3.5.13 step 1.3 / 2.2.43: TransformCount is 0 (MUST be > 0) -> STATUS_INVALID_PARAMETER.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.13 Receiving an SMB2 WRITE Request; 2.2.43 SMB2_RDMA_TRANSFORM")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannelTransform_Encryption_WriteLargeFile_ZeroTransformCount_Fails()
        {
            Smb2RDMATransformId[] smb2RdmaTransformIds = new Smb2RDMATransformId[] { Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_ENCRYPTION };
            WriteOverRdma_Encryption(smb2RdmaTransformIds: smb2RdmaTransformIds, setZeroTransformCount: true);
        }

        [TestMethod()]
        [TestCategory("Encryption")]
        [TestCategory("Smb2OverRdmaChannel")]
        [Description("Verify SMB2 can write file with the effective maximum single RDMA WRITE size over RDMA channel encrypted with AES128_CCM fails " +
            "if multiple RDMA_TRANSFORM_TYPE_ENCRYPTION RDMA_CRYPTO_TRANSFORM structure are used for the request")]
        // [MS-SMB2] 3.3.5.13 steps 1.7/1.8: more than one SMB2_RDMA_CRYPTO_TRANSFORM of type ENCRYPTION -> STATUS_INVALID_PARAMETER.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.13 Receiving an SMB2 WRITE Request")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannelTransform_Encryption_WriteLargeFile_MultipleEncryptionStructure_Fails()
        {
            Smb2RDMATransformId[] smb2RdmaTransformIds = new Smb2RDMATransformId[] { Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_ENCRYPTION };
            WriteOverRdma_Encryption(smb2RdmaTransformIds: smb2RdmaTransformIds, addEncryptionTransform: true);
        }

        [TestMethod()]
        [TestCategory("Encryption")]
        [TestCategory("Smb2OverRdmaChannel")]
        [Description("Verify SMB2 can write file with the effective maximum single RDMA WRITE size over RDMA channel encrypted with AES128_CCM fails " +
            "if an RDMA_TRANSFORM_TYPE_ENCRYPTION and RDMA_TRANSFORM_TYPE_SIGNING structure are used together for the request")]
        // [MS-SMB2] 3.3.5.13 step 1.9: one ENCRYPTION and one SIGNING SMB2_RDMA_CRYPTO_TRANSFORM together -> STATUS_INVALID_PARAMETER.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.13 Receiving an SMB2 WRITE Request")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannelTransform_Encryption_WriteLargeFile_EncryptionAndSigningStructure_Fails()
        {
            // WHAT: send exactly one ENCRYPTION and one SIGNING structure (TransformCount 2) by setting only addSigningTransform.
            // WHY: previously addEncryptionTransform was also set, giving two ENCRYPTION structs, TransformCount 3 and no SIGNING
            //      struct on the wire, so STATUS_INVALID_PARAMETER came from a malformed request, not from the intended condition.
            // SPEC: [MS-SMB2] 3.3.5.13 step 1.9 - ENCRYPTION and SIGNING SMB2_RDMA_CRYPTO_TRANSFORM structures together => STATUS_INVALID_PARAMETER.
            Smb2RDMATransformId[] smb2RdmaTransformIds = new Smb2RDMATransformId[] {
                Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_SIGNING,
                Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_ENCRYPTION
            };
            SigningAlgorithm[] signingAlgorithms = new SigningAlgorithm[]
            {
                SigningAlgorithm.AES_GMAC
            };
            WriteOverRdma_Encryption(smb2RdmaTransformIds: smb2RdmaTransformIds, addSigningTransform: true, signingAlgorithms: signingAlgorithms);
        }

        [TestMethod()]
        [TestCategory("Encryption")]
        [TestCategory("Smb2OverRdmaChannel")]
        [Description("Verify SMB2 can write file with the effective maximum single RDMA WRITE size over RDMA channel encrypted with AES128_CCM fails " +
            "if the RDMA_CRYPTO_TRANSFORM structure is not 8-byte aligned")]
        // [MS-SMB2] 3.3.5.13 step 1.11 / 2.2.43.1 Padding: SMB_DIRECT_BUFFER_DESCRIPTOR_V1 array not at the first 8-byte aligned offset
        // after SMB2_RDMA_CRYPTO_TRANSFORM -> STATUS_INVALID_PARAMETER.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.13 Receiving an SMB2 WRITE Request; 2.2.43.1 SMB2_RDMA_CRYPTO_TRANSFORM")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannelTransform_Encryption_WriteLargeFile_BufferNotAligned_Fails()
        {
            Smb2RDMATransformId[] smb2RdmaTransformIds = new Smb2RDMATransformId[] { Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_ENCRYPTION };
            WriteOverRdma_Encryption(
                smb2RdmaTransformIds: smb2RdmaTransformIds,
                channel: Channel_Values.CHANNEL_RDMA_TRANSFORM,
                encryptionAlgorithm: EncryptionAlgorithm.ENCRYPTION_AES128_GCM,
                shouldAlignBuffer: false);
        }

        [TestMethod()]
        [TestCategory("Encryption")]
        [TestCategory("Smb2OverRdmaChannel")]
        [Description("Verify SMB2 can write file with the effective maximum single RDMA WRITE size over RDMA channel encrypted fails " +
            "if the RDMA_CRYPTO_TRANSFORM SignatureLength is greater than 16 bytes")]
        // [MS-SMB2] 3.3.5.13 step 3.1.1 / 2.2.43.1: SignatureLength greater than 16 -> server MUST fail with STATUS_AUTH_TAG_MISMATCH.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.13 Receiving an SMB2 WRITE Request; 2.2.43.1 SMB2_RDMA_CRYPTO_TRANSFORM")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannelTransform_Encryption_WriteLargeFile_IncreaseSignatureLength_Fails()
        {
            Smb2RDMATransformId[] smb2RdmaTransformIds = new Smb2RDMATransformId[] { Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_ENCRYPTION };
            WriteOverRdma_Encryption(
                smb2RdmaTransformIds: smb2RdmaTransformIds,
                channel: Channel_Values.CHANNEL_RDMA_TRANSFORM,
                encryptionAlgorithm: EncryptionAlgorithm.ENCRYPTION_AES128_GCM,
                shouldIncreaseSignature: true);
        }

        [TestMethod()]
        [TestCategory("Encryption")]
        [TestCategory("Smb2OverRdmaChannel")]
        [Description("Verify SMB2 can write file with the effective maximum single RDMA WRITE size over RDMA channel encrypted with AES128_CCM fails " +
            "if the RDMA_CRYPTO_TRANSFORM NonceLength is greater than 11 bytes")]
        // [MS-SMB2] 3.3.5.13 step 3.1.2: CipherId AES-128-CCM and NonceLength != 11 -> STATUS_AUTH_TAG_MISMATCH.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.13 Receiving an SMB2 WRITE Request")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannelTransform_Encryption_WriteLargeFile_IncreaseNonceLength_AES128CCM_Fails()
        {
            Smb2RDMATransformId[] smb2RdmaTransformIds = new Smb2RDMATransformId[] { Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_ENCRYPTION };
            WriteOverRdma_Encryption(
                smb2RdmaTransformIds: smb2RdmaTransformIds,
                channel: Channel_Values.CHANNEL_RDMA_TRANSFORM,
                encryptionAlgorithm: EncryptionAlgorithm.ENCRYPTION_AES128_CCM,
                shouldIncreaseNonce: true);
        }

        [TestMethod()]
        [TestCategory("Encryption")]
        [TestCategory("Smb2OverRdmaChannel")]
        [Description("Verify SMB2 can write file with the effective maximum single RDMA WRITE size over RDMA channel encrypted with AES128_GCM fails " +
            "if the RDMA_CRYPTO_TRANSFORM NonceLength is greater than 12 bytes")]
        // [MS-SMB2] 3.3.5.13 step 3.1.3: CipherId AES-128-GCM and NonceLength != 12 -> STATUS_AUTH_TAG_MISMATCH.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.13 Receiving an SMB2 WRITE Request")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannelTransform_Encryption_WriteLargeFile_IncreaseNonceLength_AES128GCM_Fails()
        {
            Smb2RDMATransformId[] smb2RdmaTransformIds = new Smb2RDMATransformId[] { Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_ENCRYPTION };
            WriteOverRdma_Encryption(
                smb2RdmaTransformIds: smb2RdmaTransformIds,
                encryptionAlgorithm: EncryptionAlgorithm.ENCRYPTION_AES128_GCM,
                shouldIncreaseNonce: true);
        }

        [TestMethod()]
        [TestCategory("Encryption")]
        [TestCategory("Smb2OverRdmaChannel")]
        [Description("Verify SMB2 can write file with the effective maximum single RDMA WRITE size over RDMA channel encrypted with AES256_CCM fails " +
            "if the RDMA_CRYPTO_TRANSFORM NonceLength is greater than 11 bytes")]
        // [MS-SMB2] 3.3.5.13 step 3.1.2: CipherId AES-256-CCM and NonceLength != 11 -> STATUS_AUTH_TAG_MISMATCH.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.13 Receiving an SMB2 WRITE Request")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannelTransform_Encryption_WriteLargeFile_IncreaseNonceLength_AES256CCM_Fails()
        {
            Smb2RDMATransformId[] smb2RdmaTransformIds = new Smb2RDMATransformId[] { Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_ENCRYPTION };
            WriteOverRdma_Encryption(
                smb2RdmaTransformIds: smb2RdmaTransformIds,
                channel: Channel_Values.CHANNEL_RDMA_TRANSFORM,
                encryptionAlgorithm: EncryptionAlgorithm.ENCRYPTION_AES256_CCM,
                shouldIncreaseNonce: true);
        }

        [TestMethod()]
        [TestCategory("Encryption")]
        [TestCategory("Smb2OverRdmaChannel")]
        [Description("Verify SMB2 can write file with the effective maximum single RDMA WRITE size over RDMA channel encrypted with AES256_GCM fails " +
            "if the RDMA_CRYPTO_TRANSFORM NonceLength is greater than 12 bytes")]
        // [MS-SMB2] 3.3.5.13 step 3.1.3: CipherId AES-256-GCM and NonceLength != 12 -> STATUS_AUTH_TAG_MISMATCH.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.13 Receiving an SMB2 WRITE Request")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannelTransform_Encryption_WriteLargeFile_IncreaseNonceLength_AES256GCM_Fails()
        {
            Smb2RDMATransformId[] smb2RdmaTransformIds = new Smb2RDMATransformId[] { Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_ENCRYPTION };
            WriteOverRdma_Encryption(
                smb2RdmaTransformIds: smb2RdmaTransformIds,
                encryptionAlgorithm: EncryptionAlgorithm.ENCRYPTION_AES256_GCM,
                shouldIncreaseNonce: true);
        }

        [TestMethod()]
        [TestCategory("Encryption")]
        [TestCategory("Smb2OverRdmaChannel")]
        [Description("Verify SMB2 can write file with the effective maximum single RDMA WRITE size over RDMA channel encrypted with AES128_CCM fails " +
            "if the RDMA_CRYPTO_TRANSFORM NonceLength is less than 11 bytes")]
        // [MS-SMB2] 3.3.5.13 step 3.1.2: CipherId AES-128-CCM and NonceLength != 11 -> STATUS_AUTH_TAG_MISMATCH.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.13 Receiving an SMB2 WRITE Request")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannelTransform_Encryption_WriteLargeFile_DecreaseNonceLength_AES128CCM_Fails()
        {
            Smb2RDMATransformId[] smb2RdmaTransformIds = new Smb2RDMATransformId[] { Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_ENCRYPTION };
            WriteOverRdma_Encryption(
                smb2RdmaTransformIds: smb2RdmaTransformIds,
                channel: Channel_Values.CHANNEL_RDMA_TRANSFORM,
                encryptionAlgorithm: EncryptionAlgorithm.ENCRYPTION_AES128_CCM,
                shouldDecreaseNonce: true);
        }

        [TestMethod()]
        [TestCategory("Encryption")]
        [TestCategory("Smb2OverRdmaChannel")]
        [Description("Verify SMB2 can write file with the effective maximum single RDMA WRITE size over RDMA channel encrypted with AES128_GCM fails " +
            "if the RDMA_CRYPTO_TRANSFORM NonceLength is less than 12 bytes")]
        // [MS-SMB2] 3.3.5.13 step 3.1.3: CipherId AES-128-GCM and NonceLength != 12 -> STATUS_AUTH_TAG_MISMATCH.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.13 Receiving an SMB2 WRITE Request")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannelTransform_Encryption_WriteLargeFile_DecreaseNonceLength_AES128GCM_Fails()
        {
            Smb2RDMATransformId[] smb2RdmaTransformIds = new Smb2RDMATransformId[] { Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_ENCRYPTION };
            WriteOverRdma_Encryption(
                smb2RdmaTransformIds: smb2RdmaTransformIds,
                encryptionAlgorithm: EncryptionAlgorithm.ENCRYPTION_AES128_GCM,
                shouldDecreaseNonce: true);
        }

        [TestMethod()]
        [TestCategory("Encryption")]
        [TestCategory("Smb2OverRdmaChannel")]
        [Description("Verify SMB2 can write file with the effective maximum single RDMA WRITE size over RDMA channel encrypted with AES256_CCM fails " +
            "if the RDMA_CRYPTO_TRANSFORM NonceLength is less than 11 bytes")]
        // [MS-SMB2] 3.3.5.13 step 3.1.2: CipherId AES-256-CCM and NonceLength != 11 -> STATUS_AUTH_TAG_MISMATCH.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.13 Receiving an SMB2 WRITE Request")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannelTransform_Encryption_WriteLargeFile_DecreaseNonceLength_AES256CCM_Fails()
        {
            Smb2RDMATransformId[] smb2RdmaTransformIds = new Smb2RDMATransformId[] { Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_ENCRYPTION };
            WriteOverRdma_Encryption(
                smb2RdmaTransformIds: smb2RdmaTransformIds,
                channel: Channel_Values.CHANNEL_RDMA_TRANSFORM,
                encryptionAlgorithm: EncryptionAlgorithm.ENCRYPTION_AES256_CCM,
                shouldDecreaseNonce: true);
        }

        [TestMethod()]
        [TestCategory("Encryption")]
        [TestCategory("Smb2OverRdmaChannel")]
        [Description("Verify SMB2 can write file with the effective maximum single RDMA WRITE size over RDMA channel encrypted with AES256_GCM fails " +
            "if the RDMA_CRYPTO_TRANSFORM NonceLength is less than 12 bytes")]
        // [MS-SMB2] 3.3.5.13 step 3.1.3: CipherId AES-256-GCM and NonceLength != 12 -> STATUS_AUTH_TAG_MISMATCH.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.13 Receiving an SMB2 WRITE Request")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2OverRdmaChannelTransform_Encryption_WriteLargeFile_DecreaseNonceLength_AES256GCM_Fails()
        {
            Smb2RDMATransformId[] smb2RdmaTransformIds = new Smb2RDMATransformId[] { Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_ENCRYPTION };
            WriteOverRdma_Encryption(
                smb2RdmaTransformIds: smb2RdmaTransformIds,
                encryptionAlgorithm: EncryptionAlgorithm.ENCRYPTION_AES256_GCM,
                shouldDecreaseNonce: true);
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
        /// <param name="encryptionAlgorithm">EncryptionAlgorithm to test</param>
        /// <param name="smb2RdmaTransformIds">The RDMA_TRANSFORM_IDs to use for NegotiateContext</param>
        public void ReadOverRdma_Encryption(
    uint operationCount = 1,
    Smb2RDMATransformId[] smb2RdmaTransformIds = null,
    EncryptionAlgorithm encryptionAlgorithm =
        EncryptionAlgorithm.ENCRYPTION_AES128_CCM)
        {
            const int rdmaTransformHeaderSize = 16;
            const int rdmaCryptoTransformHeaderSize = 8;
            const int authenticationTagSize = 16;

            if (smb2RdmaTransformIds == null)
            {
                smb2RdmaTransformIds = new[]
                {
            Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_ENCRYPTION
        };
            }

            BaseTestSite.Assert.IsTrue(
                Array.IndexOf(
                    smb2RdmaTransformIds,
                    Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_ENCRYPTION) >= 0,
                "The test must advertise SMB2_RDMA_TRANSFORM_ENCRYPTION.");

            EncryptionAlgorithm[] encryptionAlgorithms =
            {
        encryptionAlgorithm
    };

            InitSmbdConnectionForTestCases(
                smbdAdapter.TestConfig.TestFileName_LargeFile,
                smb2RdmaTransformIds,
                addDefaultEncryption: false,
                encryptionAlgorithms: encryptionAlgorithms);

            // RDMA transform is optional ([MS-SMB2] 3.3.5.4): skip when the server does not select it.
            BaseTestSite.Assume.IsTrue(
                smbdAdapter.SelectedRdmaTransformIds != null &&
                Array.IndexOf(
                    smbdAdapter.SelectedRdmaTransformIds,
                    Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_ENCRYPTION) >= 0,
                "Server does not select SMB2_RDMA_TRANSFORM_ENCRYPTION.");

            uint readSize;
            uint effectiveOperationCount;

            ComputeReadPlan(
                operationCount,
                out readSize,
                out effectiveOperationCount);

            BaseTestSite.Log.Add(
                LogEntryKind.Debug,
                "ReadSize is {0}",
                readSize);

            BaseTestSite.Log.Add(
                LogEntryKind.Debug,
                "Read operation count is {0}",
                effectiveOperationCount);

            BaseTestSite.Log.Add(
                LogEntryKind.TestStep,
                "Send each READ request according to the SMB2 read-file limit.");

            for (int i = 0; i < effectiveOperationCount; ++i)
            {
                uint length = (uint)Math.Min(
                    readSize,
                    smbdAdapter.Smb2MaxReadSize - (uint)i * readSize);

                SmbdBufferDescriptorV1 descp;

                NtStatus status = smbdAdapter.SmbdRegisterBuffer(
                    length,
                    SmbdBufferReadWrite.RDMA_WRITE_PERMISSION_FOR_READ_FILE,
                    out descp);

                BaseTestSite.Assert.AreEqual<NtStatus>(
                    NtStatus.STATUS_SUCCESS,
                    status,
                    "Registering the RDMA READ buffer should succeed.");

                byte[] channelInfo =
                    TypeMarshal.ToBytes<SmbdBufferDescriptorV1>(descp);

                BaseTestSite.Log.Add(
                    LogEntryKind.TestStep,
                    "Read encrypted content from the file over RDMA.");

                READ_Response readResponse;
                byte[] readData;

                status = (NtStatus)smbdAdapter.Smb2ReadOverRdmaChannel(
                    (ulong)i * readSize,
                    length,
                    channelInfo,
                    out readResponse,
                    out readData);

                BaseTestSite.Assert.AreEqual<NtStatus>(
                    NtStatus.STATUS_SUCCESS,
                    status,
                    "Status of SMB2 READ is {0}.",
                    status);

                BaseTestSite.Assert.AreEqual<uint>(
                    length,
                    readResponse.DataRemaining,
                    "DataRemaining in READ response is {0}.",
                    readResponse.DataRemaining);

                BaseTestSite.Assert.AreEqual<byte>(
                    EXPECTED_READ_DATA_OFFSET,
                    readResponse.DataOffset,
                    "DataOffset in READ response is {0}.",
                    readResponse.DataOffset);

                // The file content is transferred into the registered RDMA buffer.
                // The inline READ response contains the RDMA encryption metadata.
                BaseTestSite.Assert.AreEqual<READ_Response_Flags_Values2>(
                    READ_Response_Flags_Values2.SMB2_READFLAG_RESPONSE_RDMA_TRANSFORM,
                    readResponse.Reserved2,
                    "READ response must indicate an RDMA transform. Flags are {0}.",
                    readResponse.Reserved2);

                BaseTestSite.Assert.IsTrue(
                    readData != null &&
                    readData.Length >=
                        rdmaTransformHeaderSize +
                        rdmaCryptoTransformHeaderSize,
                    "READ response must contain RDMA transform metadata. " +
                    "Data length is {0}.",
                    readData == null ? 0 : readData.Length);

                BaseTestSite.Assert.AreEqual<uint>(
                    (uint)readData.Length,
                    readResponse.DataLength,
                    "DataLength must describe the inline RDMA transform metadata.");

                // Decode SMB2_RDMA_TRANSFORM.
                byte[] rdmaTransformBytes =
                    new byte[rdmaTransformHeaderSize];

                Array.Copy(
                    readData,
                    0,
                    rdmaTransformBytes,
                    0,
                    rdmaTransformBytes.Length);

                SMB2_RDMA_TRANSFORM rdmaTransform =
                    TypeMarshal.ToStruct<SMB2_RDMA_TRANSFORM>(
                        rdmaTransformBytes);

                BaseTestSite.Assert.AreEqual<int>(
                    1,
                    rdmaTransform.TransformCount,
                    "Expected one RDMA transform, but received {0}.",
                    rdmaTransform.TransformCount);

                // Decode SMB2_RDMA_CRYPTO_TRANSFORM.
                byte[] cryptoTransformBytes =
                    new byte[readData.Length - rdmaTransformHeaderSize];

                Array.Copy(
                    readData,
                    rdmaTransformHeaderSize,
                    cryptoTransformBytes,
                    0,
                    cryptoTransformBytes.Length);

                SMB2_RDMA_CRYPTO_TRANSFORM cryptoTransform =
                    TypeMarshal.ToStruct<SMB2_RDMA_CRYPTO_TRANSFORM>(
                        cryptoTransformBytes);

                BaseTestSite.Assert.AreEqual<Smb2RDMATransformType>(
                    Smb2RDMATransformType.SMB2_RDMA_TRANSFORM_TYPE_ENCRYPTION,
                    cryptoTransform.TransformType,
                    "Expected an RDMA encryption transform.");

                BaseTestSite.Assert.AreEqual<ushort>(
                    authenticationTagSize,
                    cryptoTransform.SignatureLength,
                    "The authentication-tag length is {0}.",
                    cryptoTransform.SignatureLength);

                BaseTestSite.Assert.IsTrue(
                    cryptoTransform.NonceLength > 0,
                    "RDMA encryption transform must contain a nonce.");

                BaseTestSite.Assert.IsTrue(
                    cryptoTransform.Nonce != null &&
                    cryptoTransform.Nonce.Length >= cryptoTransform.NonceLength,
                    "RDMA encryption transform does not contain the declared " +
                    "number of nonce bytes. Declared length is {0}; available " +
                    "length is {1}.",
                    cryptoTransform.NonceLength,
                    cryptoTransform.Nonce == null
                        ? 0
                        : cryptoTransform.Nonce.Length);

                // The crypto-transform portion is padded to an 8-byte boundary.
                int unalignedCryptoTransformLength =
                    rdmaCryptoTransformHeaderSize +
                    cryptoTransform.SignatureLength +
                    cryptoTransform.NonceLength;

                int alignedCryptoTransformLength =
                    (unalignedCryptoTransformLength + 7) & ~7;

                int expectedReadDataLength =
                    rdmaTransformHeaderSize +
                    alignedCryptoTransformLength;

                BaseTestSite.Assert.AreEqual<int>(
                    expectedReadDataLength,
                    readData.Length,
                    "RDMA encryption metadata length does not match the " +
                    "lengths declared by the transform.");

                BaseTestSite.Assert.AreEqual<uint>(
                    (uint)expectedReadDataLength,
                    readResponse.DataLength,
                    "READ response DataLength is {0}.",
                    readResponse.DataLength);

                // Validate the response from the lengths declared by the RDMA
                // transform instead of inferring its nonce size from the SMB
                // encryption algorithm.
                BaseTestSite.Log.Add(
                    LogEntryKind.Debug,
                    "RDMA encryption metadata length is {0}; " +
                    "signature length is {1}; nonce length is {2}.",
                    readData.Length,
                    cryptoTransform.SignatureLength,
                    cryptoTransform.NonceLength);

                BaseTestSite.Log.Add(
                    LogEntryKind.TestStep,
                    "Read the encrypted content transferred into the registered buffer.");

                // Use length rather than readSize because the final operation can be
                // smaller than the other operations.
                byte[] encryptedFileContent = new byte[length];

                NtStatus readBufferStatus =
                    smbdAdapter.SmbdReadRegisteredBuffer(
                        encryptedFileContent,
                        descp);

                BaseTestSite.Assert.AreEqual<NtStatus>(
                    NtStatus.STATUS_SUCCESS,
                    readBufferStatus,
                    "Status of reading the registered buffer is {0}.",
                    readBufferStatus);

                // encryptedFileContent is the encrypted RDMA payload.
                // readData contains its authentication tag and nonce.
                //
                // Decrypt and authenticate encryptedFileContent here using the test
                // suite's RDMA decryption helper, cryptoTransform.Signature,
                // cryptoTransform.Nonce, and encryptionAlgorithm.
            }

            BaseTestSite.Log.Add(
                LogEntryKind.TestStep,
                "Close file.");

            smbdAdapter.Smb2CloseFile();
        }

        /// <summary>
        /// Write file content over RDMA. The file content will be written with a specific number of operations.
        /// The total size of the write content is the effective maximum single RDMA WRITE size, which is the
        /// smaller of the SMB2 negotiated MaxWriteSize and the SMBD negotiated MaxReadWriteSize. Content size
        /// in each SMB2 WRITE request is ( effectiveMaxWriteSize / operationCount ).
        /// </summary>
        /// <param name="operationCount">count of SMB2 WRITE operation</param>
        /// <param name="encryptionAlgorithm">EncryptionAlgorithm to test</param>
        /// <param name="smb2RdmaTransformIds">The RDMA_TRANSFORM_IDs to use for NegotiateContext</param>
        /// <param name="channel">Channel used for Write Request</param>
        /// <param name="addEncryptionTransform">Add an extra SMB2_RDMA_TRANSFORM_TYPE_ENCRYPTION structure</param>
        /// <param name="addSigningTransform">Add an SMB2_RDMA_TRANSFORM_TYPE_SIGNING structure</param>
        /// <param name="setZeroTransformCount">Set the TransformCount to 0</param>
        /// <param name="shouldAlignBuffer">Indicates if the SMB2_RDMA_TRANSFORM_TYPE_ENCRYPTION should be 8 byte aligned</param>
        /// <param name="signingAlgorithms">The SigningAlgorithms to use (if including signingTransform)</param>
        public void WriteOverRdma_Encryption(
            uint operationCount = 1,
            Smb2RDMATransformId[] smb2RdmaTransformIds = null,
            EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.ENCRYPTION_AES128_CCM,
            Channel_Values channel = Channel_Values.CHANNEL_RDMA_TRANSFORM,
            bool setZeroTransformCount = false,
            bool addEncryptionTransform = false,
            bool addSigningTransform = false,
            bool shouldAlignBuffer = true,
            SigningAlgorithm[] signingAlgorithms = null,
            bool shouldIncreaseSignature = false,
            bool shouldIncreaseNonce = false,
            bool shouldDecreaseNonce = false)
        {
            var isFailedTest = false;
            string fileName = CreateRandomFileName();
            BaseTestSite.Log.Add(LogEntryKind.TestStep, $"The filename ==> {fileName}");


            EncryptionAlgorithm[] encryptionAlgorithms = encryptionAlgorithm == EncryptionAlgorithm.ENCRYPTION_NONE ? null : new EncryptionAlgorithm[] { encryptionAlgorithm };
            InitSmbdConnectionForTestCases(
                fileName,
                smb2RdmaTransformIds: smb2RdmaTransformIds,
                encryptionAlgorithms: encryptionAlgorithms,
                signingAlgorithms: signingAlgorithms,
                addDefaultEncryption: false,
                enableEncryption: encryptionAlgorithms != null);

            uint writeSize;
            uint effectiveOperationCount;
            ComputeWritePlan(operationCount, out writeSize, out effectiveOperationCount);
            uint totalSize = (uint)Math.Min((ulong)writeSize * effectiveOperationCount, smbdAdapter.Smb2MaxWriteSize);

            // SMB2 Write file
            byte[] fileContent = Encoding.ASCII.GetBytes(Smb2Utility.CreateRandomStringInByte((int)writeSize));
            smbdAdapter.EncryptByteArray(fileContent, out byte[] encrypted, out byte[] nonce, out byte[] signature);

            if (shouldDecreaseNonce)
            {
                byte[] newNonce = new byte[nonce.Length - 1];
                Array.Copy(nonce, 0, newNonce, 0, newNonce.Length);
                nonce = newNonce;
            }

            if (shouldIncreaseNonce)
            {
                byte[] newNonce = new byte[nonce.Length + 1];
                Array.Copy(nonce, 0, newNonce, 1, nonce.Length);
                newNonce[0] = nonce[0];
                nonce = newNonce;
            }

            if (shouldIncreaseSignature)
            {
                byte[] newSignature = new byte[signature.Length + 1];
                Array.Copy(signature, 0, newSignature, 1, signature.Length);
                newSignature[0] = signature[0];
                signature = newSignature;
            }

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Send each write request according SMB2 write file limit. with operationCount == " + effectiveOperationCount);
            for (int i = 0; i < effectiveOperationCount; ++i)
            {
                // register memory and get buffer descriptor
                smbdAdapter.SmbdRegisterBuffer(
                    writeSize,
                    SmbdBufferReadWrite.RDMA_READ_PERMISSION_FOR_WRITE_FILE,
                    out SmbdBufferDescriptorV1 descp
                    );

                // Each WRITE request carries exactly one transform + one buffer
                // descriptor. These are built fresh per operation so the channel
                // info of one request never accumulates descriptors from previous
                // iterations (which would make the server RDMA-Read from the wrong
                // buffer when the write is split into multiple operations).
                var descriptorOffset = 0;
                // WHAT: reset TransformCount for every WRITE request instead of once for the whole test.
                // WHY: it was declared outside the loop, so addEncryptionTransform/addSigningTransform kept incrementing it on each
                //      iteration and requests after the first advertised more structures than they carried.
                // SPEC: [MS-SMB2] 2.2.43 SMB2_RDMA_TRANSFORM - TransformCount is the number of SMB2_RDMA_CRYPTO_TRANSFORM structures
                //       that follow in this request.
                var transformCount = setZeroTransformCount ? 0 : 1;
                List<byte> totalBytes = new List<byte>();

                // Build RDMA_CRYPTO_TRANSFORM
                byte[] signingTransformBytes = null;
                SMB2_RDMA_CRYPTO_TRANSFORM cryptoTransform = new()
                {
                    TransformType = Smb2RDMATransformType.SMB2_RDMA_TRANSFORM_TYPE_ENCRYPTION,
                    SignatureLength = (ushort)signature.Length,
                    NonceLength = (ushort)nonce.Length,
                    Signature = signature,
                    Nonce = nonce,
                };
                var cryptoTransformBytes = TypeMarshal.ToBytes(cryptoTransform);
                if (shouldAlignBuffer)
                    Smb2Utility.Align8(ref cryptoTransformBytes);
                descriptorOffset += cryptoTransformBytes.Length;

                if (addEncryptionTransform)
                {
                    transformCount++;
                    descriptorOffset += cryptoTransformBytes.Length;
                }

                if (addSigningTransform)
                {
                    // WHAT: build a genuine SMB2_RDMA_TRANSFORM_TYPE_SIGNING structure and append it to the request below.
                    // WHY: the old code built a second ENCRYPTION-typed struct, counted it in TransformCount, but never appended it,
                    //      so TransformCount (3) did not match the structures sent (2) - a malformed request rather than the
                    //      ENCRYPTION+SIGNING combination the test intends to exercise.
                    // SPEC: [MS-SMB2] 2.2.43.1.1 SMB2_RDMA_CRYPTO_TRANSFORM (TransformType 0x0001 ENCRYPTION / 0x0002 SIGNING) and
                    //       3.3.5.13 - ENCRYPTION and SIGNING structures together in one request => STATUS_INVALID_PARAMETER.
                    SMB2_RDMA_CRYPTO_TRANSFORM signingTransform = new()
                    {
                        TransformType = Smb2RDMATransformType.SMB2_RDMA_TRANSFORM_TYPE_SIGNING,
                        SignatureLength = (ushort)signature.Length,
                        NonceLength = (ushort)nonce.Length,
                        Signature = signature,
                        Nonce = nonce,
                    };
                    signingTransformBytes = TypeMarshal.ToBytes(signingTransform);
                    if (shouldAlignBuffer)
                        Smb2Utility.Align8(ref signingTransformBytes);
                    transformCount++;
                    descriptorOffset += signingTransformBytes.Length;
                }

                // Build RDMA_TRANSFORM
                SMB2_RDMA_TRANSFORM rdmaTransform = new()
                {
                    RdmaDescriptorOffset = 0,
                    RdmaDescriptorLength = 1,
                    Channel = Smb2RdmaTransformChannel.SMB2_CHANNEL_RDMA_V1,
                    TransformCount = (ushort)transformCount,
                    Reserved1 = 0,
                    Reserved2 = 0
                };
                var rdmaTransformBytes = TypeMarshal.ToBytes(rdmaTransform);
                descriptorOffset += rdmaTransformBytes.Length;

                rdmaTransform.RdmaDescriptorOffset = (ushort)descriptorOffset;

                smbdAdapter.SmbdWriteRegisteredBuffer(encrypted, descp);
                byte[] channelInfo = TypeMarshal.ToBytes<SmbdBufferDescriptorV1>(descp);
                rdmaTransform.RdmaDescriptorLength = (ushort)channelInfo.Length;

                rdmaTransformBytes = TypeMarshal.ToBytes(rdmaTransform);

                totalBytes.AddRange(rdmaTransformBytes);

                totalBytes.AddRange(cryptoTransformBytes);

                if (addEncryptionTransform)
                {
                    totalBytes.AddRange(cryptoTransformBytes);
                }

                if (addSigningTransform)
                {
                    totalBytes.AddRange(signingTransformBytes);
                }

                totalBytes.AddRange(channelInfo);

                BaseTestSite.Log.Add(LogEntryKind.TestStep, "Write content to file over RDMA.");
                NtStatus status = (NtStatus)smbdAdapter.Smb2WriteOverRdmaChannel(
                    (UInt64)i * writeSize,
                    totalBytes.ToArray(),
                    writeSize,
                    out WRITE_Response writeResponse,
                    channel
                    );

                if ((smb2RdmaTransformIds == null || smb2RdmaTransformIds.Length == 0) && channel == Channel_Values.CHANNEL_RDMA_TRANSFORM)
                {
                    BaseTestSite.Assert.AreEqual(
                        NtStatus.STATUS_INVALID_PARAMETER,
                        status,
                        "Server MUST return STATUS_INVALID_PARAMETER if RDMATransformIds is empty and channel is SMB2_CHANNEL_RDMA_TRANSFORM");
                    isFailedTest = true;
                }
                else if (setZeroTransformCount)
                {
                    BaseTestSite.Assert.AreEqual(
                        NtStatus.STATUS_INVALID_PARAMETER,
                        status,
                        "Server MUST return STATUS_INVALID_PARAMETER if TransformCount is 0 and channel " +
                        "is SMB2_CHANNEL_RDMA_TRANSFORM");
                    isFailedTest = true;
                }
                else if (addEncryptionTransform)
                {
                    BaseTestSite.Assert.AreEqual(
                        NtStatus.STATUS_INVALID_PARAMETER,
                        status,
                        "Server MUST return STATUS_INVALID_PARAMETER if More than one SMB2_RDMA_CRYPTO_TRANSFORM " +
                        "structures with TransformType equal to SMB2_RDMA_TRANSFORM_TYPE_ENCRYPTION are present");
                    isFailedTest = true;
                }
                else if (addSigningTransform)
                {
                    BaseTestSite.Assert.AreEqual(
                        NtStatus.STATUS_INVALID_PARAMETER,
                        status,
                        "Server MUST return STATUS_INVALID_PARAMETER if Two SMB2_RDMA_CRYPTO_TRANSFORM " +
                        "structures with TransformType equal to SMB2_RDMA_TRANSFORM_TYPE_ENCRYPTION and " +
                        "SMB2_RDMA_TRANSFORM_TYPE_SIGNING are present");
                    isFailedTest = true;
                }
                else if (!shouldAlignBuffer)
                {
                    BaseTestSite.Assert.AreEqual(
                        NtStatus.STATUS_INVALID_PARAMETER,
                        status,
                        "Server MUST return STATUS_INVALID_PARAMETER if SMB_DIRECT_BUFFER_DESCRIPTOR_V1 structures " +
                        "don't begin at the first 8-byte aligned offset");
                    isFailedTest = true;
                }
                else if (shouldIncreaseSignature || shouldIncreaseNonce || shouldDecreaseNonce)
                {
                    BaseTestSite.Assert.AreEqual(
                        NtStatus.STATUS_AUTH_TAG_MISMATCH,
                        status,
                        "The Server MUST fail the request with STATUS_AUTH_TAG_MISMATCH if SignatureLength field is greater than 16, " +
                        "Connection.CipherId is AES-128-CCM or AES-256-CCM and NonceLength field is not equal to 11 or " +
                        "Connection.CipherId is AES-128-GCM or AES-256-GCM and NonceLength field is not equal to 12.");
                    isFailedTest = true;
                }
                else
                {
                    BaseTestSite.Assert.AreEqual(
                        NtStatus.STATUS_SUCCESS,
                        status,
                        "Status of SMB2 Write File offset {0} is {1}", i * writeSize, status);
                    BaseTestSite.Assert.AreEqual(
                        (uint)writeSize,
                        writeResponse.Count,
                        "DataLength in WRITE response is {0}", writeResponse.Count);
                }
            }

            if (!isFailedTest)
            {
                BaseTestSite.Log.Add(LogEntryKind.TestStep, "Validate file content.");
                ValidateFileContent(fileContent, totalSize, fileName);
            }

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Close file.");
            smbdAdapter.Smb2CloseFile();
        }

        private void ValidateFileContent(byte[] content, uint fileSize, string fileName)
        {
            smbdAdapter.Smb2CloseFile();

            smbdAdapter.Smb2LogOff();
            smbdAdapter = new SmbdAdapter(BaseTestSite, LogSmbdEndpointEvent);

            InitSmbdConnectionForTestCases(fileName);

            uint readSize = (uint)content.Length;
            // SMB2 Read file
            SmbdBufferDescriptorV1 descp;
            smbdAdapter.SmbdRegisterBuffer(
                readSize,
                SmbdBufferReadWrite.RDMA_WRITE_PERMISSION_FOR_READ_FILE,
                out descp);

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

                byte[] readFileContent = new byte[readSize];
                smbdAdapter.SmbdReadRegisteredBuffer(readFileContent, descp);

                BaseTestSite.Assert.IsTrue(
                    SmbdUtilities.CompareByteArray(content, readFileContent),
                    "Check content of file");

                offset += readSize;
            }
        }

        private void InitSmbdConnectionForTestCases(
            string fileName,
            Smb2RDMATransformId[] smb2RdmaTransformIds = null,
            bool addDefaultEncryption = true,
            EncryptionAlgorithm[] encryptionAlgorithms = null,
            SigningAlgorithm[] signingAlgorithms = null,
            bool enableSigning = false,
            bool enableEncryption = true)
        {
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Initial SMBD connection and open file " + fileName);

            uint size = smbdAdapter.TestConfig.LargeFileSizeInByte;
            // Connect to server over RDMA
            NtStatus status = smbdAdapter.ConnectToServerOverRDMA();
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMBD connection is {0}", status);

            // SMBD Negotiate
            status = smbdAdapter.SmbdNegotiate();
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMBD negotiate is {0}", status);


            DialectRevision[] dialects = new DialectRevision[]
            {
                DialectRevision.Smb311
            };

            status = smbdAdapter.Smb2EstablishSessionAndOpenFile(
                fileName,
                negotiatedDialects: dialects,
                smb2RDMATransformIds: smb2RdmaTransformIds,
                addDefaultEncryption: addDefaultEncryption,
                encryptionAlgs: encryptionAlgorithms,
                signingAlgorithms: signingAlgorithms,
                enableSigning: enableSigning,
                enableEncryption: enableEncryption);
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMB2 establish session and open file is {0}", status);
        }

        #endregion
    }
}
