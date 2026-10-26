// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Protocols.TestSuites.Smbd.Adapter;
using Microsoft.Protocols.TestTools;
using Microsoft.Protocols.TestTools.StackSdk;
using Microsoft.Protocols.TestTools.StackSdk.FileAccessService.Smb2;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace Microsoft.Protocol.TestSuites.Smbd.TestSuite
{
    /// <summary>
    /// Tests for the handling of the SMB2_RDMA_TRANSFORM_CAPABILITIES negotiate context by the server
    /// ([MS-SMB2] 3.3.5.4, 2.2.3.1.6, 2.2.4.1.6) on an SMB Direct (RDMA) connection.
    /// The malformed requests are built here because the SDK's Negotiate helper can only produce well-formed contexts.
    /// </summary>
    [TestClass]
    public class Smb2OverRdmaNegotiateContext : Smb2OverSmbdTestBase
    {
        #region Variables
        // Data of SMB2_RDMA_TRANSFORM_CAPABILITIES without RDMATransformIds: TransformCount(2) + Reserved1(2) + Reserved2(4)
        private const int RDMA_TRANSFORM_CAPABILITIES_FIXED_SIZE = 8;

        private const int PREAUTH_SALT_LENGTH = 32;

        // Not defined by [MS-SMB2] 2.2.3.1.6, so no server can support it.
        private const ushort UNKNOWN_TRANSFORM_ID_1 = 0x00FE;
        private const ushort UNKNOWN_TRANSFORM_ID_2 = 0x7FFF;
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
        [TestCategory("Negative")]
        [TestCategory("Smb2OverRdmaNegotiateContext")]
        [Description("Verify the server fails an SMB 3.1.1 NEGOTIATE over RDMA that contains two SMB2_RDMA_TRANSFORM_CAPABILITIES contexts with STATUS_INVALID_PARAMETER")]
        // WHAT: send one NEGOTIATE (3.1.1) whose NegotiateContextList has a valid PREAUTH context and two RDMA transform contexts.
        // WHY: the duplicate-context rule is part of the generic NegotiateContextList validation, so it is not conditional on the
        //      server supporting RDMA transforms (IsRDMATransformSupported only controls how a single context is processed). No Assume here.
        // SPEC: [MS-SMB2] 3.3.5.4: "If the NegotiateContextList contains more than one SMB2_RDMA_TRANSFORM_CAPABILITIES negotiate
        //       context, the server MUST fail the negotiate request with STATUS_INVALID_PARAMETER."
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.4 Receiving an SMB2 NEGOTIATE Request")]
        public void Smb2OverRdmaNegotiateContext_RdmaTransform_TwoContexts_Fails()
        {
            Smb2NegotiateResponsePacket response = ConnectAndSendRawNegotiate(
                new DialectRevision[] { DialectRevision.Smb311 },
                BuildPreauthContext(),
                BuildRdmaTransformContext(new ushort[] { (ushort)Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_SIGNING }),
                BuildRdmaTransformContext(new ushort[] { (ushort)Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_ENCRYPTION }));

            BaseTestSite.Assert.AreEqual<NtStatus>(
                NtStatus.STATUS_INVALID_PARAMETER,
                (NtStatus)response.Header.Status,
                "Server MUST fail a NEGOTIATE with more than one SMB2_RDMA_TRANSFORM_CAPABILITIES context with STATUS_INVALID_PARAMETER");
        }

        [TestMethod()]
        [TestCategory("Negative")]
        [TestCategory("Smb2OverRdmaNegotiateContext")]
        [Description("Verify the server fails an SMB 3.1.1 NEGOTIATE over RDMA whose SMB2_RDMA_TRANSFORM_CAPABILITIES context DataLength is smaller than the structure with STATUS_INVALID_PARAMETER")]
        // WHAT: send a RDMA transform context whose Data is only 4 bytes (TransformCount + Reserved1), less than the 8-byte fixed part.
        // WHY: processing of the context only happens when the server supports it (optional feature), so the case is gated by an
        //      Assume based on a prior well-formed negotiate; otherwise a server that ignores the context legitimately returns success.
        // SPEC: [MS-SMB2] 3.3.5.4 "Processing the SMB2_RDMA_TRANSFORM_CAPABILITIES negotiate context": "If IsRDMATransformSupported is FALSE,
        //       the server MUST ignore the context." / "The server MUST fail the negotiate request with STATUS_INVALID_PARAMETER ... If the
        //       DataLength of the negotiate context is less than the size of the SMB2_RDMA_TRANSFORM_CAPABILITIES structure."
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.4 Receiving an SMB2 NEGOTIATE Request; 2.2.3.1.6 SMB2_RDMA_TRANSFORM_CAPABILITIES")]
        public void Smb2OverRdmaNegotiateContext_RdmaTransform_DataLengthTooSmall_Fails()
        {
            AssumeServerProcessesRdmaTransformContext();

            // Data is 4 bytes: TransformCount = 1, Reserved1 = 0 (Reserved2 and RDMATransformIds omitted).
            byte[] truncatedData = new byte[] { 0x01, 0x00, 0x00, 0x00 };
            Smb2NegotiateResponsePacket response = ConnectAndSendRawNegotiate(
                new DialectRevision[] { DialectRevision.Smb311 },
                BuildPreauthContext(),
                BuildContext(SMB2_NEGOTIATE_CONTEXT_Type_Values.SMB2_RDMA_TRANSFORM_CAPABILITIES, truncatedData));

            BaseTestSite.Assert.AreEqual<NtStatus>(
                NtStatus.STATUS_INVALID_PARAMETER,
                (NtStatus)response.Header.Status,
                "Server MUST fail the NEGOTIATE with STATUS_INVALID_PARAMETER when the DataLength of the " +
                "SMB2_RDMA_TRANSFORM_CAPABILITIES context ({0}) is less than the structure size ({1})",
                truncatedData.Length, RDMA_TRANSFORM_CAPABILITIES_FIXED_SIZE);
        }

        [TestMethod()]
        [TestCategory("Negative")]
        [TestCategory("Smb2OverRdmaNegotiateContext")]
        [Description("Verify the server fails an SMB 3.1.1 NEGOTIATE over RDMA whose SMB2_RDMA_TRANSFORM_CAPABILITIES context has TransformCount 0 with STATUS_INVALID_PARAMETER")]
        // WHAT: send a RDMA transform context with TransformCount = 0 and an empty RDMATransformIds array (8-byte Data).
        // WHY: gated by an Assume (optional feature); a server that ignores the context legitimately returns success.
        // SPEC: [MS-SMB2] 3.3.5.4 Processing the SMB2_RDMA_TRANSFORM_CAPABILITIES context: "The server MUST fail the negotiate request with
        //       STATUS_INVALID_PARAMETER ... If TransformCount is equal to zero." 2.2.3.1.6: "TransformCount ... MUST be greater than 0."
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.4 Receiving an SMB2 NEGOTIATE Request; 2.2.3.1.6 SMB2_RDMA_TRANSFORM_CAPABILITIES")]
        public void Smb2OverRdmaNegotiateContext_RdmaTransform_ZeroTransformCount_Fails()
        {
            AssumeServerProcessesRdmaTransformContext();

            Smb2NegotiateResponsePacket response = ConnectAndSendRawNegotiate(
                new DialectRevision[] { DialectRevision.Smb311 },
                BuildPreauthContext(),
                BuildRdmaTransformContext(new ushort[0]));

            BaseTestSite.Assert.AreEqual<NtStatus>(
                NtStatus.STATUS_INVALID_PARAMETER,
                (NtStatus)response.Header.Status,
                "Server MUST fail the NEGOTIATE with STATUS_INVALID_PARAMETER when TransformCount is 0");
        }

        [TestMethod()]
        [TestCategory("Positive")]
        [TestCategory("Smb2OverRdmaNegotiateContext")]
        [Description("Verify the server answers SMB2_RDMA_TRANSFORM_NONE when the client only offers unknown RDMA transform IDs")]
        // WHAT: offer only IDs that [MS-SMB2] 2.2.3.1.6 does not define (0x00FE, 0x7FFF) and check the response context.
        // WHY: with no common transform the negotiate still succeeds (it is not an error condition) and, because the context was processed,
        //      the response MUST carry an RDMA transform context that tells the client no transform is selected. Gated by an Assume
        //      (optional feature) so a server that ignores the context is reported as inconclusive rather than failed.
        // SPEC: [MS-SMB2] 3.3.5.4: "If the server does not support any of the RDMA transforms provided by the client,
        //       Connection.RDMATransformIds MUST be set to an empty list." and, in the response: "If Connection.RDMATransformIds is empty,
        //       set TransformCount to 1 and set RDMATransformIds to SMB2_RDMA_TRANSFORM_NONE." (format per 2.2.4.1.6)
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.4 Receiving an SMB2 NEGOTIATE Request; 2.2.4.1.6 SMB2_RDMA_TRANSFORM_CAPABILITIES")]
        public void Smb2OverRdmaNegotiateContext_RdmaTransform_NoCommonTransform_ResponseNone()
        {
            AssumeServerProcessesRdmaTransformContext();

            Smb2NegotiateResponsePacket response = ConnectAndSendRawNegotiate(
                new DialectRevision[] { DialectRevision.Smb311 },
                BuildPreauthContext(),
                BuildRdmaTransformContext(new ushort[] { UNKNOWN_TRANSFORM_ID_1, UNKNOWN_TRANSFORM_ID_2 }));

            BaseTestSite.Assert.AreEqual<NtStatus>(
                NtStatus.STATUS_SUCCESS,
                (NtStatus)response.Header.Status,
                "NEGOTIATE with no common RDMA transform is not an error, status MUST be STATUS_SUCCESS");
            BaseTestSite.Assert.AreEqual<DialectRevision>(
                DialectRevision.Smb311,
                response.PayLoad.DialectRevision,
                "Selected dialect is {0}", response.PayLoad.DialectRevision);
            BaseTestSite.Assert.IsTrue(
                response.NegotiateContext_RDMA != null,
                "The server processed the RDMA transform context so the response MUST contain an SMB2_RDMA_TRANSFORM_CAPABILITIES context");

            SMB2_RDMA_TRANSFORM_CAPABILITIES responseContext = response.NegotiateContext_RDMA.Value;
            BaseTestSite.Assert.AreEqual<ushort>(
                1,
                responseContext.TransformCount,
                "TransformCount in the response context MUST be 1 when Connection.RDMATransformIds is empty");
            BaseTestSite.Assert.IsTrue(
                responseContext.RDMATransformIds != null && responseContext.RDMATransformIds.Length == 1,
                "RDMATransformIds in the response context MUST contain exactly one element");
            BaseTestSite.Assert.AreEqual<Smb2RDMATransformId>(
                Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_NONE,
                responseContext.RDMATransformIds[0],
                "RDMATransformIds[0] MUST be SMB2_RDMA_TRANSFORM_NONE when there is no common transform");
        }

        [TestMethod()]
        [TestCategory("Positive")]
        [TestCategory("Smb2OverRdmaNegotiateContext")]
        [Description("Verify the server never returns an unknown RDMA transform ID that the client offered next to defined IDs")]
        // WHAT: offer {0x00FE (unknown), SIGNING, ENCRYPTION} and check that the response lists only transforms the server supports.
        // WHY: Connection.RDMATransformIds is "all the supported RDMA transforms common to both client and server"; an ID that no
        //      implementation defines can never be common, so echoing it would be a defect. Gated by an Assume (optional feature).
        // SPEC: [MS-SMB2] 3.3.5.4: "The server MUST set Connection.RDMATransformIds to all the supported RDMA transforms common to both client
        //       and server in the RDMATransformIds field." and the response "set RDMATransformIds to Connection.RDMATransformIds and set
        //       TransformCount to the number of elements in RDMATransformIds."
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.4 Receiving an SMB2 NEGOTIATE Request; 2.2.4.1.6 SMB2_RDMA_TRANSFORM_CAPABILITIES")]
        public void Smb2OverRdmaNegotiateContext_RdmaTransform_UnknownIdIgnored()
        {
            AssumeServerProcessesRdmaTransformContext();

            Smb2NegotiateResponsePacket response = ConnectAndSendRawNegotiate(
                new DialectRevision[] { DialectRevision.Smb311 },
                BuildPreauthContext(),
                BuildRdmaTransformContext(new ushort[]
                {
                    UNKNOWN_TRANSFORM_ID_1,
                    (ushort)Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_SIGNING,
                    (ushort)Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_ENCRYPTION
                }));

            BaseTestSite.Assert.AreEqual<NtStatus>(
                NtStatus.STATUS_SUCCESS,
                (NtStatus)response.Header.Status,
                "Status of NEGOTIATE with a mix of known and unknown RDMA transform IDs");
            BaseTestSite.Assert.IsTrue(
                response.NegotiateContext_RDMA != null,
                "The server processed the RDMA transform context so the response MUST contain an SMB2_RDMA_TRANSFORM_CAPABILITIES context");

            SMB2_RDMA_TRANSFORM_CAPABILITIES responseContext = response.NegotiateContext_RDMA.Value;
            Smb2RDMATransformId[] returnedIds = responseContext.RDMATransformIds ?? new Smb2RDMATransformId[0];
            BaseTestSite.Assert.AreEqual<int>(
                returnedIds.Length,
                responseContext.TransformCount,
                "TransformCount MUST be the number of elements in RDMATransformIds");
            BaseTestSite.Assert.IsTrue(
                returnedIds.Length >= 1,
                "The response context MUST contain at least one RDMATransformIds element (SMB2_RDMA_TRANSFORM_NONE when none is common)");
            BaseTestSite.Assert.IsFalse(
                returnedIds.Contains((Smb2RDMATransformId)UNKNOWN_TRANSFORM_ID_1),
                "The undefined transform ID 0x{0:X4} cannot be a transform supported by the server; returned IDs: [{1}]",
                UNKNOWN_TRANSFORM_ID_1, string.Join(", ", returnedIds));
        }

        [TestMethod()]
        [TestCategory("Positive")]
        [TestCategory("Smb2OverRdmaNegotiateContext")]
        [Description("Verify the server ignores the SMB2_RDMA_TRANSFORM_CAPABILITIES context and returns none when the selected dialect is 3.0.2")]
        // WHAT: negotiate with dialect 3.0.2 only, carrying a PREAUTH and a RDMA transform context laid out as in a 3.1.1 request.
        // WHY: negotiate contexts exist only for 3.1.1; for earlier dialects the same bytes are ClientStartTime/reserved, so the server
        //      must neither fail nor answer with a NegotiateContextList.
        // SPEC: [MS-SMB2] 3.3.5.4: the NegotiateContextList is processed only "If the Connection.Dialect is "3.1.1"", and the server
        //       builds a NegotiateContextList for the response only "If Connection.Dialect is "3.1.1"". 2.2.3: for dialects other than
        //       3.1.1 the NegotiateContextOffset/Count/Reserved2 bytes are ClientStartTime.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.4 Receiving an SMB2 NEGOTIATE Request; 2.2.3 SMB2 NEGOTIATE Request")]
        public void Smb2OverRdmaNegotiateContext_RdmaTransform_Smb302_ContextIgnored()
        {
            Smb2NegotiateResponsePacket response = ConnectAndSendRawNegotiate(
                new DialectRevision[] { DialectRevision.Smb302 },
                BuildPreauthContext(),
                BuildRdmaTransformContext(new ushort[]
                {
                    (ushort)Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_SIGNING,
                    (ushort)Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_ENCRYPTION
                }));

            BaseTestSite.Assert.AreEqual<NtStatus>(
                NtStatus.STATUS_SUCCESS,
                (NtStatus)response.Header.Status,
                "Contexts MUST be ignored for dialect 3.0.2, so the NEGOTIATE succeeds");
            BaseTestSite.Assert.AreEqual<DialectRevision>(
                DialectRevision.Smb302,
                response.PayLoad.DialectRevision,
                "Selected dialect is {0}", response.PayLoad.DialectRevision);
            BaseTestSite.Assert.IsTrue(
                response.NegotiateContext_RDMA == null,
                "The response of a 3.0.2 NEGOTIATE MUST NOT contain an SMB2_RDMA_TRANSFORM_CAPABILITIES context");
        }

        #endregion

        #region Common Methods

        /// <summary>
        /// Skips the test when the server does not process SMB2_RDMA_TRANSFORM_CAPABILITIES (it is optional: [MS-SMB2] 3.3.5.4
        /// "If IsRDMATransformSupported is FALSE, the server MUST ignore the context"). A well-formed context is sent on a
        /// throw-away connection; a processed context is answered with a response context. After the probe the adapter is
        /// replaced because a connection allows only one NEGOTIATE ([MS-SMB2] 3.3.5.4: a second one disconnects).
        /// </summary>
        private void AssumeServerProcessesRdmaTransformContext()
        {
            Smb2NegotiateResponsePacket probe = ConnectAndSendRawNegotiate(
                new DialectRevision[] { DialectRevision.Smb311 },
                BuildPreauthContext(),
                BuildRdmaTransformContext(new ushort[]
                {
                    (ushort)Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_SIGNING,
                    (ushort)Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_ENCRYPTION
                }));

            BaseTestSite.Assert.AreEqual<NtStatus>(
                NtStatus.STATUS_SUCCESS,
                (NtStatus)probe.Header.Status,
                "A well-formed 3.1.1 NEGOTIATE with a RDMA transform context MUST succeed");

            bool processed = probe.NegotiateContext_RDMA != null;

            smbdAdapter.DisconnectRdma();
            smbdAdapter = new SmbdAdapter(BaseTestSite, LogSmbdEndpointEvent);

            BaseTestSite.Assume.IsTrue(
                processed,
                "Server did not answer with an SMB2_RDMA_TRANSFORM_CAPABILITIES context, so it ignores the optional context " +
                "([MS-SMB2] 3.3.5.4, IsRDMATransformSupported is FALSE) and its validation cannot be tested.");
        }

        /// <summary>
        /// Connects over RDMA, completes the SMBD negotiation and sends a hand-built SMB2 NEGOTIATE request.
        /// </summary>
        /// <param name="dialects">Dialects of the request</param>
        /// <param name="contexts">Fully encoded negotiate contexts, placed in the given order</param>
        /// <returns>The decoded NEGOTIATE response (Header.Status holds the status, also for error responses)</returns>
        private Smb2NegotiateResponsePacket ConnectAndSendRawNegotiate(DialectRevision[] dialects, params byte[][] contexts)
        {
            NtStatus status = smbdAdapter.ConnectToServerOverRDMA();
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMBD connection is {0}", status);

            status = smbdAdapter.SmbdNegotiate();
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, status, "Status of SMBD negotiate is {0}", status);

            // SmbdAdapter does not expose its SMB2 client and its Smb2Negotiate cannot express malformed or duplicated contexts,
            // so the client is taken from the adapter's private field; only the packet send/receive of the client is used.
            FieldInfo clientField = typeof(SmbdAdapter).GetField("client", BindingFlags.Instance | BindingFlags.NonPublic);
            Smb2OverSmbdTestClient client = clientField == null ? null : clientField.GetValue(smbdAdapter) as Smb2OverSmbdTestClient;
            if (client == null)
            {
                BaseTestSite.Assert.Inconclusive("Cannot access the SMB2 client of SmbdAdapter (private field 'client' not found).");
            }

            RawNegotiateRequest request = new RawNegotiateRequest(dialects, contexts);
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Send NEGOTIATE over RDMA, dialects [{0}], {1} negotiate context(s).",
                string.Join(", ", dialects), contexts.Length);
            client.SendPacket(request);

            // MessageId of the first request on a connection is 0.
            Smb2NegotiateResponsePacket response = client.ExpectPacket<Smb2NegotiateResponsePacket>(0);
            BaseTestSite.Log.Add(LogEntryKind.Debug, "NEGOTIATE response status 0x{0:X8}", response.Header.Status);
            return response;
        }

        private static byte[] BuildContext(SMB2_NEGOTIATE_CONTEXT_Type_Values contextType, byte[] data)
        {
            List<byte> context = new List<byte>();
            context.AddRange(BitConverter.GetBytes((ushort)contextType));
            context.AddRange(BitConverter.GetBytes((ushort)data.Length));
            context.AddRange(BitConverter.GetBytes((uint)0)); // Reserved
            context.AddRange(data);
            return context.ToArray();
        }

        /// <summary>
        /// SMB2_PREAUTH_INTEGRITY_CAPABILITIES with SHA-512 and a random salt; 3.3.5.4 requires exactly one in a 3.1.1 request.
        /// </summary>
        private static byte[] BuildPreauthContext()
        {
            byte[] salt = new byte[PREAUTH_SALT_LENGTH];
            new Random().NextBytes(salt);

            List<byte> data = new List<byte>();
            data.AddRange(BitConverter.GetBytes((ushort)1)); // HashAlgorithmCount
            data.AddRange(BitConverter.GetBytes((ushort)salt.Length)); // SaltLength
            data.AddRange(BitConverter.GetBytes((ushort)PreauthIntegrityHashID.SHA_512)); // HashAlgorithms[0]
            data.AddRange(salt);
            return BuildContext(SMB2_NEGOTIATE_CONTEXT_Type_Values.SMB2_PREAUTH_INTEGRITY_CAPABILITIES, data.ToArray());
        }

        /// <summary>
        /// SMB2_RDMA_TRANSFORM_CAPABILITIES with TransformCount equal to the number of IDs given (0 for an empty array).
        /// </summary>
        private static byte[] BuildRdmaTransformContext(ushort[] transformIds)
        {
            List<byte> data = new List<byte>();
            data.AddRange(BitConverter.GetBytes((ushort)transformIds.Length)); // TransformCount
            data.AddRange(BitConverter.GetBytes((ushort)0)); // Reserved1
            data.AddRange(BitConverter.GetBytes((uint)0)); // Reserved2
            foreach (ushort transformId in transformIds)
            {
                data.AddRange(BitConverter.GetBytes(transformId));
            }
            return BuildContext(SMB2_NEGOTIATE_CONTEXT_Type_Values.SMB2_RDMA_TRANSFORM_CAPABILITIES, data.ToArray());
        }

        /// <summary>
        /// NEGOTIATE request whose wire bytes are fully controlled by the test: the SDK request class can carry at most one
        /// context per type and always writes a consistent DataLength, so it cannot express the cases of this class.
        /// </summary>
        private sealed class RawNegotiateRequest : Smb2NegotiateRequestPacket
        {
            private readonly DialectRevision[] requestDialects;
            private readonly byte[][] contexts;
            private readonly Guid clientGuid = Guid.NewGuid();

            public RawNegotiateRequest(DialectRevision[] requestDialects, byte[][] contexts)
            {
                this.requestDialects = requestDialects;
                this.contexts = contexts;

                // Same header values as Smb2OverSmbdTestClient.Smb2Negotiate: first message of the connection.
                Header.CreditCharge = 1;
                Header.Command = Smb2Command.NEGOTIATE;
                Header.CreditRequestResponse = 1;
                Header.Flags = Packet_Header_Flags_Values.NONE;
                Header.MessageId = 0;
            }

            public override byte[] ToBytes()
            {
                List<byte> message = new List<byte>();
                message.AddRange(TypeMarshal.ToBytes(Header));

                uint contextOffset = (uint)(64 + 36 + 2 * requestDialects.Length);
                Smb2Utility.Align8(ref contextOffset);

                message.AddRange(BitConverter.GetBytes((ushort)36)); // StructureSize
                message.AddRange(BitConverter.GetBytes((ushort)requestDialects.Length)); // DialectCount
                message.AddRange(BitConverter.GetBytes((ushort)SecurityMode_Values.NEGOTIATE_SIGNING_ENABLED));
                message.AddRange(BitConverter.GetBytes((ushort)0)); // Reserved
                message.AddRange(BitConverter.GetBytes((uint)Smb2OverSmbdTestClient.CAPABILITIES));
                message.AddRange(clientGuid.ToByteArray());
                // NegotiateContextOffset/Count/Reserved2 (ClientStartTime when 3.1.1 is not offered)
                message.AddRange(BitConverter.GetBytes(contextOffset));
                message.AddRange(BitConverter.GetBytes((ushort)contexts.Length));
                message.AddRange(BitConverter.GetBytes((ushort)0));

                foreach (DialectRevision dialect in requestDialects)
                {
                    message.AddRange(BitConverter.GetBytes((ushort)dialect));
                }

                foreach (byte[] context in contexts)
                {
                    while (message.Count % 8 != 0)
                    {
                        message.Add(0);
                    }
                    message.AddRange(context);
                }

                return message.ToArray();
            }
        }

        #endregion
    }
}
