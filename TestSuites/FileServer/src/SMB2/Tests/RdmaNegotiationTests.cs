// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.Protocols.TestTools.StackSdk.FileAccessService.Smb2;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Protocols.TestSuites.FileSharing.SMB2.Tests;

[TestClass]
[TestCategory("ManagedRegression")]
public sealed class RdmaNegotiationTests
{
    private static readonly Smb2RDMATransformId[] Offer =
    {
        Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_ENCRYPTION,
        Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_SIGNING,
    };

    [TestMethod]
    public void Negotiate_OfferedSelection_AcceptsAllSelectedTransforms()
    {
        var client = new NegotiationClient();
        Negotiate(client, Response(DialectRevision.Smb311, Offer), Offer);
        CollectionAssert.AreEqual(Offer, client.SelectedRdmaTransformIds);

        var subset = new[] { Offer[1] };
        Negotiate(client, Response(DialectRevision.Smb311, subset), Offer);
        CollectionAssert.AreEqual(subset, client.SelectedRdmaTransformIds);
    }

    [TestMethod]
    [DataRow(DialectRevision.Smb311, false)]
    [DataRow(DialectRevision.Smb311, true)]
    [DataRow(DialectRevision.Smb302, false)]
    [DataRow(DialectRevision.Smb2002, false)]
    public void Negotiate_ReusedClientWithoutResponseContext_ClearsPreviousSelection(
        DialectRevision dialect, bool offerAgain)
    {
        var client = new NegotiationClient();
        Negotiate(client, Response(DialectRevision.Smb311, Offer), Offer);
        Negotiate(client, Response(dialect, null), offerAgain ? Offer : null);
        Assert.AreEqual(0, client.SelectedRdmaTransformIds.Length);
    }

    [TestMethod]
    public void Negotiate_OfferedNone_AcceptsNoneWithoutInventingAnException()
    {
        var client = new NegotiationClient();
        var none = new[] { Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_NONE };
        Negotiate(client, Response(DialectRevision.Smb311, none), none);
        CollectionAssert.AreEqual(none, client.SelectedRdmaTransformIds);
    }

    [TestMethod]
    [DataRow("excess")]
    [DataRow("unoffered")]
    [DataRow("unoffered-none")]
    [DataRow("unsolicited")]
    [DataRow("empty-offer")]
    [DataRow("short-data")]
    [DataRow("zero-count")]
    [DataRow("count-mismatch")]
    [DataRow("unknown-id")]
    public void Negotiate_InvalidRdmaResponse_RejectsWithoutChangingAcceptedSelection(string scenario)
    {
        var client = new NegotiationClient();
        Negotiate(client, Response(DialectRevision.Smb311, Offer), Offer);
        Smb2RDMATransformId[] accepted = client.SelectedRdmaTransformIds;
        Smb2RDMATransformId[]? offered = Offer;
        Smb2NegotiateResponsePacket response;
        switch (scenario)
        {
            case "excess":
                offered = new[] { Offer[0] };
                response = Response(DialectRevision.Smb311, new[] { Offer[0], Offer[0] });
                break;
            case "unoffered":
                offered = new[] { Offer[0] };
                response = Response(DialectRevision.Smb311, new[] { Offer[1] });
                break;
            case "unoffered-none":
                response = Response(DialectRevision.Smb311,
                    new[] { Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_NONE });
                break;
            case "unsolicited":
                offered = null;
                response = Response(DialectRevision.Smb311, new[] { Offer[0] });
                break;
            case "empty-offer":
                offered = Array.Empty<Smb2RDMATransformId>();
                response = Response(DialectRevision.Smb311, new[] { Offer[0] });
                break;
            case "short-data":
                response = Response(DialectRevision.Smb311, new[] { Offer[0] });
                var context = response.NegotiateContext_RDMA!.Value;
                context.Header.DataLength--;
                response.NegotiateContext_RDMA = context;
                break;
            case "zero-count":
                response = Response(DialectRevision.Smb311, Array.Empty<Smb2RDMATransformId>());
                break;
            case "count-mismatch":
                response = Response(DialectRevision.Smb311, Offer);
                var mismatched = response.NegotiateContext_RDMA!.Value;
                mismatched.TransformCount = 1;
                response.NegotiateContext_RDMA = mismatched;
                break;
            case "unknown-id":
                response = Response(DialectRevision.Smb311, new[] { (Smb2RDMATransformId)ushort.MaxValue });
                break;
            default:
                throw new AssertFailedException("Unknown regression scenario.");
        }

        Assert.ThrowsException<InvalidOperationException>(() => Negotiate(client, response, offered));
        Assert.AreSame(accepted, client.SelectedRdmaTransformIds,
            "Rejected server input must not replace accepted RDMA state.");
        CollectionAssert.AreEqual(Offer, client.SelectedRdmaTransformIds);
    }

    [TestMethod]
    public void Negotiate_LowerDialectWithRdmaContext_DoesNotSelectRdmaTransforms()
    {
        var client = new NegotiationClient();
        Negotiate(client, Response(DialectRevision.Smb311, Offer), Offer);
        Negotiate(client, Response(DialectRevision.Smb302, Offer), null);
        Assert.AreEqual(0, client.SelectedRdmaTransformIds.Length);
    }

    [TestMethod]
    public void MultiProtocolNegotiate_ReusedClientSelectingSmb2002_ClearsPreviousSelection()
    {
        var client = new NegotiationClient();
        Negotiate(client, Response(DialectRevision.Smb311, Offer), Offer);
        client.Response = Response(DialectRevision.Smb2002, null);
        uint status = client.MultiProtocolNegotiate(
            new[] { "SMB 2.002" }, out DialectRevision selectedDialect, out byte[] token,
            out Packet_Header header, out NEGOTIATE_Response payload);
        Assert.AreEqual(Smb2Status.STATUS_SUCCESS, status);
        Assert.AreEqual(DialectRevision.Smb2002, selectedDialect);
        Assert.AreEqual(0, client.SelectedRdmaTransformIds.Length);
    }

    [TestMethod]
    public void Negotiate_ErrorResponse_DoesNotAcceptRdmaSelection()
    {
        var client = new NegotiationClient();
        Negotiate(client, Response(DialectRevision.Smb311, Offer), Offer);
        Smb2RDMATransformId[] accepted = client.SelectedRdmaTransformIds;
        client.Response = Response(DialectRevision.Smb311,
            new[] { Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_NONE });
        client.Response.Header.Status = Smb2Status.STATUS_INVALID_PARAMETER;
        uint status = client.Negotiate(
            1, 1, Packet_Header_Flags_Values.NONE, client.NextMessageId++,
            new[] { DialectRevision.Smb311 },
            SecurityMode_Values.NEGOTIATE_SIGNING_ENABLED, Capabilities_Values.NONE, Guid.Empty,
            out DialectRevision selectedDialect, out byte[] token,
            out Smb2NegotiateRequestPacket request, out Smb2NegotiateResponsePacket received,
            rdmaTransformIds: Offer);
        Assert.AreEqual(Smb2Status.STATUS_INVALID_PARAMETER, status);
        Assert.AreSame(accepted, client.SelectedRdmaTransformIds);
    }

    private static void Negotiate(
        NegotiationClient client,
        Smb2NegotiateResponsePacket response,
        Smb2RDMATransformId[]? offered)
    {
        client.Response = response;
        uint status = client.Negotiate(
            1, 1, Packet_Header_Flags_Values.NONE, client.NextMessageId++,
            new[] { DialectRevision.Smb311, DialectRevision.Smb302, DialectRevision.Smb2002 },
            SecurityMode_Values.NEGOTIATE_SIGNING_ENABLED, Capabilities_Values.NONE, Guid.Empty,
            out DialectRevision selectedDialect, out byte[] token,
            out Smb2NegotiateRequestPacket request, out Smb2NegotiateResponsePacket received,
            preauthHashAlgs: new[] { PreauthIntegrityHashID.SHA_512 },
            rdmaTransformIds: offered);
        Assert.AreEqual(Smb2Status.STATUS_SUCCESS, status);
        Assert.AreEqual(response.PayLoad.DialectRevision, selectedDialect);
        Assert.AreSame(response, received);
        Assert.AreEqual(0, token.Length);
        if (offered == null)
        {
            Assert.IsNull(request.NegotiateContext_RDMA);
        }
        else
        {
            CollectionAssert.AreEqual(offered, request.NegotiateContext_RDMA!.Value.RDMATransformIds);
        }
    }

    private static Smb2NegotiateResponsePacket Response(
        DialectRevision dialect, Smb2RDMATransformId[]? selected)
    {
        var response = new Smb2NegotiateResponsePacket { Buffer = Array.Empty<byte>() };
        response.Header.Status = Smb2Status.STATUS_SUCCESS;
        response.PayLoad.DialectRevision = dialect;
        response.PayLoad.SecurityBufferOffset = response.BufferOffset;
        if (dialect == DialectRevision.Smb311)
        {
            var preauth = new SMB2_PREAUTH_INTEGRITY_CAPABILITIES
            {
                HashAlgorithmCount = 1,
                HashAlgorithms = new[] { PreauthIntegrityHashID.SHA_512 },
                Salt = Array.Empty<byte>(),
            };
            preauth.Header.ContextType = SMB2_NEGOTIATE_CONTEXT_Type_Values.SMB2_PREAUTH_INTEGRITY_CAPABILITIES;
            preauth.Header.DataLength = (ushort)preauth.GetDataLength();
            response.NegotiateContext_PREAUTH = preauth;
            response.PayLoad.Reserved = (NEGOTIATE_Response_Reserved_Values)1;
        }
        if (selected != null)
        {
            var context = new SMB2_RDMA_TRANSFORM_CAPABILITIES
            {
                TransformCount = (ushort)selected.Length,
                RDMATransformIds = (Smb2RDMATransformId[])selected.Clone(),
            };
            context.Header.ContextType = SMB2_NEGOTIATE_CONTEXT_Type_Values.SMB2_RDMA_TRANSFORM_CAPABILITIES;
            context.Header.DataLength = (ushort)context.GetDataLength();
            response.NegotiateContext_RDMA = context;
            response.PayLoad.Reserved = (NEGOTIATE_Response_Reserved_Values)((ushort)response.PayLoad.Reserved + 1);
        }
        response.PayLoad.NegotiateContextOffset = response.BufferOffset;
        return response;
    }

    private sealed class NegotiationClient : Smb2Client
    {
        public NegotiationClient() : base(TimeSpan.FromSeconds(1)) { }

        public Smb2NegotiateResponsePacket Response { get; set; } = null!;
        public ulong NextMessageId { get; set; }

        public override void SendPacket(byte[] data)
        {
            Assert.IsTrue(data.Length >= 32, "Exercise real SMB request serialization before returning a response.");
        }

        public override T ExpectPacket<T>(ulong messageId) => (T)(Smb2Packet)Response;
    }
}
