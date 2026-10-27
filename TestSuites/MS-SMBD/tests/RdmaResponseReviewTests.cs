// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Threading;
using Microsoft.Protocols.TestTools.StackSdk;
using Microsoft.Protocols.TestTools.StackSdk.FileAccessService.Smb2;
using Microsoft.Protocols.TestTools.StackSdk.FileAccessService.Smbd;
using Microsoft.Protocols.TestSuites.Smbd.Adapter;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Protocols.TestSuites.Smbd.Tests
{
    [TestClass]
    public class RdmaResponseReviewTests
    {
        private const ulong AsyncId = 0x1234567887654321;

        [DataTestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public void PublicReadWaitsForFinalAndAccountsRepeatedPendingOnce(bool error)
        {
            var client = new QueuedClient(
                Error(0, Smb2Status.STATUS_PENDING, 3, AsyncId),
                Error(0, Smb2Status.STATUS_PENDING, 2, AsyncId),
                error ? Error(0, Smb2Status.STATUS_ACCESS_DENIED, 0, AsyncId) : Read(0, 0, AsyncId),
                Read(2, 1));
            Assert.AreEqual(error ? Smb2Status.STATUS_ACCESS_DENIED : Smb2Status.STATUS_SUCCESS,
                client.Smb2Read(0, 131070, out _, out _));
            Assert.AreEqual((ushort)2, client.Sent.Single().CreditCharge);
            Assert.AreEqual((ushort)11, client.Smb2AvailableCredits, "8+3+2-2+0");
            Assert.AreEqual(2ul, MessageId(client));
            Assert.AreEqual(3, client.ReceiveBudgets.Count);
            Assert.AreEqual(Smb2Status.STATUS_SUCCESS, client.Smb2Read(0, 1, out _, out _));
            Assert.AreEqual((ushort)11, client.Smb2AvailableCredits);
            Assert.AreEqual(3ul, MessageId(client), "An ordinary final error leaves the existing ledger reusable.");
        }

        [TestMethod]
        public void PublicReadRejectsWrongMessageAndFullWidthAsyncIdWithoutTheirGrants()
        {
            var client = new QueuedClient(
                Error(42, Smb2Status.STATUS_PENDING, 20, AsyncId),
                Error(0, Smb2Status.STATUS_PENDING, 3, AsyncId),
                Read(0, 0, 0x9999999987654321), Read(0, 0, AsyncId));
            Assert.AreEqual(Smb2Status.STATUS_SUCCESS, client.Smb2Read(0, 131070, out _, out _));
            Assert.AreEqual((ushort)9, client.Smb2AvailableCredits);
            Assert.AreEqual(4, client.ReceiveBudgets.Count);
            Assert.AreEqual(2ul, MessageId(client));
        }

        [DataTestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public void PlainFinalPreservesStatusGrantAndHistoricalWireCharge(bool error)
        {
            var client = new QueuedClient(error
                ? Error(0, Smb2Status.STATUS_ACCESS_DENIED, 4)
                : Read(0, 4));
            Assert.AreEqual(error ? Smb2Status.STATUS_ACCESS_DENIED : Smb2Status.STATUS_SUCCESS,
                client.Smb2Read(0, 65536, out _, out _));
            ushort charge = client.Sent.Single().CreditCharge;
            Assert.AreEqual((ushort)(12 - charge), client.Smb2AvailableCredits);
            Assert.AreEqual((ulong)charge, MessageId(client));
            Assert.AreEqual(1, client.ReceiveBudgets.Count);
        }

        [TestMethod]
        public void PublicWriteFinalErrorAccountsOnlyOnceAndKeepsNextReadUsable()
        {
            var client = new QueuedClient(
                Error(0, Smb2Status.STATUS_PENDING, 3, AsyncId, Smb2Command.WRITE),
                Error(0, Smb2Status.STATUS_ACCESS_DENIED, 0, AsyncId, Smb2Command.WRITE),
                Read(2, 1));
            Assert.AreEqual(Smb2Status.STATUS_ACCESS_DENIED, client.Smb2Write(0, new byte[131070], out _));
            Assert.AreEqual((ushort)2, client.Sent.Single().CreditCharge);
            Assert.AreEqual((ushort)9, client.Smb2AvailableCredits);
            Assert.AreEqual(2ul, MessageId(client));
            Assert.AreEqual(Smb2Status.STATUS_SUCCESS, client.Smb2Read(0, 1, out _, out _));
            Assert.AreEqual((ushort)9, client.Smb2AvailableCredits);
            Assert.AreEqual(3ul, MessageId(client));
        }

        [TestMethod]
        public void AsyncFinalCannotSupplyAnotherGrant()
        {
            var client = new QueuedClient(Error(0, Smb2Status.STATUS_PENDING, 3, AsyncId), Read(0, 9, AsyncId));
            Assert.ThrowsExactly<InvalidOperationException>(() => client.Smb2Read(0, 1, out _, out _));
            Assert.AreEqual((ushort)11, client.Smb2AvailableCredits);
            Assert.AreEqual(0ul, MessageId(client));
        }

        [DataTestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public void PublicReadKeepsOverallDeadlineAcrossEmptyOrPendingMessages(bool pending)
        {
            var client = new QueuedClient { Repeat = pending ? Error(0, Smb2Status.STATUS_PENDING, 0, AsyncId) : Array.Empty<byte>() };
            typeof(Smb2OverSmbdTestClient).GetField("smb2ConnectionTimeout", BindingFlags.NonPublic | BindingFlags.Instance)
                .SetValue(client, TimeSpan.FromMilliseconds(100));
            var watch = Stopwatch.StartNew();
            Assert.ThrowsExactly<TimeoutException>(() => client.Smb2Read(0, 1, out _, out _));
            Assert.IsTrue(watch.Elapsed < TimeSpan.FromSeconds(2));
            Assert.IsTrue(client.ReceiveBudgets.Count > 1);
            Assert.IsTrue(client.ReceiveBudgets.Last() < client.ReceiveBudgets.First());
            Assert.AreEqual(0ul, MessageId(client));
            Assert.AreEqual((ushort)8, client.Smb2AvailableCredits);
        }

        [TestMethod]
        public void PublicExpectRetainsCompoundRemainder()
        {
            var first = ReadPacket(8, 1);
            first.Header.NextCommand = 80;
            var client = new QueuedClient(first.ToBytes().Concat(Read(9, 1)).ToArray());
            Assert.AreEqual(8ul, client.ExpectPacket<Smb2ReadResponsePacket>(8).Header.MessageId);
            Assert.AreEqual(9ul, client.ExpectPacket<Smb2ReadResponsePacket>(9).Header.MessageId);
            Assert.AreEqual(1, client.ReceiveBudgets.Count);
        }

        [TestMethod]
        public void PublicReadRetainsUnsolicitedOplockForItsExistingReceive()
        {
            var notification = new Smb2OpLockBreakNotificationPacket();
            notification.Header.Command = Smb2Command.OPLOCK_BREAK;
            notification.Header.Flags = Packet_Header_Flags_Values.FLAGS_SERVER_TO_REDIR;
            notification.Header.MessageId = ulong.MaxValue;
            notification.PayLoad.StructureSize = 24;
            var client = new QueuedClient(Error(0, Smb2Status.STATUS_PENDING, 3, AsyncId),
                notification.ToBytes(), Read(0, 0, AsyncId));
            Assert.AreEqual(Smb2Status.STATUS_SUCCESS, client.Smb2Read(0, 131070, out _, out _));
            Assert.AreEqual(ulong.MaxValue, client.ExpectPacket<Smb2OpLockBreakNotificationPacket>(0).Header.MessageId);
            Assert.AreEqual(3, client.ReceiveBudgets.Count);
            Assert.AreEqual((ushort)9, client.Smb2AvailableCredits);
        }

        [DataTestMethod]
        [DataRow(NtStatus.STATUS_IO_TIMEOUT, true)]
        [DataRow(NtStatus.STATUS_TIMEOUT, true)]
        [DataRow(NtStatus.STATUS_CONNECTION_DISCONNECTED, false)]
        [DataRow(NtStatus.STATUS_CANCELLED, false)]
        public void PublicExpectPreservesTimeoutVersusProviderFailure(NtStatus status, bool timeout)
        {
            var client = new QueuedClient { FirstStatus = status };
            Exception failure = Assert.Throws<Exception>(() => client.ExpectPacket<Smb2EchoResponsePacket>(0));
            Assert.AreEqual(timeout, failure is TimeoutException);
            Assert.AreEqual(!timeout, failure is InvalidOperationException);
            StringAssert.Contains(failure.Message, status.ToString());
        }

        [DataTestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public void RealTransportReassemblySpendsOnlyRemainingDeadline(bool missingFinal)
        {
            var client = new FragmentClient { MissingFinal = missingFinal };
            NtStatus status = client.ReceiveMessage(TimeSpan.FromMilliseconds(100), out byte[] message);
            Assert.AreEqual(missingFinal ? NtStatus.STATUS_IO_TIMEOUT : NtStatus.STATUS_SUCCESS, status);
            if (missingFinal) Assert.IsNull(message);
            else CollectionAssert.AreEqual(new byte[] { 1, 1 }, message);
            Assert.IsTrue(client.ReceiveBudgets.Count > 1);
            Assert.IsTrue(client.ReceiveBudgets.Last() < client.ReceiveBudgets.First());
        }

        private static ulong MessageId(QueuedClient client) =>
            (ulong)typeof(Smb2OverSmbdTestClient).GetField("messageId", BindingFlags.NonPublic | BindingFlags.Instance).GetValue(client);

        private static byte[] Error(ulong mid, uint status, ushort grant, ulong? asyncId = null, Smb2Command command = Smb2Command.READ)
        {
            var packet = new Smb2ErrorResponsePacket();
            packet.Header.Command = command;
            packet.Header.MessageId = mid;
            packet.Header.Status = status;
            packet.Header.CreditRequestResponse = grant;
            packet.Header.Flags = Packet_Header_Flags_Values.FLAGS_SERVER_TO_REDIR;
            if (asyncId.HasValue)
            {
                packet.Header.Flags |= Packet_Header_Flags_Values.FLAGS_ASYNC_COMMAND;
                packet.AsyncId = asyncId.Value;
            }
            packet.PayLoad.StructureSize = 9;
            packet.PayLoad.ErrorData = new byte[1];
            return packet.ToBytes();
        }

        private static Smb2ReadResponsePacket ReadPacket(ulong mid, ushort grant, ulong? asyncId = null)
        {
            var response = new Smb2ReadResponsePacket();
            response.Header.Command = Smb2Command.READ;
            response.Header.Flags = Packet_Header_Flags_Values.FLAGS_SERVER_TO_REDIR;
            response.Header.MessageId = mid;
            response.Header.CreditRequestResponse = grant;
            if (asyncId.HasValue)
            {
                response.Header.Flags |= Packet_Header_Flags_Values.FLAGS_ASYNC_COMMAND;
                response.AsyncId = asyncId.Value;
            }
            response.PayLoad.StructureSize = 17;
            response.PayLoad.DataOffset = (byte)Smb2OverSmbdTestClient.READ_RESPONSE_HEADER_SIZE;
            response.Buffer = Array.Empty<byte>();
            return response;
        }

        private static byte[] Read(ulong mid, ushort grant, ulong? asyncId = null) => ReadPacket(mid, grant, asyncId).ToBytes();

        private sealed class QueuedClient : Smb2OverSmbdTestClient
        {
            private readonly Queue<byte[]> responses;
            public List<Packet_Header> Sent { get; } = new();
            public List<TimeSpan> ReceiveBudgets { get; } = new();
            public byte[] Repeat { get; set; }
            public NtStatus? FirstStatus { get; set; }

            public QueuedClient(params byte[][] responses) : base(TimeSpan.FromSeconds(1))
            {
                this.responses = new Queue<byte[]>(responses);
                Decoder.TransportType = Smb2TransportType.Rdma;
                Smb2AvailableCredits = 8;
            }

            public override void SendPacket(byte[] data) => Sent.Add(TypeMarshal.ToStruct<Packet_Header>(data));

            protected override NtStatus ReceiveSmbdMessage(TimeSpan timeout, out byte[] message)
            {
                ReceiveBudgets.Add(timeout);
                message = null;
                if (FirstStatus.HasValue && ReceiveBudgets.Count == 1) return FirstStatus.Value;
                if (Repeat != null && ReceiveBudgets.Count < 60)
                {
                    Thread.Sleep(5);
                    message = Repeat;
                }
                else if (responses.Count > 0) message = responses.Dequeue();
                return message == null ? NtStatus.STATUS_IO_TIMEOUT : NtStatus.STATUS_SUCCESS;
            }
        }

        private sealed class FragmentClient : SmbdClient
        {
            public bool MissingFinal { get; set; }
            public List<TimeSpan> ReceiveBudgets { get; } = new();

            public FragmentClient()
            {
                Connection = new SmbdConnection();
                Connection.ReceiveCredits = 4;
                Connection.FragmentReassemblyBuffer = new byte[1024];
            }

            public override NtStatus ReceiveDataTransferMessage(TimeSpan timeout, out SmbdDataTransferMessage message)
            {
                ReceiveBudgets.Add(timeout);
                Thread.Sleep(5);
                message = new SmbdDataTransferMessage
                {
                    DataLength = 1,
                    RemainingDataLength = MissingFinal || ReceiveBudgets.Count == 1 ? 1u : 0u,
                    Buffer = new byte[] { 1 }
                };
                return ReceiveBudgets.Count > 30 ? NtStatus.STATUS_IO_TIMEOUT : NtStatus.STATUS_SUCCESS;
            }
        }
    }
}
