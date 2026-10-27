// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.ExceptionServices;
using System.Xml.Linq;
using Microsoft.Protocol.TestSuites.Smbd.TestSuite;
using Microsoft.Protocols.TestSuites.Smbd.Adapter;
using Microsoft.Protocols.TestTools;
using Microsoft.Protocols.TestTools.StackSdk;
using Microsoft.Protocols.TestTools.StackSdk.FileAccessService.Smb2;
using Microsoft.Protocols.TestTools.StackSdk.FileAccessService.Smbd;
using Microsoft.Protocols.TestTools.StackSdk.Security.SspiLib;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using DetectorClient = Microsoft.Protocols.TestManager.SMBDPlugin.Detector.SmbdClient;

namespace Microsoft.Protocols.TestSuites.Smbd.UnitTests
{
    [TestClass]
    [TestCategory("HardwareFree")]
    [DoNotParallelize]
    public class NegotiationReviewTests
    {
        private object previousSite;
        private static readonly FieldInfo BaseSite = typeof(TestClassBase).GetField(
            "baseTestSite", BindingFlags.NonPublic | BindingFlags.Static);

        public TestContext TestContext { get; set; }

        [TestInitialize]
        public void Initialize()
        {
            previousSite = BaseSite.GetValue(null);
        }

        [TestCleanup]
        public void Cleanup()
        {
            BaseSite.SetValue(null, previousSite);
        }

        [DataTestMethod]
        [DataRow(65536u)]
        [DataRow(uint.MaxValue)]
        public void DetectorRejectsInvalidSafetyMargin(uint margin)
        {
            var client = Detector(margin);
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => client.CalculateSmb2MaxReadWriteSize());
        }

        [DataTestMethod]
        [DataRow(0u, 65536u)]
        [DataRow(100u, 65436u)]
        [DataRow(65535u, 1u)]
        public void DetectorRetainsValidSingleCreditLimit(uint margin, uint expected)
        {
            Assert.AreEqual(expected, Detector(margin).CalculateSmb2MaxReadWriteSize());
        }

        [TestMethod]
        public void DetectorRetainsNegotiatedLimitsAndPrerequisite()
        {
            var client = Detector(100);
            Set(client, "maxReadSize", 8192u);
            Set(client, "maxWriteSize", 4096u);
            Assert.AreEqual(4096u, client.CalculateSmb2MaxReadWriteSize());
            Set(client, "negotiated", false);
            Assert.ThrowsExactly<InvalidOperationException>(() => client.CalculateSmb2MaxReadWriteSize());
        }

        [DataTestMethod]
        [DataRow(4096u)]
        [DataRow(32768u)]
        [DataRow(65536u)]
        public void ConfiguredIoctlOutputSizeReachesEncodedRequest(uint configuredSize)
        {
            var properties = Properties();
            properties["QueryNetworkInterfaceMaxOutputResponse"] = configuredSize.ToString();
            var test = new Smb2MultiChannelOverRdma();
            Configure(test, properties);
            typeof(Smb2MultiChannelOverRdma).GetMethod("TestInitialize",
                BindingFlags.Instance | BindingFlags.NonPublic).Invoke(test, null);
            var mainChannel = (Smb2OverSmbdTestClient)Get(test, "mainChannelClient");
            var client = new CapturingClient
            {
                QueryNetworkInterfaceMaxOutputResponse = mainChannel.QueryNetworkInterfaceMaxOutputResponse
            };
            client.Smb2QueryNetworkInterfaceInfo(out _);
            var payload = TypeMarshal.ToStruct<IOCTL_Request>(client.Sent.Skip(64).ToArray());
            Assert.AreEqual(configuredSize, payload.MaxOutputResponse);
        }

        [DataTestMethod]
        [DataRow(131072u, 262144u, 131072u, (ushort)2)]
        [DataRow(262144u, 131072u, 131072u, (ushort)2)]
        [DataRow(32768u, 16384u, 16384u, (ushort)1)]
        public void IoctlPreservesNegotiatedLimitAndCreditCharge(
            uint configured, uint negotiated, uint expected, ushort credits)
        {
            var client = new CapturingClient
            {
                QueryNetworkInterfaceMaxOutputResponse = configured,
                Smb2MaxTransactSize = negotiated,
                Smb2AvailableCredits = 64
            };
            client.Smb2QueryNetworkInterfaceInfo(out _);
            var payload = TypeMarshal.ToStruct<IOCTL_Request>(client.Sent.Skip(64).ToArray());
            var header = TypeMarshal.ToStruct<Packet_Header>(client.Sent);
            Assert.AreEqual(expected, payload.MaxOutputResponse);
            Assert.AreEqual(credits, header.CreditCharge);
            Assert.AreEqual((ushort)(65 - credits), client.Smb2AvailableCredits);
        }

        [DataTestMethod]
        [DataRow(8192u, 65536u, 65536u, 65536u, 8192u)]
        [DataRow(32768u, 65536u, 65536u, 65536u, 32768u)]
        [DataRow(65536u, 8192u, 16384u, 32768u, 8192u)]
        [DataRow(65536u, 32768u, 8192u, 16384u, 8192u)]
        [DataRow(65536u, 32768u, 16384u, 4096u, 4096u)]
        public void ConfiguredRdmaPayloadReachesReadAndWriteBuilders(
            uint configured, uint maxRead, uint maxWrite, uint maxRdma, uint expected)
        {
            var properties = Properties();
            properties["RdmaChannelDataSizeInByte"] = configured.ToString();
            var adapter = new SmbdAdapter(Site(properties));
            var client = new CapturingClient
            {
                Smb2MaxReadSize = maxRead,
                Smb2MaxWriteSize = maxWrite,
                Smb2AvailableCredits = 64
            };
            var transport = (SmbdClient)Get(client, "smbdClient");
            typeof(SmbdClient).GetProperty("Connection").SetValue(transport,
                new SmbdConnection { MaxReadWriteSize = maxRdma });
            Set(adapter, "client", client);
            uint size = adapter.GetRdmaChannelDataSize();
            byte[] descriptors = new byte[SmbdBufferDescriptorV1.SIZE * 2];
            adapter.Smb2ReadOverRdmaChannel(0, size, descriptors, out _, out _);
            var read = TypeMarshal.ToStruct<READ_Request>(client.Sent.Skip(64).ToArray());
            Assert.AreEqual(expected, read.Length);
            adapter.Smb2WriteOverRdmaChannel(0, descriptors, size, out _);
            var write = TypeMarshal.ToStruct<WRITE_Request>(client.Sent.Skip(64).ToArray());
            Assert.AreEqual(expected, write.RemainingBytes);
            Assert.AreEqual(0u, write.Length);
        }

        [TestMethod]
        public void ZeroConfiguredBuffersAreRejectedBeforeSending()
        {
            var client = new CapturingClient { QueryNetworkInterfaceMaxOutputResponse = 0 };
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => client.Smb2QueryNetworkInterfaceInfo(out _));
            Assert.IsNull(client.Sent);
            var properties = Properties();
            properties["RdmaChannelDataSizeInByte"] = "0";
            var adapter = new SmbdAdapter(Site(properties));
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => adapter.GetRdmaChannelDataSize());
        }

#if LINUX
        [TestMethod]
        public void DisconnectedTransportIsNotAcceptedAsNoResponseTimeout()
        {
            var client = new Smb2OverSmbdTestClient(TimeSpan.FromMilliseconds(100));
            client.Decoder.TransportType = Smb2TransportType.Rdma;
            var transport = (SmbdClient)Get(client, "smbdClient");
            var connection = new SmbdConnection
            {
                Endpoint = (SmbdConnectionEndpoint)RuntimeHelpers.GetUninitializedObject(typeof(SmbdConnectionEndpoint))
            };
            typeof(SmbdClient).GetProperty("Connection").SetValue(transport, connection);
            Exception failure = null;
            try
            {
                client.ExpectPacket<Smb2EchoResponsePacket>(0);
            }
            catch (Exception ex)
            {
                failure = ex;
            }
            Assert.IsNotNull(failure);
            Assert.IsNotInstanceOfType<TimeoutException>(failure);
            Assert.IsInstanceOfType<InvalidOperationException>(failure);
            StringAssert.Contains(failure.Message, NtStatus.STATUS_CONNECTION_DISCONNECTED.ToString());
        }
#endif

        [DataTestMethod]
        [DataRow(NtStatus.STATUS_IO_TIMEOUT, true)]
        [DataRow(NtStatus.STATUS_TIMEOUT, true)]
        [DataRow(NtStatus.STATUS_CANCELLED, false)]
        [DataRow(NtStatus.STATUS_INTERNAL_ERROR, false)]
        [DataRow(NtStatus.STATUS_CONNECTION_DISCONNECTED, false)]
        [DataRow(NtStatus.STATUS_INSUFFICIENT_RESOURCES, false)]
        public void ReceiveStatusClassificationDoesNotHideProviderFailures(NtStatus status, bool timeout)
        {
            var client = new ReceivingClient { Status = status };
            Exception failure = Assert.Throws<Exception>(() => client.ExpectPacket<Smb2EchoResponsePacket>(0));
            Assert.AreEqual(timeout, failure is TimeoutException);
            Assert.AreEqual(!timeout, failure is InvalidOperationException);
            StringAssert.Contains(failure.Message, status.ToString());
            StringAssert.Contains(failure.Message, $"0x{(uint)status:X8}");
        }

        [TestMethod]
        public void NativeQueueTimeoutExceptionIsPreserved()
        {
            var timeout = new TimeoutException("receive queue expired");
            var client = new ReceivingClient { Failure = timeout };
            Assert.AreSame(timeout, Assert.ThrowsExactly<TimeoutException>(
                () => client.ExpectPacket<Smb2EchoResponsePacket>(0)));
        }

        [DataTestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public void PendingReadCompletesAndAccountsCreditsOnceIncludingFinalError(bool error)
        {
            var client = new QueuedResponseClient(
                ErrorResponse(0, Smb2Status.STATUS_PENDING, 3, 0x1234567887654321),
                ErrorResponse(0, Smb2Status.STATUS_PENDING, 2, 0x1234567887654321),
                error ? ErrorResponse(0, Smb2Status.STATUS_ACCESS_DENIED, 0, 0x1234567887654321)
                    : FinalRead(0, 0, 0x1234567887654321),
                FinalRead(2, 1));
            uint status = client.Smb2Read(0, 131072, out _, out _);
            Assert.AreEqual(error ? Smb2Status.STATUS_ACCESS_DENIED : Smb2Status.STATUS_SUCCESS, status);
            Assert.AreEqual((ushort)11, client.Smb2AvailableCredits, "8+3+2-2+0");
            Assert.AreEqual(2ul, Get(client, "messageId"));
            Assert.AreEqual(3, client.ReceiveCount);
            Assert.AreEqual(1, client.SendCount);
            Assert.AreEqual(Smb2Status.STATUS_SUCCESS, client.Smb2Read(0, 1, out _, out _));
            Assert.AreEqual((ushort)11, client.Smb2AvailableCredits);
            Assert.AreEqual(3ul, Get(client, "messageId"), "Final errors leave the existing ledger reusable.");
        }

        [TestMethod]
        public void PendingReadDiscardsUnmatchedAndWrongAsyncIdWithoutGrant()
        {
            var client = new QueuedResponseClient(
                ErrorResponse(42, Smb2Status.STATUS_PENDING, 20, 7),
                ErrorResponse(0, Smb2Status.STATUS_PENDING, 3, 0x1234567887654321),
                FinalRead(0, 0, 0x9999999987654321),
                FinalRead(0, 0, 0x1234567887654321));
            Assert.AreEqual(Smb2Status.STATUS_SUCCESS, client.Smb2Read(0, 131072, out _, out _));
            Assert.AreEqual((ushort)9, client.Smb2AvailableCredits, "8+3-2; unmatched grant is ignored");
            Assert.AreEqual(4, client.ReceiveCount);
        }

        [TestMethod]
        public void PlainReadRetainsFinalGrantAndStatus()
        {
            var client = new QueuedResponseClient(FinalRead(0, 4));
            Assert.AreEqual(Smb2Status.STATUS_SUCCESS, client.Smb2Read(0, 1, out _, out _));
            Assert.AreEqual((ushort)11, client.Smb2AvailableCredits);
            Assert.AreEqual(1ul, Get(client, "messageId"));
        }

        [TestMethod]
        public void PendingWriteFinalErrorAccountsChargeAndPreservesNextRequest()
        {
            var client = new QueuedResponseClient(
                ErrorResponse(0, Smb2Status.STATUS_PENDING, 3, 7, Smb2Command.WRITE),
                ErrorResponse(0, Smb2Status.STATUS_ACCESS_DENIED, 0, 7, Smb2Command.WRITE),
                FinalRead(2, 1));
            Assert.AreEqual(Smb2Status.STATUS_ACCESS_DENIED, client.Smb2Write(0, new byte[131072], out _));
            Assert.AreEqual((ushort)9, client.Smb2AvailableCredits);
            Assert.AreEqual(2ul, Get(client, "messageId"));
            Assert.AreEqual(Smb2Status.STATUS_SUCCESS, client.Smb2Read(0, 1, out _, out _));
            Assert.AreEqual((ushort)9, client.Smb2AvailableCredits);
            Assert.AreEqual(3ul, Get(client, "messageId"));
        }

        [TestMethod]
        public void AsyncFinalCannotGrantCredits()
        {
            var client = new QueuedResponseClient(
                ErrorResponse(0, Smb2Status.STATUS_PENDING, 3, 7),
                FinalRead(0, 9, 7));
            Assert.ThrowsExactly<InvalidOperationException>(() => client.Smb2Read(0, 1, out _, out _));
            Assert.AreEqual((ushort)11, client.Smb2AvailableCredits);
        }

        [TestMethod]
        public void PendingStreamDoesNotRestartOverallDeadline()
        {
            var client = new QueuedResponseClient { RepeatPending = true };
            typeof(Smb2OverSmbdTestClient).GetField("smb2ConnectionTimeout", BindingFlags.NonPublic | BindingFlags.Instance)
                .SetValue(client, TimeSpan.FromMilliseconds(50));
            var watch = Stopwatch.StartNew();
            Assert.ThrowsExactly<TimeoutException>(() => client.Smb2Read(0, 1, out _, out _));
            Assert.IsTrue(watch.Elapsed < TimeSpan.FromSeconds(2));
            Assert.IsTrue(client.ReceiveCount > 1);
            Assert.IsTrue(client.ReceiveBudgets.Last() < client.ReceiveBudgets.First());
        }

        [TestMethod]
        public void SharedEnvelopeConsumesEachInterimOnceNotEachAsyncId()
        {
            var client = new QueuedResponseClient();
            ulong? asyncId = null;
            byte[] pending = ErrorResponse(0, Smb2Status.STATUS_PENDING, 3, 0x1234567887654321);
            var first = client.DecodeSmb2Responses(pending).Single();
            Assert.IsTrue(client.TryAcceptResponse(first, 0, ref asyncId));
            Assert.IsFalse(client.TryAcceptResponse(first, 0, ref asyncId));
            Assert.IsTrue(client.TryAcceptResponse(client.DecodeSmb2Responses(pending).Single(), 0, ref asyncId));
            Assert.AreEqual((ushort)14, client.Smb2AvailableCredits);
            Assert.AreEqual(0ul, Get(client, "messageId"));
            Assert.AreEqual(0x1234567887654321ul, asyncId);
        }

        [TestMethod]
        public void SharedReceiveRetainsCompoundRemainderForOutstandingRequests()
        {
            var first = ReadResponse();
            first.Header.MessageId = 8;
            first.Header.NextCommand = 80;
            first.Buffer = Array.Empty<byte>();
            var client = new QueuedResponseClient(first.ToBytes().Concat(FinalRead(9, 1)).ToArray());
            Assert.AreEqual(8ul, client.ReceiveSmb2Response(TimeSpan.FromSeconds(1)).MessageId);
            Assert.AreEqual(9ul, client.ReceiveSmb2Response(TimeSpan.FromSeconds(1)).MessageId);
            Assert.AreEqual(1, client.ReceiveCount);
        }

        [TestMethod]
        public void PendingReadRetainsUnsolicitedOplockNotificationForExplicitReceive()
        {
            var notification = new Smb2OpLockBreakNotificationPacket();
            notification.Header.Command = Smb2Command.OPLOCK_BREAK;
            notification.Header.Flags = Packet_Header_Flags_Values.FLAGS_SERVER_TO_REDIR;
            notification.Header.MessageId = ulong.MaxValue;
            notification.PayLoad.StructureSize = 24;
            var client = new QueuedResponseClient(
                ErrorResponse(0, Smb2Status.STATUS_PENDING, 3, 7),
                notification.ToBytes(), FinalRead(0, 0, 7));
            Assert.AreEqual(Smb2Status.STATUS_SUCCESS, client.Smb2Read(0, 131072, out _, out _));
            var received = client.ExpectPacket<Smb2OpLockBreakNotificationPacket>(0);
            Assert.AreEqual(ulong.MaxValue, received.Header.MessageId);
            Assert.AreEqual(3, client.ReceiveCount);
            Assert.AreEqual((ushort)9, client.Smb2AvailableCredits);
        }

        [TestMethod]
        public void NegotiatedCapabilitiesCacheActualServerResponseNotClientOffer()
        {
            var client = new RdmaNegotiationClient(DialectRevision.Smb302);
            client.ResponseCapabilities = NEGOTIATE_Response_Capabilities_Values.GLOBAL_CAP_DFS;
            client.Smb2Negotiate(new[] { DialectRevision.Smb302 }, out _);
            Assert.AreEqual(NEGOTIATE_Response_Capabilities_Values.GLOBAL_CAP_DFS, client.NegotiatedServerCapabilities);
            client.ResponseCapabilities = NEGOTIATE_Response_Capabilities_Values.GLOBAL_CAP_MULTI_CHANNEL;
            client.Smb2Negotiate(new[] { DialectRevision.Smb302 }, out _);
            Assert.AreEqual(NEGOTIATE_Response_Capabilities_Values.GLOBAL_CAP_MULTI_CHANNEL, client.NegotiatedServerCapabilities);
        }

        [DataTestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public void TransportReassemblyUsesRemainingMessageDeadline(bool missingFinal)
        {
            var client = new FragmentResponseClient { MissingFinal = missingFinal };
            NtStatus status = client.ReceiveMessage(TimeSpan.FromMilliseconds(50), out byte[] message);
            Assert.AreEqual(missingFinal ? NtStatus.STATUS_IO_TIMEOUT : NtStatus.STATUS_SUCCESS, status);
            if (missingFinal) Assert.IsNull(message);
            else CollectionAssert.AreEqual(new byte[] { 1, 1 }, message);
            Assert.IsTrue(client.ReceiveBudgets.Count > 1);
            Assert.IsTrue(client.ReceiveBudgets.Last() < client.ReceiveBudgets.First());
        }

        [DataTestMethod]
        [DataRow(16391u, 3)]
        [DataRow(8192u, 1)]
        [DataRow(7u, 1)]
        public void MultichannelPublicEntrySeedsExactInlineChunks(uint total, int count)
        {
            var properties = Properties();
            var test = InitializeMultichannel(properties);
            ((TestConfig)Get(test, "testConfig")).LargeFileSizeInByte = total;
            var client = new InlineChunkClient
            {
                Smb2MaxReadSize = 8192, Smb2MaxWriteSize = 8192
            };
            Set(test, "mainChannelClient", client);
            RunToCapturedBoundary(
                test.BVT_Smb2MultipleChannel_2Channels_DiffNicTypeDiffTransport);
            Assert.AreEqual(count, client.Writes.Count);
            Assert.AreEqual(total, (uint)client.FileContent.Length);
            ulong offset = 0;
            foreach (var request in client.Writes)
            {
                Assert.AreEqual(Channel_Values.CHANNEL_NONE, request.Channel);
                Assert.AreEqual(offset, request.Offset);
                Assert.AreEqual((uint)Math.Min(8192ul, total - offset), request.Length);
                offset += request.Length;
            }
            Assert.AreEqual((ulong)total, offset);
            CollectionAssert.AreEqual(client.FileContent, client.Payloads.SelectMany(bytes => bytes).ToArray());
        }

        [TestMethod]
        public void SigningNegativePublicEntryMutatesEqualBytesInEncodedTransform()
        {
            var properties = Properties();
            properties["RdmaChannelDataSizeInByte"] = "4096";
            var test = new Smb2OverRdmaChannelTransformSigning();
            Configure(test, properties);
            var client = new SignatureMutationClient();
            SetConnection(client, new SmbdConnection { MaxReadWriteSize = 65536, MaxSendSize = 65536 });
            client.ServerConnection.MaxReadWriteSize = client.ServerConnection.MaxReceiveSize = 65536;
            Set(Get(test, "smbdAdapter"), "client", client);
            RunToCapturedBoundary(() => test.WriteOverRdma_Signing(
                smb2RdmaTransformIds: new[] { Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_SIGNING },
                setInvalidSignature: true, enableRemoteInvalidation: false));
            Assert.IsNotNull(client.EncodedSignature);
            Assert.AreEqual(1, client.OriginalSignature.Zip(client.EncodedSignature).Count(p => p.First != p.Second));
            CollectionAssert.AreEqual(client.OriginalSignature.Skip(1).ToArray(),
                client.EncodedSignature.Skip(1).ToArray());
        }

        private static byte[] ErrorResponse(ulong mid, uint status, ushort grant, ulong asyncId,
            Smb2Command command = Smb2Command.READ)
        {
            var packet = new Smb2ErrorResponsePacket();
            packet.Header.Command = command;
            packet.Header.MessageId = mid;
            packet.Header.Status = status;
            packet.Header.CreditRequestResponse = grant;
            packet.Header.Flags = Packet_Header_Flags_Values.FLAGS_SERVER_TO_REDIR
                | Packet_Header_Flags_Values.FLAGS_ASYNC_COMMAND;
            packet.AsyncId = asyncId;
            packet.PayLoad.StructureSize = 9;
            packet.PayLoad.ErrorData = new byte[1];
            return packet.ToBytes();
        }

        private static void RunToCapturedBoundary(Action action)
        {
            try { action(); }
            catch (BoundaryReachedException) { return; }
            Assert.Fail("Production entry did not reach the captured boundary.");
        }

        private static byte[] FinalRead(ulong mid, ushort grant, ulong? asyncId = null)
        {
            var response = ReadResponse();
            response.Header.MessageId = mid;
            response.Header.CreditRequestResponse = grant;
            if (asyncId.HasValue)
            {
                response.Header.Flags |= Packet_Header_Flags_Values.FLAGS_ASYNC_COMMAND;
                response.AsyncId = asyncId.Value;
            }
            response.Buffer = Array.Empty<byte>();
            return response.ToBytes();
        }

        [DataTestMethod]
        [DataRow((ushort)1, true)]
        [DataRow((ushort)2, true)]
        [DataRow((ushort)0, false)]
        public void NegotiateCreditsAreNonzeroNotBoundedByRequest(ushort granted, bool accepted)
        {
            var test = new SmbdNegotiate();
            Configure(test, Properties());
            var response = new SmbdNegotiateResponse
            {
                MinVersion = SmbdVersion.V1,
                MaxVersion = SmbdVersion.V1,
                NegotiatedVersion = SmbdVersion.V1,
                CreditsRequested = 1,
                CreditsGranted = granted,
                MaxReadWriteSize = 1048576,
                PreferredSendSize = 128,
                MaxReceiveSize = 128,
                MaxFragmentedSize = 131072
            };
            Action check = () => test.NegotiateBasicChecker(response, 1, 128, 128, 131072);
            if (accepted)
            {
                check();
            }
            else
            {
                Assert.ThrowsExactly<AssertFailedException>(check);
            }
        }

        [DataTestMethod]
        [DataRow("NonWindows")]
        [DataRow("WindowsServer2012R2")]
        public void ReceiveOverflowProviderExpectationIsOptIn(string platform)
        {
            var properties = Properties();
            properties["Platform"] = platform;
            properties["ExpectDisconnectOnReceiveOverflow"] = "false";
            var test = new SmbdDataTransfer();
            Configure(test, properties);
            Assert.ThrowsExactly<AssertInconclusiveException>(
                test.SmbdDataTransfer_NegativeParameter_DataLength_AgainstMaxReceiveSize);
        }

        [TestMethod]
        public void MissingOverflowExpectationRemainsDisabled()
        {
            var properties = Properties();
            properties.Remove("ExpectDisconnectOnReceiveOverflow");
            var config = new TestConfig(Site(properties));
            Assert.IsFalse(config.ExpectDisconnectOnReceiveOverflow);
            properties["ExpectDisconnectOnReceiveOverflow"] = "true";
            Assert.IsTrue(new TestConfig(Site(properties)).ExpectDisconnectOnReceiveOverflow);
        }

        [DataTestMethod]
        [DataRow(NtStatus.STATUS_CONNECTION_DISCONNECTED)]
        [DataRow(NtStatus.STATUS_CANCELLED)]
        [DataRow(NtStatus.STATUS_IO_TIMEOUT)]
        public void DataTransferRead_ReturnedFailureStopsBeforeEmptyMessageRetry(NtStatus status)
        {
            var test = new SmbdDataTransfer();
            Configure(test, Properties());
            var client = new CreditClient(Array.Empty<SmbdDataTransferMessage>())
            {
                ReceiveStatus = status
            };
            SetConnection(client, new SmbdConnection { ReceiveCredits = 1 });
            Set(Get(test, "smbdAdapter"), "client", client);

            var failure = Assert.ThrowsExactly<AssertFailedException>(() => test.ValidateReadResponse(80));
            StringAssert.Contains(failure.Message, status.ToString());
            Assert.AreEqual(1, client.Received);
            Assert.AreEqual(1u, client.ClientConnection.ReceiveCredits);
            Assert.AreEqual(0, client.Posted);
            Assert.AreEqual(0, client.Sent);
        }

        [DataTestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public void DataTransferRead_SuccessfulEmptyMessageStillAllowsReadCompletion(bool emptyFirst)
        {
            byte[] bytes = ReadResponse().ToBytes();
            var messages = new List<SmbdDataTransferMessage>();
            if (emptyFirst)
            {
                messages.Add(Transfer(Array.Empty<byte>(), 0, 1));
            }
            messages.Add(Transfer(bytes, 0, 1));
            var test = new SmbdDataTransfer();
            Configure(test, Properties());
            var client = new CreditClient(messages) { PostLimit = 0 };
            SetConnection(client, new SmbdConnection { ReceiveCredits = (uint)messages.Count });
            Set(Get(test, "smbdAdapter"), "client", client);

            test.ValidateReadResponse(bytes.Length);

            Assert.AreEqual(messages.Count, client.Received);
            Assert.AreEqual(1, client.Sent);
        }

        [DataTestMethod]
        [DataRow(2048, 1364u, 2, false)]
        [DataRow(2048, 1024u, 2, true)]
        [DataRow(4096, 1364u, 3, true)]
        public void ZeroRemainingMutation_RequiresAnOriginallyNonfinalFragment(
            int requestSize, uint maxSendSize, int selectedMessage, bool nonfinal)
        {
            var messages = SmbdClient.SplitData2Segments(new byte[requestSize],
                maxSendSize - (uint)SmbdDataTransferMessage.DEFAULT_DATA_OFFSET);
            var test = new SmbdDataTransfer();
            Configure(test, Properties());
            var client = new CreditClient(Array.Empty<SmbdDataTransferMessage>())
            {
                StopAfterSends = selectedMessage
            };
            Set(Get(test, "smbdAdapter"), "client", client);
            uint originalRemaining = messages[selectedMessage - 1].RemainingDataLength;
            Action send = () => test.SendWithInvalidRemainingDataLength(messages, selectedMessage, 0);

            if (nonfinal)
            {
                Assert.IsTrue(originalRemaining > 0);
                Assert.ThrowsExactly<SendCapturedException>(send);
                Assert.AreEqual(selectedMessage, client.Sent);
                Assert.AreEqual(0u, client.LastRemaining);
            }
            else
            {
                Assert.AreEqual(0u, originalRemaining);
                var failure = Assert.ThrowsExactly<AssertFailedException>(send);
                StringAssert.Contains(failure.Message, "non-final");
                Assert.AreEqual(0, client.Sent);
            }
            Assert.AreEqual(originalRemaining, messages[selectedMessage - 1].RemainingDataLength);
        }

        [DataTestMethod]
        [DataRow("final", 1u, (ushort)0, false)]
        [DataRow("final", 1u, (ushort)1, true)]
        [DataRow("final", 1u, (ushort)2, true)]
        [DataRow("final", 3u, (ushort)0, true)]
        [DataRow("final", 3u, (ushort)1, true)]
        [DataRow("intermediate", 1u, (ushort)0, false)]
        [DataRow("intermediate", 1u, (ushort)1, true)]
        [DataRow("intermediate", 3u, (ushort)0, true)]
        [DataRow("intermediate", 3u, (ushort)1, true)]
        [DataRow("empty", 1u, (ushort)0, false)]
        [DataRow("empty", 1u, (ushort)1, true)]
        [DataRow("empty", 3u, (ushort)0, true)]
        [DataRow("empty", 3u, (ushort)1, true)]
        public void ValidateReadResponse_ChecksEveryMessageBeforeReplenishment(
            string kind, uint initialCredits, ushort grant, bool accepted)
        {
            var packet = ReadResponse();
            packet.Buffer = Enumerable.Range(0, 17).Select(i => (byte)i).ToArray();
            packet.PayLoad.DataLength = (uint)packet.Buffer.Length;
            byte[] bytes = packet.ToBytes();
            var messages = new List<SmbdDataTransferMessage>();
            if (kind == "empty")
            {
                messages.Add(Transfer(Array.Empty<byte>(), 0, grant));
                messages.Add(Transfer(bytes, 0, 1));
            }
            else if (kind == "intermediate")
            {
                messages.Add(Transfer(bytes.Take(40).ToArray(), (uint)bytes.Length - 40, grant));
                messages.Add(Transfer(bytes.Skip(40).ToArray(), 0, 1));
            }
            else
            {
                messages.Add(Transfer(bytes, 0, grant));
            }

            var test = new SmbdCreditManagement();
            Configure(test, Properties());
            using var receiveResults = new SyncFilterQueue<SmbdRequestResult>();
            var endpoint = (SmbdConnectionEndpoint)RuntimeHelpers.GetUninitializedObject(
                typeof(SmbdConnectionEndpoint));
            Set(endpoint, "receiveRequestResult", receiveResults);
            var client = new CreditClient(messages);
            SetConnection(client, new SmbdConnection
            {
                ReceiveCredits = initialCredits,
                SendCreditTarget = 1,
                Endpoint = endpoint
            });
            Set(Get(test, "smbdAdapter"), "client", client);
            try
            {
                Action validate = () => test.ValidateReadResponse((int)initialCredits, bytes.Length);
                if (accepted)
                {
                    validate();
                    Assert.AreEqual(messages.Count, client.Received);
                }
                else
                {
                    var failure = Assert.ThrowsExactly<AssertFailedException>(validate);
                    StringAssert.Contains(failure.Message, "last credit");
                    Assert.AreEqual(1, client.Received);
                    Assert.AreEqual(0, client.Posted);
                    Assert.AreEqual(0, client.Sent);
                }
            }
            finally
            {
                TestContext.WriteLine(
                    $"kind={kind}, initialCredits={initialCredits}, grant={grant}, "
                    + $"received={client.Received}, posted={client.Posted}, sent={client.Sent}");
            }
        }

        [DataTestMethod]
        [DataRow(65536u)]
        [DataRow(32768u)]
        [DataRow(1048576u)]
        public void AlternativeChannelInitialization_ForwardsConfiguredCap(uint configured)
        {
            var properties = Properties();
            properties["ClientMaxReadWriteSize"] = configured.ToString();
            var test = InitializeMultichannel(properties);
            var client = (Smb2OverSmbdTestClient)Get(test, "alternativeChannelClient");
            TestContext.WriteLine($"configured={configured}, alternativeClientCap={client.ClientMaxReadWriteSize}");
            Assert.AreEqual(configured, client.ClientMaxReadWriteSize);
        }

        [DataTestMethod]
        [DataRow(65536u, 1048576u, 150000u, new uint[] { 65536, 65536, 18928 })]
        [DataRow(32768u, 1048576u, 70000u, new uint[] { 32768, 32768, 4464 })]
        [DataRow(1048576u, 32768u, 70000u, new uint[] { 32768, 32768, 4464 })]
        [DataRow(1048576u, 1048576u, 1048593u, new uint[] { 1048576, 17 })]
        [DataRow(65536u, 65536u, 65536u, new uint[] { 65536 })]
        [DataRow(1048576u, 1048576u, 0u, new uint[] { })]
        public void AlternativeChannelRead_BoundsActualRegisteredAndEncodedLengths(
            uint effectiveRdmaLimit, uint smb2Limit, uint total, uint[] expectedLengths)
        {
            var test = InitializeMultichannel(Properties());
            byte[] content = Enumerable.Range(0, (int)total).Select(i => (byte)(i % 251)).ToArray();
            var client = new RdmaReadClient(content) { Smb2MaxReadSize = smb2Limit };
            SetConnection(client, new SmbdConnection { MaxReadWriteSize = effectiveRdmaLimit });
            Set(test, "alternativeChannelClient", client);
            Invoke(test, "ReadFileFromAlternativeChannel", content, total);

            TestContext.WriteLine(
                $"SMBD={effectiveRdmaLimit}, SMB2={smb2Limit}, total={total}, "
                + $"registered=[{string.Join(",", client.Registered.Select(d => d.Length))}], "
                + $"requested=[{string.Join(",", client.Requests.Select(r => r.Length))}], "
                + $"offsets=[{string.Join(",", client.Requests.Select(r => r.Offset))}]");
            CollectionAssert.AreEqual(expectedLengths, client.Registered.Select(d => d.Length).ToArray());
            CollectionAssert.AreEqual(expectedLengths, client.Requests.Select(r => r.Length).ToArray());
            CollectionAssert.AreEqual(expectedLengths, client.Descriptors.Select(d => d.Length).ToArray());
            CollectionAssert.AreEqual(expectedLengths, client.MemoryReads.ToArray());
            ulong offset = 0;
            foreach (var request in client.Requests)
            {
                Assert.AreEqual(offset, request.Offset);
                Assert.AreEqual(Channel_Values.CHANNEL_RDMA_V1, request.Channel);
                offset += request.Length;
            }
            Assert.AreEqual((ulong)total, offset);
        }

        [DataTestMethod]
        [DataRow(0u, 65536u)]
        [DataRow(65536u, 0u)]
        public void AlternativeChannelRead_ZeroLimitFailsBeforeRegistration(uint rdmaLimit, uint smb2Limit)
        {
            var test = InitializeMultichannel(Properties());
            var client = new RdmaReadClient(new byte[1]) { Smb2MaxReadSize = smb2Limit };
            SetConnection(client, new SmbdConnection { MaxReadWriteSize = rdmaLimit });
            Set(test, "alternativeChannelClient", client);
            Assert.ThrowsExactly<AssertFailedException>(() =>
                Invoke(test, "ReadFileFromAlternativeChannel", new byte[1], 1u));
            Assert.AreEqual(0, client.Registered.Count);
            Assert.AreEqual(0, client.Requests.Count);
        }

        [DataTestMethod]
        [DataRow(0ul, 16u, false)]
        [DataRow(5ul, 3u, false)]
        [DataRow(0ul, 16u, true)]
        public void ReadRangeOverRdma_SuccessReturnsRegisteredContent(ulong offset, uint length, bool zeroContent)
        {
            byte[] content = Enumerable.Range(1, 16).Select(i => zeroContent ? (byte)0 : (byte)i).ToArray();
            var client = new RdmaReadClient(content);
            var test = new SmbdProtocolGaps();
            Configure(test, Properties());
            Set(Get(test, "smbdAdapter"), "client", client);

            var result = (byte[])typeof(SmbdProtocolGaps).GetMethod(
                "ReadRangeOverRdma", BindingFlags.Instance | BindingFlags.NonPublic)
                .Invoke(test, new object[] { offset, length });

            CollectionAssert.AreEqual(content.Skip((int)offset).Take((int)length).ToArray(), result);
            CollectionAssert.AreEqual(new[] { length }, client.MemoryReads.ToArray());
            Assert.AreEqual(offset, client.Requests.Single().Offset);
        }

        [DataTestMethod]
        [DataRow(0ul, NtStatus.STATUS_CONNECTION_DISCONNECTED)]
        [DataRow(8ul, NtStatus.STATUS_INVALID_PARAMETER_2)]
        [DataRow(8ul, NtStatus.STATUS_INTERNAL_ERROR)]
        public void ReadRangeOverRdma_FailedMemoryReadRejectsUntouchedBuffer(ulong offset, NtStatus status)
        {
            var client = new RdmaReadClient(new byte[16]) { MemoryReadStatus = status };
            var test = new SmbdProtocolGaps();
            Configure(test, Properties());
            Set(Get(test, "smbdAdapter"), "client", client);

            var failure = Assert.ThrowsExactly<AssertFailedException>(() =>
                Invoke(test, "ReadRangeOverRdma", offset, 8u));

            StringAssert.Contains(failure.Message, status.ToString());
            CollectionAssert.AreEqual(new[] { 8u }, client.MemoryReads.ToArray());
            CollectionAssert.AreEqual(new byte[8], client.LastMemoryReadBuffer);
            Assert.AreEqual(offset, client.Requests.Single().Offset);
        }

        [DataTestMethod]
        [DataRow(DialectRevision.Smb30, false, true)]
        [DataRow(DialectRevision.Smb302, false, true)]
        [DataRow(DialectRevision.Smb311, false, true)]
        [DataRow(DialectRevision.Smb30, true, false)]
        [DataRow(DialectRevision.Smb302, true, false)]
        [DataRow(DialectRevision.Smb311, true, true)]
        public void RdmaWriteInitialization_BaselineKeepsLegacyDialectsWhileTransformsRequire311(
            DialectRevision supportedDialect, bool transformSpecific, bool compatible)
        {
            var test = new Smb2OverRdmaChannel();
            Configure(test, Properties(), (method, args) =>
            {
                if (args.OfType<string>().Any(s => s.Contains("The select DialectRevsion")))
                {
                    throw new BoundaryReachedException();
                }
            });
            var client = new RdmaNegotiationClient(supportedDialect);
            Set(Get(test, "smbdAdapter"), "client", client);
            Action run = transformSpecific
                ? test.Smb2OverRdmaChannel_ReadWriteMultipleBufferDescriptorList
                : test.BVT_Smb2OverRdmaChannel_WriteLargeFile;
            if (compatible)
            {
                Assert.ThrowsExactly<BoundaryReachedException>(run);
                Assert.AreEqual(supportedDialect, client.SelectedDialect);
            }
            else
            {
                Assert.ThrowsExactly<AssertFailedException>(run);
                Assert.AreEqual(DialectRevision.Smb2Unknown, client.SelectedDialect);
            }
            var expectedDialects = transformSpecific
                ? new[] { DialectRevision.Smb311 }
                : new[] { DialectRevision.Smb30, DialectRevision.Smb302, DialectRevision.Smb311 };
            CollectionAssert.AreEqual(expectedDialects, client.Request.Dialects);
            CollectionAssert.AreEqual(
                new[] { Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_SIGNING },
                client.Request.NegotiateContext_RDMA.Value.RDMATransformIds);
            TestContext.WriteLine(
                $"transformSpecific={transformSpecific}, server={supportedDialect}, "
                + $"offered=[{string.Join(",", client.Request.Dialects)}], selected={client.SelectedDialect}");
        }

        [DataTestMethod]
        [DataRow(8192u, 65536u, 65536u, 65536u, 8192u)]
        [DataRow(65536u, 8192u, 65536u, 65536u, 8192u)]
        [DataRow(65536u, 65536u, 8192u, 65536u, 8192u)]
        [DataRow(65536u, 65536u, 65536u, 8192u, 8192u)]
        [DataRow(65536u, 65536u, 65536u, 65536u, 65536u)]
        public void InvalidationWrite_PositiveRequestBoundsRegistrationDescriptorAndRemainingBytes(
            uint configured, uint maxRead, uint maxWrite, uint maxRdma, uint expected)
        {
            var properties = Properties();
            properties["RdmaChannelDataSizeInByte"] = configured.ToString();
            properties["DriverPlatform"] = "NonWindows";
            var test = new InvalidationWriteScenario();
            Configure(test, properties);
            var client = new RdmaWriteClient { Smb2MaxReadSize = maxRead, Smb2MaxWriteSize = maxWrite };
            SetConnection(client, new SmbdConnection { MaxReadWriteSize = maxRdma });
            client.ServerConnection.MaxReadWriteSize = maxRdma;
            Set(Get(test, "smbdAdapter"), "client", client);

            Assert.ThrowsExactly<BoundaryReachedException>(
                test.BVT_Smb2OverRdma_Smb302_Write_SMB2_CHANNEL_RDMA_V1_INVALIDATE);
            Assert.AreEqual(expected, client.Registered.Length);
            Assert.AreEqual(expected, client.MemoryWriteLength);
            Assert.AreEqual(expected, client.Descriptor.Length);
            Assert.AreEqual(expected, client.Request.RemainingBytes);
            Assert.AreEqual(0u, client.Request.Length);
            Assert.AreEqual(Channel_Values.CHANNEL_RDMA_V1_INVALIDATE, client.Request.Channel);
            TestContext.WriteLine(
                $"configured={configured}, SMB2read={maxRead}, SMB2write={maxWrite}, SMBD={maxRdma}, "
                + $"registered={client.Registered.Length}, memoryWrite={client.MemoryWriteLength}, "
                + $"descriptor={client.Descriptor.Length}, RemainingBytes={client.Request.RemainingBytes}");
        }

        [DataTestMethod]
        [DataRow(0u, 65536u, 65536u, 65536u)]
        [DataRow(65536u, 0u, 65536u, 65536u)]
        [DataRow(65536u, 65536u, 0u, 65536u)]
        [DataRow(65536u, 65536u, 65536u, 0u)]
        public void InvalidationWrite_ZeroSizeFailsBeforeRegistration(
            uint configured, uint maxRead, uint maxWrite, uint maxRdma)
        {
            var properties = Properties();
            properties["RdmaChannelDataSizeInByte"] = configured.ToString();
            properties["DriverPlatform"] = "NonWindows";
            var test = new InvalidationWriteScenario();
            Configure(test, properties);
            var client = new RdmaWriteClient { Smb2MaxReadSize = maxRead, Smb2MaxWriteSize = maxWrite };
            SetConnection(client, new SmbdConnection { MaxReadWriteSize = maxRdma });
            client.ServerConnection.MaxReadWriteSize = maxRdma;
            Set(Get(test, "smbdAdapter"), "client", client);
            if (configured == 0)
            {
                Assert.ThrowsExactly<ArgumentOutOfRangeException>(
                    test.BVT_Smb2OverRdma_Smb302_Write_SMB2_CHANNEL_RDMA_V1_INVALIDATE);
            }
            else
            {
                Assert.ThrowsExactly<InvalidOperationException>(
                    test.BVT_Smb2OverRdma_Smb302_Write_SMB2_CHANNEL_RDMA_V1_INVALIDATE);
            }
            Assert.AreEqual(0, client.RegistrationCount);
            Assert.AreEqual(0, client.MemoryWriteCount);
            Assert.AreEqual(0, client.WriteRequestCount);
        }

        public static IEnumerable<object[]> PositiveRdmaCases()
        {
            var limits = new uint[][]
            {
                new uint[] { 8192, 65536, 65536, 65536, 8192 },
                new uint[] { 1048576, 8192, 65536, 65536, 8192 },
                new uint[] { 1048576, 65536, 8192, 65536, 8192 },
                new uint[] { 1048576, 65536, 65536, 8192, 8192 },
                new uint[] { 65536, 65536, 65536, 65536, 65536 }
            };
            foreach (string entry in PositiveRdmaEntries)
            {
                foreach (uint[] limit in limits)
                {
                    yield return new object[] { entry, DialectRevision.Smb311, false,
                        limit[0], limit[1], limit[2], limit[3], limit[4] };
                }
            }
            foreach (var dialect in new[] { DialectRevision.Smb30, DialectRevision.Smb302, DialectRevision.Smb311 })
            {
                yield return new object[] { "plain-read", dialect, true, 8192u, 65536u, 65536u, 65536u, 8192u };
            }
        }

        private static readonly string[] PositiveRdmaEntries =
            { "invalidate-write", "invalidate-read", "plain-write", "plain-read" };

        [DataTestMethod]
        [DynamicData(nameof(PositiveRdmaCases), DynamicDataSourceType.Method)]
        public void PositiveRdmaGroup_BoundsActualEntryPacketsAndPreservesDialectFallback(
            string entry, DialectRevision serverDialect, bool selectSigning,
            uint configured, uint maxRead, uint maxWrite, uint maxRdma, uint expected)
        {
            var (test, client) = PositiveRdmaScenario(
                entry, serverDialect, selectSigning, configured, maxRead, maxWrite, maxRdma);
            Action run = PositiveRdmaEntry(test, entry);
            if (entry.StartsWith("invalidate", StringComparison.Ordinal))
            {
                Assert.ThrowsExactly<BoundaryReachedException>(run);
            }
            else
            {
                run();
            }

            Assert.AreEqual(entry == "plain-read" ? serverDialect : DialectRevision.Smb302, client.SelectedDialect);
            CollectionAssert.AreEqual(entry == "plain-read"
                ? new[] { DialectRevision.Smb30, DialectRevision.Smb302, DialectRevision.Smb311 }
                : new[] { DialectRevision.Smb302 }, client.Request.Dialects);
            Assert.AreEqual(expected, (uint)client.FileContent.Length, "The actual seeded file must be bounded.");
            Assert.IsTrue(client.ReadRequests.Count > 0);
            Assert.AreEqual(entry == "plain-read" ? 2 : entry == "plain-write" ? 2 : 1, client.MemoryReads.Count);
            foreach (var read in client.ReadRequests)
            {
                Assert.IsTrue(read.Length > 0 && read.Length <= expected);
                Assert.AreEqual(entry == "invalidate-read"
                    ? Channel_Values.CHANNEL_RDMA_V1_INVALIDATE : Channel_Values.CHANNEL_RDMA_V1, read.Channel);
            }
            Assert.AreEqual(client.ReadRequests.Count, client.ReadDescriptors.Count);
            for (int i = 0; i < client.ReadRequests.Count; i++)
            {
                Assert.IsTrue(client.ReadDescriptors[i].Length >= client.ReadRequests[i].Length);
                if (entry.EndsWith("read", StringComparison.Ordinal))
                {
                    Assert.AreEqual(client.ReadRequests[i].Length, client.ReadDescriptors[i].Length);
                }
            }
            CollectionAssert.AreEqual(client.ReadRequests.Select(r => r.Length).ToArray(),
                client.MemoryReads.ToArray());
            if (entry == "invalidate-read")
            {
                Assert.IsTrue(client.Writes.All(w => w.Channel == Channel_Values.CHANNEL_NONE));
                Assert.AreEqual(expected, client.Writes.Aggregate(0u, (sum, w) => sum + w.Length));
                Assert.IsTrue(client.Writes.All(w => w.Length > 0 &&
                    w.Length <= maxWrite - Smb2OverSmbdTestClient.WRITE_REQUEST_HEADER_SIZE));
            }
            else
            {
                Assert.AreEqual(entry == "plain-write" ? 2 : 1, client.Writes.Count);
                Assert.AreEqual(client.Writes.Count, client.MemoryWrites.Count);
                Assert.AreEqual(client.Writes.Count, client.WriteDescriptors.Count);
                Assert.IsTrue(client.MemoryWrites.All(n => n == expected));
                Assert.IsTrue(client.WriteDescriptors.All(d => d.Length == expected));
                foreach (var write in client.Writes)
                {
                    Assert.AreEqual(expected, write.RemainingBytes);
                    Assert.AreEqual(0u, write.Length);
                    Assert.AreEqual(entry == "invalidate-write" ? Channel_Values.CHANNEL_RDMA_V1_INVALIDATE
                        : entry == "plain-read" && selectSigning && serverDialect == DialectRevision.Smb311
                            ? Channel_Values.CHANNEL_RDMA_TRANSFORM : Channel_Values.CHANNEL_RDMA_V1, write.Channel);
                }
            }
            Assert.IsTrue(client.Registered.All(d => d.Length > 0 && d.Length <= Math.Min(maxRead, maxRdma)));
            if (entry == "plain-read")
            {
                CollectionAssert.AreEqual(new[] { Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_SIGNING },
                    client.Request.NegotiateContext_RDMA.Value.RDMATransformIds);
                Assert.AreEqual(selectSigning && serverDialect == DialectRevision.Smb311,
                    client.SelectedRdmaTransformIds.Contains(Smb2RDMATransformId.SMB2_RDMA_TRANSFORM_SIGNING));
                Assert.AreEqual(client.ReadDescriptors[0], client.ReadDescriptors[1], "The normal READ descriptor remains reusable.");
            }
            if (entry == "plain-write")
            {
                Assert.AreEqual(client.WriteDescriptors[0], client.WriteDescriptors[1], "The normal WRITE descriptor remains reusable.");
            }
            TestContext.WriteLine(
                $"entry={entry}, server={serverDialect}, signing={selectSigning}, configured={configured}, "
                + $"SMB2read={maxRead}, SMB2write={maxWrite}, conservativeSMBDcap={maxRdma}, file={client.FileContent.Length}, "
                + $"registered=[{string.Join(",", client.Registered.Select(d => d.Length))}], "
                + $"WRITEremaining=[{string.Join(",", client.Writes.Select(w => w.RemainingBytes))}], "
                + $"READlength=[{string.Join(",", client.ReadRequests.Select(r => r.Length))}]");
        }

        public static IEnumerable<object[]> PositiveRdmaZeroCases()
        {
            foreach (string entry in PositiveRdmaEntries)
            {
                for (int zero = 0; zero < 4; zero++)
                {
                    yield return new object[] { entry, zero };
                }
            }
        }

        [DataTestMethod]
        [DynamicData(nameof(PositiveRdmaZeroCases), DynamicDataSourceType.Method)]
        public void PositiveRdmaGroup_ZeroPreconditionsStopBeforeRegistrationCopyOrDataRequest(string entry, int zero)
        {
            uint[] limits = { 65536, 65536, 65536, 65536 };
            limits[zero] = 0;
            var (test, client) = PositiveRdmaScenario(entry, DialectRevision.Smb311, false,
                limits[0], limits[1], limits[2], limits[3]);
            Action run = PositiveRdmaEntry(test, entry);
            if (zero == 0)
            {
                Assert.ThrowsExactly<ArgumentOutOfRangeException>(run);
            }
            else
            {
                Assert.ThrowsExactly<InvalidOperationException>(run);
            }
            Assert.AreEqual(0, client.Registered.Count);
            Assert.AreEqual(0, client.MemoryWrites.Count);
            Assert.AreEqual(0, client.MemoryReads.Count);
            Assert.AreEqual(0, client.Writes.Count);
            Assert.AreEqual(0, client.ReadRequests.Count);
            Assert.AreEqual(0, client.FileContent.Length);
        }

        private static (Smb2OverRdmaChannelRemoteInvalidation Test, PositiveRdmaClient Client) PositiveRdmaScenario(
            string entry, DialectRevision serverDialect, bool selectSigning,
            uint configured, uint maxRead, uint maxWrite, uint maxRdma)
        {
            var properties = Properties();
            properties["RdmaChannelDataSizeInByte"] = configured.ToString();
            properties["DriverPlatform"] = "NonWindows";
            var test = new Smb2OverRdmaChannelRemoteInvalidation();
            Configure(test, properties);
            Set(test, "fileName", "positive-rdma.bin");
            var client = new PositiveRdmaClient(entry == "plain-read" ? serverDialect : DialectRevision.Smb302)
            {
                SelectSigning = selectSigning,
                Smb2MaxReadSize = maxRead,
                Smb2MaxWriteSize = maxWrite,
                StopAfterReadCopy = entry.StartsWith("invalidate", StringComparison.Ordinal)
            };
            SetConnection(client, new SmbdConnection { MaxReadWriteSize = maxRdma, MaxSendSize = 65536 });
            client.ServerConnection.MaxReadWriteSize = maxRdma;
            client.ServerConnection.MaxReceiveSize = 65536;
            Set(Get(test, "smbdAdapter"), "client", client);
            return (test, client);
        }

        [DataTestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public void FragmentedRead_InterimDoesNotBecomeFinalOrCountTowardFinalFragments(bool fragmentInterim)
        {
            var messages = FragmentedReadMessages(fragmentInterim, true);
            var (test, client) = FragmentedReadScenario(messages);

            Invoke(test, "ValidateFragmentedReadResponse", 256u, 200u, 9ul, TimeSpan.FromSeconds(1));

            Assert.AreEqual(messages.Count, client.Received);
            Assert.AreEqual((ushort)12, client.Smb2AvailableCredits);
            Assert.IsTrue(client.ReceiveTimeouts.All(t => t > TimeSpan.Zero && t <= TimeSpan.FromSeconds(1)));
        }

        [TestMethod]
        public void FragmentedRead_SynchronousFinalKeepsSingleFinalCreditGrant()
        {
            var response = ReadResponse();
            response.Header.MessageId = 9;
            response.Header.CreditRequestResponse = 3;
            response.Buffer = new byte[256];
            response.PayLoad.DataLength = 256;
            byte[] bytes = response.ToBytes();
            var messages = new[]
            {
                Transfer(bytes.Take(168).ToArray(), (uint)bytes.Length - 168, 1),
                Transfer(bytes.Skip(168).ToArray(), 0, 1)
            };
            var (test, client) = FragmentedReadScenario(messages);

            Invoke(test, "ValidateFragmentedReadResponse", 256u, 200u, 9ul, TimeSpan.FromSeconds(1));

            Assert.AreEqual((ushort)10, client.Smb2AvailableCredits);
            Assert.AreEqual(0ul, (ulong)Get(client, "messageId"));
        }

        [TestMethod]
        public void FragmentedRead_FragmentedInterimCannotSatisfyFinalFragmentationOracle()
        {
            var (test, _) = FragmentedReadScenario(FragmentedReadMessages(true, false));
            var failure = Assert.ThrowsExactly<AssertFailedException>(() =>
                Invoke(test, "ValidateFragmentedReadResponse", 256u, 512u, 9ul, TimeSpan.FromSeconds(1)));
            StringAssert.Contains(failure.Message, "at least 2");
        }

        [TestMethod]
        public void FragmentedRead_MalformedRemainingIsRejectedWithinCurrentUpperLayerMessage()
        {
            var messages = FragmentedReadMessages(false, true);
            var last = messages.Last();
            last.RemainingDataLength = 1;
            messages[messages.Count - 1] = last;
            var (test, _) = FragmentedReadScenario(messages);
            Assert.ThrowsExactly<AssertFailedException>(() =>
                Invoke(test, "ValidateFragmentedReadResponse", 256u, 200u, 9ul, TimeSpan.FromSeconds(1)));
        }

        [DataTestMethod]
        [DataRow(255)]
        [DataRow(257)]
        public void FragmentedRead_WrongFinalSizeIsNotHiddenByInterim(int length)
        {
            var (test, _) = FragmentedReadScenario(FragmentedReadMessages(false, true, length));
            var failure = Assert.ThrowsExactly<AssertFailedException>(() =>
                Invoke(test, "ValidateFragmentedReadResponse", 256u, 200u, 9ul, TimeSpan.FromSeconds(1)));
            StringAssert.Contains(failure.Message, "Total final READ response bytes");
        }

        [TestMethod]
        public void FragmentedRead_FinalStatusIsCheckedBeforeSuccessfulReadLength()
        {
            var messages = new List<SmbdDataTransferMessage>
            {
                Transfer(AsyncReadError(NtStatus.STATUS_PENDING, 5), 0, 1),
                Transfer(AsyncReadError(NtStatus.STATUS_ACCESS_DENIED, 0), 0, 1)
            };
            var (test, client) = FragmentedReadScenario(messages);
            var failure = Assert.ThrowsExactly<AssertFailedException>(() =>
                Invoke(test, "ValidateFragmentedReadResponse", 256u, 200u, 9ul, TimeSpan.FromSeconds(1)));
            StringAssert.Contains(failure.Message, "STATUS_ACCESS_DENIED");
            Assert.AreEqual((ushort)12, client.Smb2AvailableCredits);
        }

        [TestMethod]
        public void FragmentedRead_MissingFinalKeepsBoundedReceiveBudget()
        {
            var messages = new[] { Transfer(AsyncReadError(NtStatus.STATUS_PENDING, 5), 0, 1) };
            var (test, client) = FragmentedReadScenario(messages);
            client.TimeoutWhenExhausted = true;
            client.ClientConnection.ReceiveCredits = 2;
            Assert.ThrowsExactly<TimeoutException>(() =>
                Invoke(test, "ValidateFragmentedReadResponse", 256u, 200u, 9ul, TimeSpan.FromMilliseconds(100)));
            Assert.AreEqual(2, client.Received);
            Assert.IsTrue(client.ReceiveTimeouts.All(t => t > TimeSpan.Zero && t <= TimeSpan.FromMilliseconds(100)));
        }

        private static (SmbdProtocolGaps, CreditClient) FragmentedReadScenario(
            IEnumerable<SmbdDataTransferMessage> messages)
        {
            var test = new SmbdProtocolGaps();
            Configure(test, Properties());
            var client = new CreditClient(messages) { Smb2AvailableCredits = 7 };
            SetConnection(client, new SmbdConnection
            {
                ReceiveCredits = (uint)messages.Count(),
                MaxFragmentedSize = 4096,
                MaxReceiveSize = 200
            });
            Set(Get(test, "smbdAdapter"), "client", client);
            return (test, client);
        }

        private static Action PositiveRdmaEntry(Smb2OverRdmaChannelRemoteInvalidation test, string entry) => entry switch
        {
            "invalidate-write" => test.BVT_Smb2OverRdma_Smb302_Write_SMB2_CHANNEL_RDMA_V1_INVALIDATE,
            "invalidate-read" => test.BVT_Smb2OverRdma_Smb302_Read_SMB2_CHANNEL_RDMA_V1_INVALIDATE,
            "plain-write" => test.Smb2OverRdma_Write_SMB2_CHANNEL_RDMA_V1,
            "plain-read" => test.Smb2OverRdma_Read_SMB2_CHANNEL_RDMA_V1,
            _ => throw new ArgumentOutOfRangeException(nameof(entry))
        };

        [DataTestMethod]
        [DataRow(2048u, 8192u, 2048u)]
        [DataRow(8192u, 1024u, 1024u)]
        [DataRow(8192u, 8192u, 4096u)]
        [DataRow(1u, 8192u, 1u)]
        public void TransformEdgeRead_UsesEffectiveOperationLimit(
            uint rdmaLimit, uint readLimit, uint expected)
        {
            var client = new RdmaReadClient(Array.Empty<byte>())
            {
                Smb2MaxReadSize = readLimit,
                Smb2MaxWriteSize = 1,
                ReportTransferredLength = true
            };
            var test = InitializeTransformEdge(client, rdmaLimit);
            Invoke(test, "ReadOnce", new object[] { null });
            Invoke(test, "ReadOnce", new object[] { null });

            TestContext.WriteLine($"SMBD={rdmaLimit}, SMB2 READ={readLimit}, expected={expected}");
            CollectionAssert.AreEqual(new[] { expected, expected },
                client.Registered.Select(d => d.Length).ToArray());
            CollectionAssert.AreEqual(new[] { expected, expected },
                client.Requests.Select(r => r.Length).ToArray());
            CollectionAssert.AreEqual(new[] { expected, expected },
                client.Descriptors.Select(d => d.Length).ToArray());
            Assert.IsTrue(client.Requests.All(r => r.Channel == Channel_Values.CHANNEL_RDMA_V1));
        }

        [DataTestMethod]
        [DataRow(2048u, 8192u, 2048u, false)]
        [DataRow(2048u, 8192u, 2048u, true)]
        [DataRow(8192u, 1024u, 1024u, false)]
        [DataRow(8192u, 1024u, 1024u, true)]
        [DataRow(8192u, 8192u, 4096u, false)]
        [DataRow(8192u, 8192u, 4096u, true)]
        [DataRow(1u, 8192u, 1u, false)]
        [DataRow(1u, 8192u, 1u, true)]
        public void TransformEdgeWrite_UsesEffectiveOperationLimitBeforeNativeMemory(
            uint rdmaLimit, uint writeLimit, uint expected, bool encrypt)
        {
            var client = new TransformWriteProbeClient
            {
                Smb2MaxReadSize = 1,
                Smb2MaxWriteSize = writeLimit
            };
            var test = InitializeTransformEdge(client, rdmaLimit);
            Assert.ThrowsExactly<RegistrationReachedException>(() =>
                Invoke(test, "SendTransformWrite", (Smb2RDMATransformType)0x00FF, encrypt, 0));

            TestContext.WriteLine(
                $"SMBD={rdmaLimit}, SMB2 WRITE={writeLimit}, encrypted={encrypt}, registration={client.RegisteredLength}");
            Assert.AreEqual(expected, client.RegisteredLength);
            Assert.AreEqual(SmbdBufferReadWrite.RDMA_READ_PERMISSION_FOR_WRITE_FILE, client.Permission);
        }

        [DataTestMethod]
        [DataRow("ReadOnce", 0u, 8192u)]
        [DataRow("ReadOnce", 8192u, 0u)]
        [DataRow("SendTransformWrite", 0u, 8192u)]
        [DataRow("SendTransformWrite", 8192u, 0u)]
        public void TransformEdge_ZeroCapacityFailsBeforeRegistration(
            string method, uint rdmaLimit, uint smb2Limit)
        {
            var client = new TransformWriteProbeClient
            {
                Smb2MaxReadSize = smb2Limit,
                Smb2MaxWriteSize = smb2Limit
            };
            var test = InitializeTransformEdge(client, rdmaLimit);
            object[] arguments = method == "ReadOnce"
                ? new object[] { null }
                : new object[] { (Smb2RDMATransformType)0x00FF, false, 0 };
            Assert.ThrowsExactly<AssertFailedException>(() => Invoke(test, method, arguments));
            Assert.IsNull(client.RegisteredLength);
        }

        private static Smb2OverRdmaTransformEdge InitializeTransformEdge(
            Smb2OverSmbdTestClient client, uint rdmaLimit)
        {
            var properties = Properties();
            properties["RdmaChannelDataSizeInByte"] = "0";
            var test = new Smb2OverRdmaTransformEdge();
            Configure(test, properties);
            SetConnection(client, new SmbdConnection { MaxReadWriteSize = rdmaLimit });
            Set((SmbdAdapter)Get(test, "smbdAdapter"), "client", client);
            return test;
        }

        [DataTestMethod]
        [DataRow(131072u, 262144u, 131072u, (ushort)2)]
        [DataRow(262144u, 131072u, 131072u, (ushort)2)]
        [DataRow(32768u, 16384u, 16384u, (ushort)1)]
        [DataRow(65536u, 65536u, 65536u, (ushort)1)]
        [DataRow(65537u, 262144u, 65537u, (ushort)2)]
        [DataRow(1u, 65536u, 1u, (ushort)1)]
        [DataRow(uint.MaxValue, 65536u, 65536u, (ushort)1)]
        public void MultichannelRawQuery_BoundsRequestAndAccountsOnce(
            uint configured, uint negotiated, uint expected, ushort charge)
        {
            var client = new CapturingClient
            {
                QueryNetworkInterfaceMaxOutputResponse = configured,
                Smb2MaxTransactSize = negotiated,
                Smb2AvailableCredits = 64
            };
            InvokeMultichannelRawQuery(client, out _, out _, out _, out _);
            var request = TypeMarshal.ToStruct<IOCTL_Request>(client.Sent.Skip(64).ToArray());
            var header = TypeMarshal.ToStruct<Packet_Header>(client.Sent);
            Assert.AreEqual(expected, request.MaxOutputResponse);
            Assert.AreEqual(charge, header.CreditCharge);
            Assert.AreEqual(CtlCode_Values.FSCTL_QUERY_NETWORK_INTERFACE_INFO, request.CtlCode);
            Assert.AreEqual(Packet_Header_Flags_Values.FLAGS_SIGNED, header.Flags);
            Assert.AreEqual(ulong.MaxValue, request.FileId.Persistent);
            Assert.AreEqual(ulong.MaxValue, request.FileId.Volatile);
            Assert.AreEqual((ushort)(65 - charge), client.Smb2AvailableCredits);
            Assert.AreEqual((ulong)charge, (ulong)Get(client, "messageId"));
            Assert.AreEqual(1, client.Packets.Count);
            TestContext.WriteLine($"configured={configured}, negotiated={negotiated}, encoded={request.MaxOutputResponse}, charge={header.CreditCharge}");
        }

        [DataTestMethod]
        [DataRow((uint)NtStatus.STATUS_SUCCESS)]
        [DataRow((uint)NtStatus.STATUS_NOT_SUPPORTED)]
        public void MultichannelRawQuery_PreservesRawResponseOnSuccessOrError(uint status)
        {
            byte[] input = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            byte[] output = InterfaceOutput();
            var client = new CapturingClient
            {
                IoctlStatus = status,
                ResponseInput = input,
                ResponseOutput = output,
                Smb2AvailableCredits = 64
            };
            uint actual = InvokeMultichannelRawQuery(client,
                out byte[] actualInput, out byte[] actualOutput, out Packet_Header header, out IOCTL_Response ioctl);
            Assert.AreEqual(status, actual);
            Assert.AreEqual(status, header.Status);
            Assert.AreEqual(Smb2Command.IOCTL, header.Command);
            Assert.AreEqual((uint)CtlCode_Values.FSCTL_QUERY_NETWORK_INTERFACE_INFO, ioctl.CtlCode);
            Assert.AreEqual((uint)input.Length, ioctl.InputCount);
            Assert.AreEqual((uint)output.Length, ioctl.OutputCount);
            Assert.AreEqual(ioctl.InputOffset + ioctl.InputCount, ioctl.OutputOffset);
            CollectionAssert.AreEqual(input, actualInput);
            CollectionAssert.AreEqual(output, actualOutput);
        }

        [TestMethod]
        public void MultichannelRawQuery_ZeroConfiguredSizeFailsBeforeSending()
        {
            var client = new CapturingClient { QueryNetworkInterfaceMaxOutputResponse = 0 };
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
                InvokeMultichannelRawQuery(client, out _, out _, out _, out _));
            Assert.AreEqual(0, client.Packets.Count);
            Assert.AreEqual(0ul, (ulong)Get(client, "messageId"));
        }

        [DataTestMethod]
        [DataRow(65536u, 0u)]
        [DataRow(uint.MaxValue, uint.MaxValue)]
        public void MultichannelRawQuery_InvalidEffectiveSizeFailsBeforeSending(uint configured, uint negotiated)
        {
            var client = new CapturingClient
            {
                QueryNetworkInterfaceMaxOutputResponse = configured,
                Smb2MaxTransactSize = negotiated
            };
            Assert.ThrowsExactly<InvalidOperationException>(() =>
                InvokeMultichannelRawQuery(client, out _, out _, out _, out _));
            Assert.AreEqual(0, client.Packets.Count);
            Assert.AreEqual((ushort)1, client.Smb2AvailableCredits);
        }

        [TestMethod]
        public void MultichannelRawQuery_RefillsBeforeSelectingMessageId()
        {
            var client = new CapturingClient
            {
                QueryNetworkInterfaceMaxOutputResponse = 131072,
                Smb2MaxTransactSize = 262144,
                Smb2AvailableCredits = 1,
                EchoCreditGrant = 4
            };
            InvokeMultichannelRawQuery(client, out _, out _, out _, out _);
            var headers = client.Packets.Select(p => TypeMarshal.ToStruct<Packet_Header>(p)).ToArray();
            CollectionAssert.AreEqual(new[] { Smb2Command.ECHO, Smb2Command.IOCTL },
                headers.Select(h => h.Command).ToArray());
            CollectionAssert.AreEqual(new ulong[] { 0, 1 }, headers.Select(h => h.MessageId).ToArray());
            CollectionAssert.AreEqual(new ushort[] { 1, 2 }, headers.Select(h => h.CreditCharge).ToArray());
            Assert.AreEqual(3ul, (ulong)Get(client, "messageId"));
            Assert.AreEqual((ushort)3, client.Smb2AvailableCredits);
            CollectionAssert.AreEqual(new ulong[] { 0, 1 }, client.ExpectedMessageIds.ToArray());
        }

        [TestMethod]
        public void MultichannelRawQuery_DeniedCreditsNeverSendsIoctl()
        {
            var client = new CapturingClient
            {
                QueryNetworkInterfaceMaxOutputResponse = 131072,
                Smb2MaxTransactSize = 262144,
                Smb2AvailableCredits = 1,
                EchoCreditGrant = 1
            };
            Assert.ThrowsExactly<Exception>(() =>
                InvokeMultichannelRawQuery(client, out _, out _, out _, out _));
            Assert.AreEqual(1, client.Packets.Count);
            Assert.AreEqual(Smb2Command.ECHO, TypeMarshal.ToStruct<Packet_Header>(client.Sent).Command);
            Assert.AreEqual(1ul, (ulong)Get(client, "messageId"));
            Assert.AreEqual((ushort)1, client.Smb2AvailableCredits);
        }

        [TestMethod]
        public void MultichannelParsedQuery_UsesSameBoundsAndAccountsOnce()
        {
            var client = new CapturingClient
            {
                QueryNetworkInterfaceMaxOutputResponse = 262144,
                Smb2MaxTransactSize = 131072,
                Smb2AvailableCredits = 64,
                IoctlStatus = (uint)NtStatus.STATUS_SUCCESS,
                IoctlCreditGrant = 3,
                ResponseOutput = InterfaceOutput()
            };
            Assert.AreEqual((uint)NtStatus.STATUS_SUCCESS, client.Smb2QueryNetworkInterfaceInfo(out var interfaces));
            Assert.AreEqual(1, interfaces.Length);
            Assert.AreEqual(7u, interfaces[0].IfIndex);
            Assert.AreEqual(2ul, (ulong)Get(client, "messageId"));
            Assert.AreEqual((ushort)65, client.Smb2AvailableCredits);
            Assert.AreEqual(1, client.Packets.Count);
        }

        [TestMethod]
        public void MultichannelBindingRawAccounting_RemainsSingleCredit()
        {
            var client = new CapturingClient { Smb2AvailableCredits = 7 };
            typeof(Smb2MultiChannelGaps).GetMethod("AfterRawResponse", BindingFlags.Static | BindingFlags.NonPublic)
                .Invoke(null, new object[] { client, new Packet_Header { CreditRequestResponse = 3 } });
            Assert.AreEqual(1ul, (ulong)Get(client, "messageId"));
            Assert.AreEqual((ushort)9, client.Smb2AvailableCredits);
            Assert.AreEqual(0, client.Packets.Count);
        }

        private static uint InvokeMultichannelRawQuery(
            Smb2OverSmbdTestClient client,
            out byte[] input, out byte[] output, out Packet_Header header, out IOCTL_Response ioctl)
        {
            object[] arguments = { client, null, null, null, null };
            uint status;
            try
            {
                status = (uint)typeof(Smb2MultiChannelGaps)
                    .GetMethod("QueryNetworkInterfaceInfo", BindingFlags.Instance | BindingFlags.NonPublic)
                    .Invoke(new Smb2MultiChannelGaps(), arguments);
            }
            catch (TargetInvocationException ex) when (ex.InnerException != null)
            {
                ExceptionDispatchInfo.Capture(ex.InnerException).Throw();
                throw;
            }
            input = (byte[])arguments[1];
            output = (byte[])arguments[2];
            header = (Packet_Header)arguments[3];
            ioctl = (IOCTL_Response)arguments[4];
            return status;
        }

        private static byte[] InterfaceOutput()
        {
            byte[] address = new byte[128];
            address[0] = 2;
            address[4] = 192;
            address[6] = 2;
            address[7] = 1;
            return TypeMarshal.ToBytes(new NETWORK_INTERFACE_INFO_Response
            {
                IfIndex = 7,
                Capability = NETWORK_INTERFACE_INFO_Response_Capabilities.RDMA_CAPABLE,
                LinkSpeed = 1000000000,
                AddressStorage = TypeMarshal.ToStruct<NETWORK_INTERFACE_INFO_Response_SockAddr_Storage>(address)
            });
        }

        private static List<SmbdDataTransferMessage> FragmentedReadMessages(
            bool fragmentInterim, bool fragmentFinal, int finalLength = 256)
        {
            byte[] interim = AsyncReadError(NtStatus.STATUS_PENDING, 5);
            var response = ReadResponse();
            response.Header.MessageId = 9;
            response.Header.Flags |= Packet_Header_Flags_Values.FLAGS_ASYNC_COMMAND;
            response.Header.TreeId = 0x80000001;
            response.Header.ProcessId = 7;
            response.Header.CreditRequestResponse = 0;
            response.Buffer = new byte[finalLength];
            response.PayLoad.DataLength = (uint)finalLength;
            byte[] final = response.ToBytes();
            var messages = new List<SmbdDataTransferMessage>();
            foreach (var item in new[] { (interim, fragmentInterim), (final, fragmentFinal) })
            {
                if (item.Item2)
                {
                    int half = item.Item1.Length / 2;
                    messages.Add(Transfer(item.Item1.Take(half).ToArray(), (uint)item.Item1.Length - (uint)half, 1));
                    messages.Add(Transfer(item.Item1.Skip(half).ToArray(), 0, 1));
                }
                else
                {
                    messages.Add(Transfer(item.Item1, 0, 1));
                }
            }
            return messages;
        }

        private static byte[] AsyncReadError(NtStatus status, ushort grant)
        {
            var packet = new Smb2ErrorResponsePacket();
            packet.Header.Command = Smb2Command.READ;
            packet.Header.MessageId = 9;
            packet.Header.Status = (uint)status;
            packet.Header.Flags = Packet_Header_Flags_Values.FLAGS_SERVER_TO_REDIR | Packet_Header_Flags_Values.FLAGS_ASYNC_COMMAND;
            packet.Header.TreeId = 0x80000001;
            packet.Header.ProcessId = 7;
            packet.Header.CreditRequestResponse = grant;
            packet.PayLoad.StructureSize = 9;
            packet.PayLoad.ErrorData = new byte[1];
            packet.PayLoad.ByteCount = 1;
            return packet.ToBytes();
        }

        private static SmbdDataTransferMessage Transfer(byte[] buffer, uint remaining, ushort grant) =>
            new SmbdDataTransferMessage
            {
                CreditsRequested = 1,
                CreditsGranted = grant,
                DataOffset = buffer.Length == 0 ? 0u : (uint)SmbdDataTransferMessage.DEFAULT_DATA_OFFSET,
                DataLength = (uint)buffer.Length,
                RemainingDataLength = remaining,
                Buffer = buffer
            };

        private static Smb2ReadResponsePacket ReadResponse()
        {
            var response = new Smb2ReadResponsePacket();
            response.Header.Command = Smb2Command.READ;
            response.Header.Flags = Packet_Header_Flags_Values.FLAGS_SERVER_TO_REDIR;
            response.Header.CreditRequestResponse = 64;
            response.PayLoad.StructureSize = 17;
            response.PayLoad.DataOffset = (byte)Smb2OverSmbdTestClient.READ_RESPONSE_HEADER_SIZE;
            return response;
        }

        private static Smb2MultiChannelOverRdma InitializeMultichannel(NameValueCollection properties)
        {
            var test = new Smb2MultiChannelOverRdma();
            Configure(test, properties);
            Invoke(test, "TestInitialize");
            return test;
        }

        private static void Invoke(object target, string name, params object[] args)
        {
            try
            {
                target.GetType().GetMethod(name, BindingFlags.NonPublic | BindingFlags.Instance)
                    .Invoke(target, args);
            }
            catch (TargetInvocationException ex) when (ex.InnerException != null)
            {
                ExceptionDispatchInfo.Capture(ex.InnerException).Throw();
            }
        }

        private static void SetConnection(Smb2OverSmbdTestClient client, SmbdConnection connection) =>
            typeof(SmbdClient).GetProperty("Connection").SetValue(Get(client, "smbdClient"), connection);

        private static DetectorClient Detector(uint margin)
        {
            var client = (DetectorClient)RuntimeHelpers.GetUninitializedObject(typeof(DetectorClient));
            client.BufferSizeSafetyMargin = margin;
            Set(client, "negotiated", true);
            Set(client, "maxReadSize", 1048576u);
            Set(client, "maxWriteSize", 1048576u);
            return client;
        }

        private static void Configure(SmbdTestBase test, NameValueCollection properties,
            Action<MethodInfo, object[]> log = null)
        {
            var site = Site(properties, log);
            BaseSite.SetValue(null, site);
            typeof(SmbdTestBase).GetField("smbdAdapter", BindingFlags.Instance | BindingFlags.NonPublic)
                .SetValue(test, new SmbdAdapter(site));
            typeof(SmbdTestBase).GetField("fileNameList", BindingFlags.Instance | BindingFlags.NonPublic)
                .SetValue(test, new List<string>());
        }

        private static NameValueCollection Properties()
        {
            var result = new NameValueCollection();
            foreach (string path in Directory.GetFiles(AppContext.BaseDirectory, "*.ptfconfig"))
            {
                foreach (var p in XDocument.Load(path).Descendants().Where(e => e.Name.LocalName == "Property"))
                {
                    result[(string)p.Attribute("name")] = (string)p.Attribute("value");
                }
            }
            result["Platform"] = "NonWindows";
            // Hardware-free protocol fixtures must not start capture or contact a SUT.
            result["Diagnostics.Enabled"] = "false";
            result["SutLog.Enabled"] = "false";
            return result;
        }

        private static ITestSite Site(NameValueCollection properties, Action<MethodInfo, object[]> log = null)
        {
            var assert = CallbackProxy.Create<IChecker>((m, a) =>
            {
                Check(m.Name, a, false);
                return null;
            });
            var assume = CallbackProxy.Create<IChecker>((m, a) =>
            {
                Check(m.Name, a, true);
                return null;
            });
            return CallbackProxy.Create<ITestSite>((m, a) => m.Name switch
            {
                "get_Properties" => properties,
                "get_Assert" => assert,
                "get_Assume" => assume,
                "get_Log" => CallbackProxy.Create<ILogger>((method, args) =>
                {
                    log?.Invoke(method, args);
                    return null;
                }),
                "get_TestProperties" => new Dictionary<string, object>
                {
                    ["CurrentTestCaseName"] = typeof(Smb2MultiChannelOverRdma).FullName
                        + ".BVT_Smb2MultipleChannel_2Channels_DiffNicTypeDiffTransport"
                },
                _ => null
            });
        }

        private static void Check(string name, object[] args, bool assume)
        {
            bool failed = name switch
            {
                "IsTrue" => !(bool)args[0],
                "IsFalse" => (bool)args[0],
                "AreEqual" => !Equals(args[0], args[1]),
                "Fail" => true,
                "Inconclusive" => true,
                _ => throw new NotSupportedException("Unimplemented checker operation: " + name)
            };
            if (failed)
            {
                string message = name + ": " + string.Join(", ", args);
                if (assume || name == "Inconclusive")
                {
                    throw new AssertInconclusiveException(message);
                }
                throw new AssertFailedException(message);
            }
        }

        private static object Get(object target, string name)
        {
            for (Type type = target.GetType(); type != null; type = type.BaseType)
            {
                var field = type.GetField(name, BindingFlags.NonPublic | BindingFlags.Instance);
                if (field != null)
                {
                    return field.GetValue(target);
                }
            }
            throw new MissingFieldException(target.GetType().FullName, name);
        }

        private static void Set(object target, string name, object value) =>
            target.GetType().GetField(name, BindingFlags.NonPublic | BindingFlags.Instance).SetValue(target, value);

        private sealed class BoundaryReachedException : Exception { }

        private sealed class InvalidationWriteScenario : Smb2OverRdmaChannelRemoteInvalidation
        {
            protected override void EstablishConnectionAndOpenFile(
                string fileName, DialectRevision[] negotiatedDialects = null)
            {
                CollectionAssert.AreEqual(new[] { DialectRevision.Smb302 }, negotiatedDialects);
            }
        }

        private class RdmaNegotiationClient : Smb2OverSmbdTestClient
        {
            private readonly DialectRevision supportedDialect;
            public Smb2NegotiateRequestPacket Request { get; private set; }
            public DialectRevision SelectedDialect { get; private set; }
            public bool SelectSigning { get; set; } = true;
            public NEGOTIATE_Response_Capabilities_Values ResponseCapabilities { get; set; }
            public RdmaNegotiationClient(DialectRevision supportedDialect) : base(TimeSpan.Zero)
            {
                this.supportedDialect = supportedDialect;
                Smb2MaxReadSize = Smb2MaxWriteSize = 65536;
            }
            public override NtStatus ConnectToServerOverRDMA(
                string clientIp, string serverIp, int port, AddressFamily family,
                uint inbound, uint outbound, uint readLimit, uint dataSize, NdspiVersion version = NdspiVersion.NDv2) =>
                NtStatus.STATUS_SUCCESS;

            public override NtStatus SmbdNegotiate(
                SmbdVersion min, SmbdVersion max, ushort reserved, ushort requested, ushort receiveMax,
                uint preferred, uint receiveSize, uint fragmentedSize, out SmbdNegotiateResponse response)
            {
                response = new SmbdNegotiateResponse();
                return NtStatus.STATUS_SUCCESS;
            }
            public override void SendPacket(byte[] data)
            {
                var decoder = new Smb2Decoder(Smb2Role.Server, new Dictionary<ulong, Smb2CryptoInfo>());
                Request = (Smb2NegotiateRequestPacket)decoder.DecodeSinglePacket(
                    data, Smb2Role.Server, 0, 0, out _, out _);
            }
            public override T ExpectPacket<T>(ulong messageId)
            {
                bool compatible = Request.Dialects.Contains(supportedDialect);
                SelectedDialect = compatible ? supportedDialect : DialectRevision.Smb2Unknown;
                var response = new Smb2NegotiateResponsePacket { Buffer = Array.Empty<byte>() };
                response.Header.Status = compatible ? Smb2Status.STATUS_SUCCESS : Smb2Status.STATUS_NOT_SUPPORTED;
                response.Header.CreditRequestResponse = 64;
                response.PayLoad.DialectRevision = SelectedDialect;
                response.PayLoad.SecurityBufferOffset = response.BufferOffset;
                response.PayLoad.MaxReadSize = Smb2MaxReadSize;
                response.PayLoad.MaxWriteSize = Smb2MaxWriteSize;
                response.PayLoad.MaxTransactSize = 65536;
                response.PayLoad.Capabilities = ResponseCapabilities;
                if (compatible && supportedDialect == DialectRevision.Smb311)
                {
                    var preauth = new SMB2_PREAUTH_INTEGRITY_CAPABILITIES
                    {
                        HashAlgorithmCount = 1,
                        HashAlgorithms = new[] { PreauthIntegrityHashID.SHA_512 },
                        Salt = Array.Empty<byte>()
                    };
                    preauth.Header.ContextType = SMB2_NEGOTIATE_CONTEXT_Type_Values.SMB2_PREAUTH_INTEGRITY_CAPABILITIES;
                    preauth.Header.DataLength = (ushort)preauth.GetDataLength();
                    response.NegotiateContext_PREAUTH = preauth;
                    response.NegotiateContext_RDMA = SelectSigning ? Request.NegotiateContext_RDMA : null;
                    response.NegotiateContext_SIGNING = Request.NegotiateContext_SIGNING;
                }
                return (T)(object)response;
            }
        }

        private class PositiveRdmaClient : RdmaNegotiationClient
        {
            private readonly Dictionary<uint, byte[]> memory = new();
            private readonly Dictionary<uint, SmbdBufferReadWrite> permissions = new();
            private Smb2Command lastCommand;
            private uint nextToken;
            public byte[] FileContent { get; private set; } = Array.Empty<byte>();
            public bool StopAfterReadCopy { get; set; }
            public List<SmbdBufferDescriptorV1> Registered { get; } = new();
            public List<SmbdBufferDescriptorV1> WriteDescriptors { get; } = new();
            public List<SmbdBufferDescriptorV1> ReadDescriptors { get; } = new();
            public List<WRITE_Request> Writes { get; } = new();
            public List<READ_Request> ReadRequests { get; } = new();
            public List<uint> MemoryWrites { get; } = new();
            public List<uint> MemoryReads { get; } = new();
            public PositiveRdmaClient(DialectRevision dialect) : base(dialect) { }

            public override void ConnectOverTCP(IPAddress serverIp, IPAddress clientIp, ushort serverPort = 445) { }

            public override uint Smb2SessionSetup(SecurityPackageType package,
                string domain, string user, string password, string server,
                bool enableSigning = true, bool enableEncryption = false)
            {
                // Substitute authentication only; keys and preauth bytes are synthetic, never live identity data.
                cryptoInfoTable[0] = new Smb2CryptoInfo(SelectedDialect, new byte[16], enableSigning, false, false,
                    preauthIntegrityHashValue: new byte[64], signingId: SelectedSigningAlgorithm,
                    isSigningAlgorithmNegotiated: SelectedDialect == DialectRevision.Smb311);
                typeof(Smb2OverSmbdTestClient).GetField("sessionSigningEnabled", BindingFlags.NonPublic | BindingFlags.Instance)
                    .SetValue(this, enableSigning);
                return Smb2Status.STATUS_SUCCESS;
            }

            public override NtStatus SmbdRegisterBuffer(
                uint length, SmbdBufferReadWrite flag, bool reversed, out SmbdBufferDescriptorV1 descriptor)
            {
                descriptor = new SmbdBufferDescriptorV1 { Length = length, Token = ++nextToken };
                Registered.Add(descriptor);
                if (length == 0)
                {
                    throw new InvalidOperationException("Zero registration cannot make READ progress.");
                }
                memory[descriptor.Token] = new byte[length];
                permissions[descriptor.Token] = flag;
                return NtStatus.STATUS_SUCCESS;
            }

            public override NtStatus SmbdWriteRegisteredBuffer(byte[] data, SmbdBufferDescriptorV1 descriptor)
            {
                Assert.AreEqual(SmbdBufferReadWrite.RDMA_READ_PERMISSION_FOR_WRITE_FILE, permissions[descriptor.Token]);
                MemoryWrites.Add((uint)data.Length);
                Assert.AreEqual(descriptor.Length, (uint)data.Length);
                Array.Copy(data, memory[descriptor.Token], data.Length);
                return NtStatus.STATUS_SUCCESS;
            }

            public override NtStatus SmbdReadRegisteredBuffer(byte[] data, SmbdBufferDescriptorV1 descriptor)
            {
                Assert.AreEqual(SmbdBufferReadWrite.RDMA_WRITE_PERMISSION_FOR_READ_FILE, permissions[descriptor.Token]);
                var request = ReadRequests.Last();
                Assert.AreEqual(request.Length, (uint)data.Length);
                Assert.IsTrue(data.Length <= memory[descriptor.Token].Length);
                Array.Copy(FileContent, (long)request.Offset, memory[descriptor.Token], 0, data.Length);
                Array.Copy(memory[descriptor.Token], data, data.Length);
                CollectionAssert.AreEqual(FileContent.Skip((int)request.Offset).Take(data.Length).ToArray(), data);
                MemoryReads.Add((uint)data.Length);
                if (StopAfterReadCopy)
                {
                    throw new BoundaryReachedException();
                }
                return NtStatus.STATUS_SUCCESS;
            }

            public override void SendPacket(byte[] data)
            {
                var header = TypeMarshal.ToStruct<Packet_Header>(data);
                lastCommand = header.Command;
                if (lastCommand == Smb2Command.NEGOTIATE)
                {
                    base.SendPacket(data);
                }
                else if (lastCommand == Smb2Command.WRITE)
                {
                    var request = TypeMarshal.ToStruct<WRITE_Request>(data.Skip(64).ToArray());
                    Writes.Add(request);
                    byte[] content;
                    if (request.Channel == Channel_Values.CHANNEL_NONE)
                    {
                        content = data.Skip(request.DataOffset).Take((int)request.Length).ToArray();
                    }
                    else
                    {
                        int offset = request.WriteChannelInfoOffset;
                        if (request.Channel == Channel_Values.CHANNEL_RDMA_TRANSFORM)
                        {
                            var transform = TypeMarshal.ToStruct<SMB2_RDMA_TRANSFORM>(data.Skip(offset).ToArray());
                            Assert.AreEqual(1, (int)transform.TransformCount);
                            Assert.AreEqual(Smb2RdmaTransformChannel.SMB2_CHANNEL_RDMA_V1, transform.Channel);
                            Assert.IsTrue(header.Flags.HasFlag(Packet_Header_Flags_Values.FLAGS_SIGNED));
                            var crypto = TypeMarshal.ToStruct<SMB2_RDMA_CRYPTO_TRANSFORM>(
                                data.Skip(offset + TypeMarshal.ToBytes(transform).Length).ToArray());
                            Assert.AreEqual(Smb2RDMATransformType.SMB2_RDMA_TRANSFORM_TYPE_SIGNING, crypto.TransformType);
                            Assert.AreEqual(16, (int)crypto.SignatureLength);
                            Assert.AreEqual(0, (int)crypto.NonceLength);
                            Assert.IsTrue(crypto.Signature.Any(b => b != 0));
                            offset += transform.RdmaDescriptorOffset;
                        }
                        var descriptor = TypeMarshal.ToStruct<SmbdBufferDescriptorV1>(data.Skip(offset).ToArray());
                        WriteDescriptors.Add(descriptor);
                        content = memory[descriptor.Token].Take((int)request.RemainingBytes).ToArray();
                    }
                    byte[] file = FileContent;
                    if ((ulong)file.Length < request.Offset + (ulong)content.Length)
                    {
                        Array.Resize(ref file, checked((int)request.Offset + content.Length));
                    }
                    Array.Copy(content, 0, file, (long)request.Offset, content.Length);
                    FileContent = file;
                }
                else if (lastCommand == Smb2Command.READ)
                {
                    var request = TypeMarshal.ToStruct<READ_Request>(data.Skip(64).ToArray());
                    ReadRequests.Add(request);
                    ReadDescriptors.Add(TypeMarshal.ToStruct<SmbdBufferDescriptorV1>(
                        data.Skip(request.ReadChannelInfoOffset).ToArray()));
                }
                else
                {
                    Assert.IsTrue(lastCommand == Smb2Command.TREE_CONNECT || lastCommand == Smb2Command.CREATE);
                }
            }

            public override T ExpectPacket<T>(ulong messageId)
            {
                if (lastCommand == Smb2Command.NEGOTIATE)
                {
                    return base.ExpectPacket<T>(messageId);
                }
                var response = (Smb2SinglePacket)(object)Activator.CreateInstance(typeof(T));
                response.Header.Command = lastCommand;
                response.Header.Status = Smb2Status.STATUS_SUCCESS;
                response.Header.CreditRequestResponse = 64;
                response.Header.TreeId = 1;
                if (response is Smb2WriteResponsePacket write)
                {
                    write.PayLoad.Count = Writes.Last().Channel == Channel_Values.CHANNEL_NONE
                        ? Writes.Last().Length : Writes.Last().RemainingBytes;
                }
                else if (response is Smb2ReadResponsePacket read)
                {
                    read.PayLoad.DataRemaining = ReadRequests.Last().Length;
                    read.Buffer = Array.Empty<byte>();
                }
                else if (response is Smb2CreateResponsePacket create)
                {
                    create.Buffer = Array.Empty<byte>();
                }
                return (T)(object)response;
            }
        }

        private sealed class RdmaWriteClient : Smb2OverSmbdTestClient
        {
            public SmbdBufferDescriptorV1 Registered { get; private set; }
            public SmbdBufferDescriptorV1 Descriptor { get; private set; }
            public WRITE_Request Request { get; private set; }
            public uint MemoryWriteLength { get; private set; }
            public int RegistrationCount { get; private set; }
            public int MemoryWriteCount { get; private set; }
            public int WriteRequestCount { get; private set; }
            public RdmaWriteClient() : base(TimeSpan.Zero) { Smb2AvailableCredits = 64; }
            public override NtStatus SmbdRegisterBuffer(
                uint length, SmbdBufferReadWrite flag, bool reversed, out SmbdBufferDescriptorV1 descriptor)
            {
                if (flag == SmbdBufferReadWrite.RDMA_WRITE_PERMISSION_FOR_READ_FILE)
                {
                    throw new BoundaryReachedException();
                }
                Assert.AreEqual(SmbdBufferReadWrite.RDMA_READ_PERMISSION_FOR_WRITE_FILE, flag);
                RegistrationCount++;
                Registered = descriptor = new SmbdBufferDescriptorV1 { Length = length, Token = 1 };
                return NtStatus.STATUS_SUCCESS;
            }
            public override NtStatus SmbdWriteRegisteredBuffer(byte[] data, SmbdBufferDescriptorV1 descriptor)
            {
                MemoryWriteLength = (uint)data.Length;
                MemoryWriteCount++;
                Assert.AreEqual(Registered.Length, descriptor.Length);
                return NtStatus.STATUS_SUCCESS;
            }
            public override void SendPacket(byte[] data)
            {
                var header = TypeMarshal.ToStruct<Packet_Header>(data);
                if (header.Command == Smb2Command.READ)
                {
                    throw new BoundaryReachedException();
                }
                Assert.AreEqual(Smb2Command.WRITE, header.Command);
                WriteRequestCount++;
                Request = TypeMarshal.ToStruct<WRITE_Request>(data.Skip(64).ToArray());
                Descriptor = TypeMarshal.ToStruct<SmbdBufferDescriptorV1>(
                    data.Skip(Request.WriteChannelInfoOffset).ToArray());
            }
            public override T ExpectPacket<T>(ulong messageId)
            {
                Assert.AreEqual(typeof(Smb2WriteResponsePacket), typeof(T));
                var response = new Smb2WriteResponsePacket();
                response.Header.Status = Smb2Status.STATUS_SUCCESS;
                response.Header.CreditRequestResponse = 64;
                response.PayLoad.Count = Request.RemainingBytes;
                return (T)(object)response;
            }
        }

        private sealed class CapturingClient : Smb2OverSmbdTestClient
        {
            public byte[] Sent { get; private set; }
            public List<byte[]> Packets { get; } = new();
            public List<ulong> ExpectedMessageIds { get; } = new();
            public uint IoctlStatus { get; set; } = (uint)NtStatus.STATUS_NOT_SUPPORTED;
            public ushort IoctlCreditGrant { get; set; } = 1;
            public ushort EchoCreditGrant { get; set; } = 4;
            public byte[] ResponseInput { get; set; }
            public byte[] ResponseOutput { get; set; }
            public CapturingClient() : base(TimeSpan.Zero) { }
            public override void SendPacket(byte[] data)
            {
                Sent = data;
                Packets.Add(data);
            }
            public override T ExpectPacket<T>(ulong messageId)
            {
                ExpectedMessageIds.Add(messageId);
                var response = (T)Activator.CreateInstance(typeof(T));
                var packet = (Smb2SinglePacket)(object)response;
                packet.Header.MessageId = messageId;
                packet.Header.Status = typeof(T) == typeof(Smb2EchoResponsePacket) ? 0 : IoctlStatus;
                packet.Header.CreditRequestResponse =
                    typeof(T) == typeof(Smb2EchoResponsePacket) ? EchoCreditGrant : IoctlCreditGrant;
                if (packet is Smb2IOCtlResponsePacket ioctl)
                {
                    byte[] input = ResponseInput ?? Array.Empty<byte>();
                    byte[] output = ResponseOutput ?? Array.Empty<byte>();
                    ioctl.Header.Command = Smb2Command.IOCTL;
                    ioctl.PayLoad.CtlCode = (uint)CtlCode_Values.FSCTL_QUERY_NETWORK_INTERFACE_INFO;
                    ioctl.PayLoad.InputOffset = ioctl.BufferOffset;
                    ioctl.PayLoad.InputCount = (uint)input.Length;
                    ioctl.PayLoad.OutputOffset = ioctl.BufferOffset + (uint)input.Length;
                    ioctl.PayLoad.OutputCount = (uint)output.Length;
                    ioctl.Buffer = input.Concat(output).ToArray();
                }
                return response;
            }
        }

        private sealed class FragmentResponseClient : SmbdClient
        {
            public bool MissingFinal { get; set; }
            public List<TimeSpan> ReceiveBudgets { get; } = new();

            public FragmentResponseClient()
            {
                Connection = new SmbdConnection();
                Connection.ReceiveCredits = 4;
                Connection.FragmentReassemblyBuffer = new byte[1024];
            }

            public override NtStatus ReceiveDataTransferMessage(TimeSpan timeout, out SmbdDataTransferMessage message)
            {
                ReceiveBudgets.Add(timeout);
                System.Threading.Thread.Sleep(5);
                message = new SmbdDataTransferMessage
                {
                    DataLength = 1,
                    RemainingDataLength = MissingFinal || ReceiveBudgets.Count == 1 ? 1u : 0u,
                    Buffer = new byte[] { 1 }
                };
                return ReceiveBudgets.Count > 20 ? NtStatus.STATUS_IO_TIMEOUT : NtStatus.STATUS_SUCCESS;
            }
        }

        private sealed class ReceivingClient : Smb2OverSmbdTestClient
        {
            public NtStatus Status { get; set; }
            public Exception Failure { get; set; }
            public ReceivingClient() : base(TimeSpan.FromSeconds(1))
            {
                Decoder.TransportType = Smb2TransportType.Rdma;
            }
            protected override NtStatus ReceiveSmbdMessage(TimeSpan timeout, out byte[] message)
            {
                message = null;
                if (Failure != null)
                {
                    throw Failure;
                }
                return Status;
            }
        }

        private sealed class QueuedResponseClient : Smb2OverSmbdTestClient
        {
            private readonly Queue<byte[]> responses;
            public int ReceiveCount { get; private set; }
            public int SendCount { get; private set; }
            public bool RepeatPending { get; set; }
            public List<TimeSpan> ReceiveBudgets { get; } = new();
            public QueuedResponseClient(params byte[][] responses) : base(TimeSpan.FromSeconds(1))
            {
                this.responses = new Queue<byte[]>(responses);
                Decoder.TransportType = Smb2TransportType.Rdma;
                Smb2AvailableCredits = 8;
            }
            public override void SendPacket(byte[] data) => SendCount++;
            protected override NtStatus ReceiveSmbdMessage(TimeSpan timeout, out byte[] message)
            {
                ReceiveCount++;
                ReceiveBudgets.Add(timeout);
                if (RepeatPending)
                {
                    System.Threading.Thread.Sleep(5);
                    message = ErrorResponse(0, Smb2Status.STATUS_PENDING, 0, 7);
                    return NtStatus.STATUS_SUCCESS;
                }
                message = responses.Count > 0 ? responses.Dequeue() : null;
                return message == null ? NtStatus.STATUS_IO_TIMEOUT : NtStatus.STATUS_SUCCESS;
            }
        }

        private sealed class InlineChunkClient : PositiveRdmaClient
        {
            public List<byte[]> Payloads { get; } = new();
            public InlineChunkClient() : base(DialectRevision.Smb30) { }
            public override void SendPacket(byte[] data)
            {
                var header = TypeMarshal.ToStruct<Packet_Header>(data);
                if (header.Command == Smb2Command.IOCTL) throw new BoundaryReachedException();
                base.SendPacket(data);
                if (header.Command == Smb2Command.WRITE)
                {
                    var request = TypeMarshal.ToStruct<WRITE_Request>(data.Skip(64).ToArray());
                    Payloads.Add(data.Skip(request.DataOffset).Take((int)request.Length).ToArray());
                }
            }
        }

        private sealed class SignatureMutationClient : PositiveRdmaClient
        {
            public byte[] OriginalSignature { get; } = Enumerable.Repeat((byte)0x33, 16).ToArray();
            public byte[] EncodedSignature { get; private set; }
            public SignatureMutationClient() : base(DialectRevision.Smb311) { }
            public override void SignByteArray(byte[] original, out byte[] nonce, out byte[] signature, Smb2Command command)
            {
                nonce = Array.Empty<byte>();
                signature = (byte[])OriginalSignature.Clone();
            }
            public override void SendPacket(byte[] data)
            {
                base.SendPacket(data);
                var header = TypeMarshal.ToStruct<Packet_Header>(data);
                if (header.Command != Smb2Command.WRITE) return;
                var request = TypeMarshal.ToStruct<WRITE_Request>(data.Skip(64).ToArray());
                var transform = TypeMarshal.ToStruct<SMB2_RDMA_TRANSFORM>(data.Skip(request.WriteChannelInfoOffset).ToArray());
                EncodedSignature = TypeMarshal.ToStruct<SMB2_RDMA_CRYPTO_TRANSFORM>(
                    data.Skip(request.WriteChannelInfoOffset + TypeMarshal.ToBytes(transform).Length).ToArray()).Signature;
                throw new BoundaryReachedException();
            }
        }

        private sealed class CreditClient : Smb2OverSmbdTestClient
        {
            private readonly Queue<SmbdDataTransferMessage> messages;
            public int Received { get; private set; }
            public int Posted { get; private set; }
            public int Sent { get; private set; }
            public NtStatus ReceiveStatus { get; set; } = NtStatus.STATUS_SUCCESS;
            public int PostLimit { get; set; } = int.MaxValue;
            public int StopAfterSends { get; set; } = int.MaxValue;
            public uint LastRemaining { get; private set; }
            public bool TimeoutWhenExhausted { get; set; }
            public List<TimeSpan> ReceiveTimeouts { get; } = new();
            public CreditClient(IEnumerable<SmbdDataTransferMessage> messages) : base(TimeSpan.Zero)
            {
                this.messages = new Queue<SmbdDataTransferMessage>(messages);
                Decoder.TransportType = Smb2TransportType.Rdma;
            }
            public override NtStatus SmbdReceiveDataTransferMessage(
                TimeSpan timeout, out SmbdDataTransferMessage message)
            {
                Received++;
                ReceiveTimeouts.Add(timeout);
                if (messages.Count == 0 && TimeoutWhenExhausted)
                {
                    throw new TimeoutException("No final READ response.");
                }
                if (ReceiveStatus != NtStatus.STATUS_SUCCESS)
                {
                    if (Received > 1)
                    {
                        throw new InvalidOperationException("A failed receive was retried as an empty message.");
                    }
                    message = new SmbdDataTransferMessage();
                    return ReceiveStatus;
                }
                message = messages.Dequeue();
                ClientConnection.ReceiveCredits--;
                ClientConnection.SendCredits += message.CreditsGranted;
                return NtStatus.STATUS_SUCCESS;
            }
            public override NtStatus SmbdPostReceive()
            {
                if (Posted >= PostLimit)
                {
                    return NtStatus.STATUS_INSUFFICIENT_RESOURCES;
                }
                Posted++;
                ClientConnection.ReceiveCredits++;
                return NtStatus.STATUS_SUCCESS;
            }
            public override NtStatus SmbdSendDataTransferMessage(
                ushort requested, ushort granted, SmbdDataTransfer_Flags flags, ushort reserved,
                uint remaining, uint dataOffset, uint dataLength, byte[] padding, byte[] buffer)
            {
                Sent++;
                LastRemaining = remaining;
                if (Sent == StopAfterSends)
                {
                    throw new SendCapturedException();
                }
                return NtStatus.STATUS_SUCCESS;
            }
        }

        private sealed class SendCapturedException : Exception { }

        private sealed class RegistrationReachedException : Exception { }

        private sealed class TransformWriteProbeClient : Smb2OverSmbdTestClient
        {
            public uint? RegisteredLength { get; private set; }
            public SmbdBufferReadWrite Permission { get; private set; }
            public TransformWriteProbeClient() : base(TimeSpan.Zero)
            {
                cryptoInfoTable[0] = new Smb2CryptoInfo(
                    DialectRevision.Smb311, new byte[16], true, false, false,
                    preauthIntegrityHashValue: new byte[64],
                    cipherId: EncryptionAlgorithm.ENCRYPTION_AES128_GCM,
                    signingId: SigningAlgorithm.AES_GMAC,
                    isSigningAlgorithmNegotiated: true);
            }
            public override NtStatus SmbdRegisterBuffer(
                uint length, SmbdBufferReadWrite flag, bool reversed, out SmbdBufferDescriptorV1 descriptor)
            {
                RegisteredLength = length;
                Permission = flag;
                throw new RegistrationReachedException();
            }
        }

        private sealed class RdmaReadClient : Smb2OverSmbdTestClient
        {
            private readonly byte[] content;
            public bool ReportTransferredLength { get; set; } = true;
            public List<SmbdBufferDescriptorV1> Registered { get; } = new();
            public List<SmbdBufferDescriptorV1> Descriptors { get; } = new();
            public List<READ_Request> Requests { get; } = new();
            public List<uint> MemoryReads { get; } = new();
            public NtStatus MemoryReadStatus { get; set; } = NtStatus.STATUS_SUCCESS;
            public byte[] LastMemoryReadBuffer { get; private set; }
            public RdmaReadClient(byte[] content) : base(TimeSpan.Zero)
            {
                this.content = content;
                Smb2AvailableCredits = 64;
            }
            public override NtStatus SmbdRegisterBuffer(
                uint length, SmbdBufferReadWrite flag, bool reversed, out SmbdBufferDescriptorV1 descriptor)
            {
                if (length == 0)
                {
                    throw new InvalidOperationException("A zero-size registration would prevent READ progress.");
                }
                Assert.AreEqual(SmbdBufferReadWrite.RDMA_WRITE_PERMISSION_FOR_READ_FILE, flag);
                descriptor = new SmbdBufferDescriptorV1 { Length = length, Token = 1 };
                Registered.Add(descriptor);
                return NtStatus.STATUS_SUCCESS;
            }
            public override void SendPacket(byte[] data)
            {
                var header = TypeMarshal.ToStruct<Packet_Header>(data);
                Assert.AreEqual(Smb2Command.READ, header.Command);
                var request = TypeMarshal.ToStruct<READ_Request>(data.Skip(64).ToArray());
                Requests.Add(request);
                Descriptors.Add(TypeMarshal.ToStruct<SmbdBufferDescriptorV1>(
                    data.Skip(request.ReadChannelInfoOffset).ToArray()));
            }
            public override T ExpectPacket<T>(ulong messageId)
            {
                Assert.AreEqual(typeof(Smb2ReadResponsePacket), typeof(T));
                var response = ReadResponse();
                if (ReportTransferredLength)
                {
                    response.PayLoad.DataRemaining = Requests.Last().Length;
                }
                return (T)(object)response;
            }
            public override NtStatus SmbdReadRegisteredBuffer(byte[] data, SmbdBufferDescriptorV1 descriptor)
            {
                MemoryReads.Add((uint)data.Length);
                LastMemoryReadBuffer = data;
                if (MemoryReadStatus != NtStatus.STATUS_SUCCESS)
                {
                    return MemoryReadStatus;
                }
                Array.Copy(content, (long)Requests.Last().Offset, data, 0, data.Length);
                return NtStatus.STATUS_SUCCESS;
            }
        }
    }

    public class CallbackProxy : DispatchProxy
    {
        private Func<MethodInfo, object[], object> callback;
        public static T Create<T>(Func<MethodInfo, object[], object> callback) where T : class
        {
            T value = Create<T, CallbackProxy>();
            ((CallbackProxy)(object)value).callback = callback;
            return value;
        }
        protected override object Invoke(MethodInfo method, object[] args) => callback(method, args);
    }
}
