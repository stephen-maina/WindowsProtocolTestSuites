// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
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

        private sealed class PositiveRdmaClient : RdmaNegotiationClient
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
            public CapturingClient() : base(TimeSpan.Zero) { }
            public override void SendPacket(byte[] data) => Sent = data;
            public override T ExpectPacket<T>(ulong messageId)
            {
                var response = (T)Activator.CreateInstance(typeof(T));
                ((Smb2SinglePacket)(object)response).Header.Status = (uint)NtStatus.STATUS_NOT_SUPPORTED;
                ((Smb2SinglePacket)(object)response).Header.CreditRequestResponse = 1;
                return response;
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
            protected override NtStatus ReceiveSmbdMessage(out byte[] message)
            {
                message = null;
                if (Failure != null)
                {
                    throw Failure;
                }
                return Status;
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
            public CreditClient(IEnumerable<SmbdDataTransferMessage> messages) : base(TimeSpan.Zero)
            {
                this.messages = new Queue<SmbdDataTransferMessage>(messages);
                Decoder.TransportType = Smb2TransportType.Rdma;
            }
            public override NtStatus SmbdReceiveDataTransferMessage(
                TimeSpan timeout, out SmbdDataTransferMessage message)
            {
                Received++;
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
