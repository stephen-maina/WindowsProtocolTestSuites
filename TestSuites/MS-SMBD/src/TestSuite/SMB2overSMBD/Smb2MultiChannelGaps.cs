// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Protocols.TestSuites.Smbd.Adapter;
using Microsoft.Protocols.TestTools;
using Microsoft.Protocols.TestTools.StackSdk;
using Microsoft.Protocols.TestTools.StackSdk.FileAccessService.Smb2;
using Microsoft.Protocols.TestTools.StackSdk.FileAccessService.Smb2.Common;
using Microsoft.Protocols.TestTools.StackSdk.FileAccessService.Smbd;
using Microsoft.Protocols.TestTools.StackSdk.Security.SspiLib;
using Microsoft.Protocols.TestTools.StackSdk.Security.SspiService;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.Protocol.TestSuites.Smbd.TestSuite
{
    /// <summary>
    /// Multi-channel / concurrency gap tests over SMB Direct (RDMA):
    /// FSCTL_QUERY_NETWORK_INTERFACE_INFO, session-binding negatives, channel failover and
    /// concurrent / credit-exceeding traffic.
    /// </summary>
    [TestClass]
    public class Smb2MultiChannelGaps : Smb2OverSmbdTestBase
    {
        #region Variables
        private const int NetworkInterfaceInfoEntrySize = 152; // Next, IfIndex, Capability, Reserved (4 each) + LinkSpeed (8) + SOCKADDR_STORAGE (128)

        private readonly List<Smb2OverSmbdTestClient> clients = new List<Smb2OverSmbdTestClient>();
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
            lock (clients)
            {
                clients.Clear();
            }
        }

        protected override void TestCleanup()
        {
            List<Smb2OverSmbdTestClient> toClose;
            lock (clients)
            {
                toClose = clients.ToList();
                clients.Clear();
            }

            foreach (Smb2OverSmbdTestClient client in toClose)
            {
                try
                {
                    client.DisconnectRdma();
                }
                catch
                {
                }
            }

            base.TestCleanup();
        }
        #endregion

        #region Test Cases: FSCTL_QUERY_NETWORK_INTERFACE_INFO

        [TestMethod()]
        [TestCategory("Smb2MultipleChannel")]
        [TestCategory("QueryNetworkInterfaceInfo")]
        [Description("Verify the FSCTL_QUERY_NETWORK_INTERFACE_INFO response sent over an SMB Direct connection: CtlCode, FileId, Flags, "
                   + "OutputOffset, 8-byte aligned NETWORK_INTERFACE_INFO chain terminated by Next=0, non-zero IfIndex, zero Reserved, "
                   + "and an RDMA_CAPABLE interface that carries the RDMA NIC address.")]
        // WHAT: issue the IOCTL on a signed SMB2 session over RDMA and validate the raw response header and every returned
        //       NETWORK_INTERFACE_INFO entry.
        // WHY: the existing multichannel tests only use the parsed interface list; nothing checked the wire layout that a
        //      multichannel client relies on (offsets, alignment, Next chain, reserved fields).
        // SPEC: [MS-SMB2] 3.3.5.15.11 (CtlCode and FileId fixed values; Flags MUST be 0; OutputOffset MUST be InputOffset +
        //       InputCount rounded up to a multiple of 8; the server MUST NOT include an interface with IfIndex 0),
        //       2.2.32 (OutputOffset rule), 2.2.32.5 (Next is 8-byte aligned and MUST be 0 for the last entry; Reserved MUST be 0;
        //       Capability is built from RSS_CAPABLE/RDMA_CAPABLE). Capability and LinkSpeed values are implementation-specific,
        //       so only the RDMA_CAPABLE bit of the interface that carries the RDMA NIC address is asserted.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.15.11 Handling a Query Network Interface Request; [MS-SMB2] 2.2.32 SMB2 IOCTL Response; [MS-SMB2] 2.2.32.5 NETWORK_INTERFACE_INFO Response")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2Multichannel_QueryNetworkInterfaceInfo_OverRdma_ResponseFormat()
        {
            TestConfig cfg = SmbdTestConfig;
            Smb2OverSmbdTestClient client = NewClient(cfg);
            EstablishSession(client, cfg, Guid.NewGuid(), true);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Send FSCTL_QUERY_NETWORK_INTERFACE_INFO over the RDMA connection.");
            uint status = QueryNetworkInterfaceInfo(client, out byte[] responseInput, out byte[] responseOutput,
                out Packet_Header header, out IOCTL_Response ioctl);

            if ((NtStatus)status == NtStatus.STATUS_NOT_SUPPORTED)
            {
                // [MS-SMB2] 3.3.5.15.11: the server MAY fail with STATUS_NOT_SUPPORTED if it is not multichannel capable.
                BaseTestSite.Assert.Inconclusive("Server does not support FSCTL_QUERY_NETWORK_INTERFACE_INFO (STATUS_NOT_SUPPORTED is allowed by the spec).");
            }
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, (NtStatus)status, "Status of FSCTL_QUERY_NETWORK_INTERFACE_INFO is {0}", (NtStatus)status);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Verify the IOCTL response header fields.");
            BaseTestSite.Assert.AreEqual<uint>((uint)CtlCode_Values.FSCTL_QUERY_NETWORK_INTERFACE_INFO, ioctl.CtlCode, "CtlCode MUST be FSCTL_QUERY_NETWORK_INTERFACE_INFO");
            BaseTestSite.Assert.AreEqual<ulong>(0xffffffffffffffff, ioctl.FileId.Persistent, "FileId.Persistent MUST be 0xFFFFFFFFFFFFFFFF");
            BaseTestSite.Assert.AreEqual<ulong>(0xffffffffffffffff, ioctl.FileId.Volatile, "FileId.Volatile MUST be 0xFFFFFFFFFFFFFFFF");
            BaseTestSite.Assert.AreEqual<uint>(0, (uint)ioctl.Flags, "Flags MUST be 0");
            uint expectedOutputOffset = RoundUpTo8(ioctl.InputOffset + ioctl.InputCount);
            BaseTestSite.Assert.AreEqual<uint>(
                expectedOutputOffset,
                ioctl.OutputOffset,
                "OutputOffset MUST be InputOffset ({0}) + InputCount ({1}) rounded up to a multiple of 8", ioctl.InputOffset, ioctl.InputCount);
            BaseTestSite.Assert.IsTrue(ioctl.OutputCount > 0 && responseOutput != null && responseOutput.Length == ioctl.OutputCount,
                "OutputCount ({0}) MUST describe the NETWORK_INTERFACE_INFO array returned in the buffer", ioctl.OutputCount);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Walk the NETWORK_INTERFACE_INFO chain.");
            IPAddress rdmaServerIp = IPAddress.Parse(cfg.ServerRNicIp);
            bool rdmaNicFound = false;
            bool rdmaNicCapable = false;
            uint offset = 0;
            int entryCount = 0;
            while (true)
            {
                BaseTestSite.Assert.IsTrue(
                    offset + NetworkInterfaceInfoEntrySize <= responseOutput.Length,
                    "Entry {0} at offset {1} MUST lie completely inside the {2}-byte output buffer", entryCount, offset, responseOutput.Length);
                BaseTestSite.Assert.AreEqual<uint>(0, offset % 8, "Entry {0} MUST start on an 8-byte boundary", entryCount);

                int at = (int)offset;
                uint next = BitConverter.ToUInt32(responseOutput, at);
                uint ifIndex = BitConverter.ToUInt32(responseOutput, at + 4);
                uint capability = BitConverter.ToUInt32(responseOutput, at + 8);
                uint reserved = BitConverter.ToUInt32(responseOutput, at + 12);
                ushort family = BitConverter.ToUInt16(responseOutput, at + 24);

                BaseTestSite.Assert.AreNotEqual<uint>(0, ifIndex, "Entry {0}: the server MUST NOT include an interface with IfIndex 0", entryCount);
                BaseTestSite.Assert.AreEqual<uint>(0, reserved, "Entry {0}: Reserved MUST be 0", entryCount);
                BaseTestSite.Assert.AreEqual<uint>(0, next % 8, "Entry {0}: Next ({1}) MUST address an 8-byte aligned entry", entryCount, next);
                BaseTestSite.Assert.IsTrue(family == 0x0002 || family == 0x0017, "Entry {0}: Family 0x{1:X4} MUST be InterNetwork or InterNetworkV6", entryCount, family);

                IPAddress address = null;
                if (family == 0x0002)
                {
                    address = new IPAddress(responseOutput.Skip(at + 28).Take(4).ToArray());
                }
                else
                {
                    address = new IPAddress(responseOutput.Skip(at + 32).Take(16).ToArray());
                }
                BaseTestSite.Log.Add(LogEntryKind.Debug, "Interface {0}: IfIndex={1}, Capability=0x{2:X}, Address={3}", entryCount, ifIndex, capability, address);

                if (address.Equals(rdmaServerIp))
                {
                    rdmaNicFound = true;
                    rdmaNicCapable |= (capability & (uint)NETWORK_INTERFACE_INFO_Response_Capabilities.RDMA_CAPABLE) != 0;
                }

                entryCount++;
                if (next == 0)
                {
                    break; // Next MUST be 0 for the last entry
                }
                BaseTestSite.Assert.IsTrue(next >= NetworkInterfaceInfoEntrySize, "Entry {0}: Next ({1}) MUST NOT overlap the current entry", entryCount - 1, next);
                offset += next;
            }

            BaseTestSite.Assert.IsTrue(rdmaNicFound, "The interface list MUST contain the RDMA NIC address {0} that the connection uses", cfg.ServerRNicIp);
            // RDMA_CAPABLE is the bit defined to mean "the interface is RDMA-capable"; the address was reached over RDMA.
            BaseTestSite.Assert.IsTrue(rdmaNicCapable, "The interface that carries {0} MUST report RDMA_CAPABLE", cfg.ServerRNicIp);
        }

        #endregion

        #region Test Cases: session binding negatives

        [TestMethod()]
        [TestCategory("Smb2MultipleChannel")]
        [TestCategory("SessionBinding")]
        [Description("Verify a session-binding SESSION_SETUP request without SMB2_FLAGS_SIGNED, sent on a second RDMA connection, "
                   + "is failed with STATUS_INVALID_PARAMETER.")]
        // WHAT: authenticate a session on RDMA connection A, then send SESSION_SETUP with SMB2_SESSION_FLAG_BINDING on a second
        //       RDMA connection B (same ClientGuid and dialect) with the SMB2_FLAGS_SIGNED bit clear.
        // WHY: a binding request is the only SESSION_SETUP the server authenticates by signature; accepting an unsigned one
        //      would let any peer that knows a SessionId attach a channel.
        // SPEC: [MS-SMB2] 3.3.5.5 step 4.1.2: "If the SMB2_FLAGS_SIGNED bit is not set in the Flags field in the header, the
        //       server MUST fail the request with error STATUS_INVALID_PARAMETER." The preceding checks (session found, dialect equal)
        //       hold here, so no other error takes precedence.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.5 Receiving an SMB2 SESSION_SETUP Request")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2Multichannel_SessionBind_OverRdma_Unsigned_InvalidParameter()
        {
            TestConfig cfg = SmbdTestConfig;
            Guid clientId = Guid.NewGuid();
            Smb2OverSmbdTestClient main = NewClient(cfg);
            EstablishSession(main, cfg, clientId, false);
            RequireMultichannel(main);
            ulong mainSessionId = GetClientField<ulong>(main, "sessionId");

            Smb2OverSmbdTestClient second = NewClient(cfg);
            ConnectAndNegotiate(second, cfg, clientId);
            RequireMultichannel(second);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Bind session 0x" + mainSessionId.ToString("X") + " on the second RDMA connection without signing.");
            uint status = SendBindRequest(second, cfg, mainSessionId, Packet_Header_Flags_Values.NONE);
            BaseTestSite.Assert.AreEqual<NtStatus>(
                NtStatus.STATUS_INVALID_PARAMETER,
                (NtStatus)status,
                "An unsigned session-binding request MUST be failed with STATUS_INVALID_PARAMETER; actual {0}", (NtStatus)status);
        }

        [TestMethod()]
        [TestCategory("Smb2MultipleChannel")]
        [TestCategory("SessionBinding")]
        [Description("Verify a session-binding SESSION_SETUP request that names an unknown SessionId, sent over RDMA, "
                   + "is failed with STATUS_USER_SESSION_DELETED.")]
        // WHAT: send SESSION_SETUP with SMB2_SESSION_FLAG_BINDING and a SessionId the server never issued on a fresh RDMA connection.
        // WHY: the server must not create or attach a session for an id it cannot find.
        // SPEC: [MS-SMB2] 3.3.5.5 step 4.1: "The server MUST look up the session in GlobalSessionTable using the SessionId from the
        //       SMB2 header. If the session is not found, the server MUST fail the session setup request with
        //       STATUS_USER_SESSION_DELETED." This lookup is the first check of the binding path, so it precedes the signature
        //       checks and the request is sent unsigned (the client holds no key for the unknown session).
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.5 Receiving an SMB2 SESSION_SETUP Request")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2Multichannel_SessionBind_OverRdma_UnknownSessionId_UserSessionDeleted()
        {
            TestConfig cfg = SmbdTestConfig;
            Guid clientId = Guid.NewGuid();
            Smb2OverSmbdTestClient main = NewClient(cfg);
            EstablishSession(main, cfg, clientId, false);
            RequireMultichannel(main);
            ulong mainSessionId = GetClientField<ulong>(main, "sessionId");

            Smb2OverSmbdTestClient second = NewClient(cfg);
            ConnectAndNegotiate(second, cfg, clientId);
            RequireMultichannel(second);

            ulong unknownSessionId = mainSessionId ^ 0x5A5A5A5A5A5A5A5AUL;
            if (unknownSessionId == 0 || unknownSessionId == mainSessionId)
            {
                unknownSessionId = mainSessionId + 0x1000UL;
            }

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Bind unknown session 0x" + unknownSessionId.ToString("X") + " on a new RDMA connection.");
            uint status = SendBindRequest(second, cfg, unknownSessionId, Packet_Header_Flags_Values.NONE);
            BaseTestSite.Assert.AreEqual<NtStatus>(
                NtStatus.STATUS_USER_SESSION_DELETED,
                (NtStatus)status,
                "Binding an unknown SessionId MUST fail with STATUS_USER_SESSION_DELETED; actual {0}", (NtStatus)status);
        }

        [TestMethod()]
        [TestCategory("Smb2MultipleChannel")]
        [TestCategory("SessionBinding")]
        [Description("Verify a signed session-binding SESSION_SETUP request for a session that is already in the receiving connection's "
                   + "SessionTable, sent over RDMA, is failed with STATUS_REQUEST_NOT_ACCEPTED.")]
        // WHAT: after authenticating a session on RDMA connection A, send a signed SESSION_SETUP with SMB2_SESSION_FLAG_BINDING for
        //       the same SessionId on the same connection A.
        // WHY: binding must attach a session to a *different* connection; re-binding on the owning connection is rejected.
        // SPEC: [MS-SMB2] 3.3.5.5 step 4.1.7: "If there is a session in Connection.SessionTable identified by the SessionId in the
        //       request, the server MUST fail the request with STATUS_REQUEST_NOT_ACCEPTED." The request is signed and has the same
        //       dialect and ClientGuid, so steps 4.1.1-4.1.6 do not apply first.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.5 Receiving an SMB2 SESSION_SETUP Request")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2Multichannel_SessionBind_OverRdma_SessionAlreadyOnConnection_RequestNotAccepted()
        {
            TestConfig cfg = SmbdTestConfig;
            Smb2OverSmbdTestClient main = NewClient(cfg);
            EstablishSession(main, cfg, Guid.NewGuid(), false);
            RequireMultichannel(main);
            ulong mainSessionId = GetClientField<ulong>(main, "sessionId");

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Bind session 0x" + mainSessionId.ToString("X") + " again on the connection that already owns it.");
            uint status = SendBindRequest(main, cfg, mainSessionId, Packet_Header_Flags_Values.FLAGS_SIGNED);
            BaseTestSite.Assert.AreEqual<NtStatus>(
                NtStatus.STATUS_REQUEST_NOT_ACCEPTED,
                (NtStatus)status,
                "Binding a session already in Connection.SessionTable MUST fail with STATUS_REQUEST_NOT_ACCEPTED; actual {0}", (NtStatus)status);
        }

        #endregion

        #region Test Cases: failover

        [TestMethod()]
        [TestCategory("Smb2MultipleChannel")]
        [TestCategory("ChannelFailover")]
        [Description("With two RDMA channels bound to one SMB2 session, drop one RDMA connection and verify SMB2 WRITE and READ "
                   + "continue to work on the surviving RDMA channel.")]
        // WHAT: authenticate on RDMA channel A, bind RDMA channel B, open a file, then disconnect A and keep reading and writing the
        //       same open through B.
        // WHY: the value of multichannel is that losing one channel does not lose the session or its opens.
        // SPEC: [MS-SMB2] 3.3.5.5 (session binding adds a channel to Session.ChannelList) and 3.3.7.1: when a connection is lost and
        //       "the Session has more than one channel in Session.ChannelList", only the channel entry is removed and
        //       Session.Connection moves to the first remaining channel; the session and its Opens are not torn down.
        //       Both channels use the single configured RDMA NIC pair (two RDMA connections / queue pairs); the spec does not require
        //       distinct NICs for a second channel.
        [TestProperty("SpecSection", "[MS-SMB2] 3.3.5.5 Receiving an SMB2 SESSION_SETUP Request; [MS-SMB2] 3.3.7.1 Handling Loss of a Connection")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2Multichannel_Failover_DropOneRdmaChannel_IoContinuesOnOther()
        {
            TestConfig cfg = SmbdTestConfig;
            Guid clientId = Guid.NewGuid();
            Smb2OverSmbdTestClient channelA = NewClient(cfg);
            EstablishSession(channelA, cfg, clientId, true);
            RequireMultichannel(channelA);

            string fileName = CreateRandomFileName();
            Require(channelA.Smb2Create(fileName), "SMB2 CREATE on channel A");
            byte[] first = MakePattern(4096, 'a');
            WRITE_Response writeResponse;
            Require(channelA.Smb2Write(0, first, out writeResponse), "SMB2 WRITE on channel A");
            BaseTestSite.Assert.AreEqual<uint>((uint)first.Length, writeResponse.Count, "WRITE on channel A wrote {0} bytes", writeResponse.Count);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Bind a second RDMA channel (B) to the session.");
            Smb2OverSmbdTestClient channelB = NewClient(cfg);
            ConnectAndNegotiate(channelB, cfg, clientId);
            RequireMultichannel(channelB);
            uint bindStatus = channelB.Smb2AlternativeChannelSessionSetup(channelA, cfg.DomainName, cfg.UserName, cfg.Password, cfg.ServerName);
            if ((NtStatus)bindStatus == NtStatus.STATUS_REQUEST_NOT_ACCEPTED || (NtStatus)bindStatus == NtStatus.STATUS_NOT_SUPPORTED)
            {
                // [MS-SMB2] 3.3.5.5: a server that is not multichannel capable SHOULD fail binding with STATUS_REQUEST_NOT_ACCEPTED.
                BaseTestSite.Assert.Inconclusive("Server does not accept session binding over a second RDMA connection: " + (NtStatus)bindStatus);
            }
            BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, (NtStatus)bindStatus, "Status of session binding on channel B is {0}", (NtStatus)bindStatus);
            channelB.TreeId = channelA.TreeId;
            channelB.FileId = channelA.FileId;

            byte[] readData;
            READ_Response readResponse;
            Require(channelB.Smb2Read(0, (uint)first.Length, out readData, out readResponse), "SMB2 READ on channel B before the drop");
            BaseTestSite.Assert.IsTrue(SmbdUtilities.CompareByteArray(first, readData), "Channel B reads the data written on channel A");

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Drop RDMA channel A.");
            channelA.DisconnectRdma();
            // Give the server time to process the transport loss; the spec fixes no timing.
            Thread.Sleep(2000);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Continue WRITE and READ on channel B.");
            byte[] second = MakePattern(4096, 'k');
            Require(channelB.Smb2Write(0, second, out writeResponse), "SMB2 WRITE on channel B after the drop");
            BaseTestSite.Assert.AreEqual<uint>((uint)second.Length, writeResponse.Count, "WRITE on channel B wrote {0} bytes", writeResponse.Count);
            Require(channelB.Smb2Read(0, (uint)second.Length, out readData, out readResponse), "SMB2 READ on channel B after the drop");
            BaseTestSite.Assert.IsTrue(SmbdUtilities.CompareByteArray(second, readData), "Channel B reads back the data it wrote after channel A was lost");

            Require(channelB.Smb2CloseFile(), "SMB2 CLOSE on channel B");
            Require(channelB.Smb2TreeDisconnect(), "SMB2 TREE_DISCONNECT on channel B");
            Require(channelB.Smb2LogOff(), "SMB2 LOGOFF on channel B");
        }

        #endregion

        #region Test Cases: concurrency

        [TestMethod()]
        [TestCategory("Smb2MultipleChannel")]
        [TestCategory("Concurrency")]
        [Description("Verify 8 concurrent SMB Direct connections can each negotiate SMBD and SMB2, authenticate and complete a small SMB2 READ.")]
        // WHAT: run 8 independent RDMA connections in parallel, each doing SMBD negotiate, SMB2 negotiate/session/tree/create,
        //       a small WRITE (to create the data) and a small READ that is compared with the written data.
        // WHY: every existing test uses one connection; connection setup, per-connection credit state and the receive/send queues
        //      must not interfere across connections.
        // SPEC: [MS-SMBD] 3.1.5.1 / 3.1.5.9 (each connection keeps its own Connection.SendCredits / ReceiveCredits) and
        //       [MS-SMB2] 3.3.5.4 / 3.3.5.5 / 3.3.5.12 (negotiate, session setup and READ are served per connection). The spec sets no
        //       connection limit that 8 connections would exceed.
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.5.1 Sending Upper Layer Messages; [MS-SMBD] 3.1.5.9 Managing Credits Prior to Sending; [MS-SMB2] 3.3.5.12 Receiving an SMB2 READ Request")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2Multichannel_Concurrent8RdmaConnections_NegotiateAndRead()
        {
            const int connectionCount = 8;
            TestConfig cfg = SmbdTestConfig;
            string[] fileNames = new string[connectionCount];
            for (int i = 0; i < connectionCount; i++)
            {
                fileNames[i] = CreateRandomFileName();
            }

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Run " + connectionCount + " RDMA connections in parallel.");
            Task<string>[] workers = new Task<string>[connectionCount];
            for (int i = 0; i < connectionCount; i++)
            {
                int index = i;
                workers[i] = Task.Run(() => RunWorker(cfg, index, fileNames[index]));
            }

            TimeSpan limit = TimeSpan.FromTicks(cfg.Smb2ConnectionTimeout.Ticks * 4) + TimeSpan.FromMinutes(1);
            bool finished = Task.WaitAll(workers, limit);
            BaseTestSite.Assert.IsTrue(finished, "All {0} connections MUST finish within {1}", connectionCount, limit);

            List<string> failures = new List<string>();
            for (int i = 0; i < connectionCount; i++)
            {
                if (workers[i].Result != null)
                {
                    failures.Add("connection " + i + ": " + workers[i].Result);
                }
            }
            BaseTestSite.Assert.AreEqual<int>(0, failures.Count, "Every concurrent connection MUST succeed. Failures: {0}", string.Join(" | ", failures));
        }

        [TestMethod()]
        [TestCategory("SmbdCreditManagement")]
        [TestCategory("Concurrency")]
        [Description("Verify one RDMA connection can carry more SMB2 requests than the initial SMBD send credits, with several outstanding at once, "
                   + "and a fragmented READ response larger than the initial receive credits; every request must succeed.")]
        // WHAT: record the SMBD send credits granted by the SMBD negotiate, then pipeline more SMB2 READ requests than that (only
        //       sending while credits remain and collecting responses as they arrive), and finally READ a response that the server must
        //       fragment over many SMBD messages.
        // WHY: credit-limited flow control is the core SMBD mechanism; it only shows up when traffic exceeds the initial credits.
        // SPEC: [MS-SMBD] 3.1.5.1 (a sender with no credits waits for the peer to grant more), 3.1.5.9 (credits are granted in
        //       Data Transfer Messages) and 3.1.5.8 (receiver processing of fragments, RemainingDataLength); [MS-SMB2] 3.3.1.2 (the
        //       server grants SMB2 credits in responses). Credits regained from responses MUST allow all requests to complete.
        [TestProperty("SpecSection", "[MS-SMBD] 3.1.5.1 Sending Upper Layer Messages; [MS-SMBD] 3.1.5.9 Managing Credits Prior to Sending; [MS-SMBD] 3.1.5.8 Receiving a Data Transfer Message; [MS-SMB2] 3.3.1.2 Algorithm for the Granting of Credits")]
        [TestProperty("SpecCompliance", "Conformant")]
        public void Smb2Multichannel_SingleConnection_OutstandingRequestsExceedInitialCredits()
        {
            TestConfig cfg = SmbdTestConfig;
            Smb2OverSmbdTestClient client = NewClient(cfg);

            Require((uint)ConnectRdma(client, cfg), "RDMA connect");
            Require((uint)SmbdNegotiate(client, cfg), "SMBD negotiate");
            uint initialSendCredits = (uint)client.ClientConnection.SendCredits;
            BaseTestSite.Log.Add(LogEntryKind.Debug, "Initial SMBD send credits: " + initialSendCredits);

            DialectRevision selected;
            Require(client.Smb2Negotiate(new[] { DialectRevision.Smb30 }, Guid.NewGuid(), out selected), "SMB2 negotiate");
            Require(client.Smb2SessionSetup(cfg.SecurityPackageForSmb2UserAuthentication, cfg.DomainName, cfg.UserName, cfg.Password, cfg.ServerName), "SMB2 session setup");
            Require(client.Smb2TreeConnect(cfg.ServerName, cfg.ShareFolder), "SMB2 tree connect");
            Require(client.Smb2Create(CreateRandomFileName()), "SMB2 create");

            // Spans many SMBD messages in both directions (MaxSendSize is small) and is capped by the negotiated sizes.
            const int chunk = 512;
            uint messageHeaderSize = (uint)Smb2OverSmbdTestClient.WRITE_REQUEST_HEADER_SIZE;
            if (client.ClientConnection.MaxFragmentedSize <= messageHeaderSize)
            {
                BaseTestSite.Assert.Inconclusive("Negotiated MaxFragmentedSize cannot carry this inline WRITE fixture.");
            }
            uint fixtureLimit = Math.Min(client.Smb2MaxWriteSize, client.Smb2MaxReadSize);
            fixtureLimit = Math.Min(fixtureLimit, client.ClientConnection.MaxFragmentedSize - messageHeaderSize);
            fixtureLimit = Math.Min(fixtureLimit, int.MaxValue);
            int fileSize = (int)Math.Min(cfg.ModerateFileSizeInByte, fixtureLimit);
            fileSize = fileSize / chunk * chunk;
            if (fileSize < chunk)
            {
                BaseTestSite.Assert.Inconclusive("Negotiated/configured sizes cannot carry a {0}-byte READ chunk.", chunk);
            }
            byte[] content = MakePattern(fileSize, 'a');

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Write " + fileSize + " bytes in one fragmented SMB2 WRITE.");
            WRITE_Response writeResponse;
            Require(client.Smb2Write(0, content, out writeResponse), "fragmented SMB2 WRITE");
            BaseTestSite.Assert.AreEqual<uint>((uint)fileSize, writeResponse.Count, "WRITE count");

            uint workloadSendWindow = Math.Max(initialSendCredits, client.ClientConnection.SendCredits);
            uint workloadReceiveWindow = client.ClientConnection.ReceiveCredits;
            int total = CreditWorkloadSize(workloadSendWindow);
            BaseTestSite.Log.Add(LogEntryKind.TestStep,
                "Pipeline {0} READs: SMBD negotiate send window={1}, post-WRITE send window={2}, receive window={3}, SMB2 credits={4}.",
                total, initialSendCredits, client.ClientConnection.SendCredits, workloadReceiveWindow, client.Smb2AvailableCredits);
            ReadTraffic traffic = PipelinedReads(client, content, chunk, total);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Read the whole file back in one fragmented READ response.");
            uint receiveWindow = Math.Max(workloadReceiveWindow, client.ClientConnection.ReceiveCredits);
            ReadTraffic finalRead = PipelinedReads(client, content, fileSize, 1);

            Require(client.Smb2CloseFile(), "SMB2 CLOSE");
            Require(client.Smb2TreeDisconnect(), "SMB2 TREE_DISCONNECT");
            Require(client.Smb2LogOff(), "SMB2 LOGOFF");
            RequireCreditCoverage(workloadSendWindow, traffic.Completed, traffic.PeakOutstanding,
                finalRead.FinalFragments, receiveWindow);
        }

        #endregion

        #region Helpers

        private static readonly object SetupLock = new object();

        private Smb2OverSmbdTestClient NewClient(TestConfig cfg)
        {
            Smb2OverSmbdTestClient client = new Smb2OverSmbdTestClient(cfg.Smb2ConnectionTimeout);
            client.ClientMaxReadWriteSize = cfg.ClientMaxReadWriteSize;
            client.QueryNetworkInterfaceMaxOutputResponse = cfg.QueryNetworkInterfaceMaxOutputResponse;
            lock (clients)
            {
                clients.Add(client);
            }
            return client;
        }

        private uint QueryNetworkInterfaceInfo(
            Smb2OverSmbdTestClient client,
            out byte[] responseInput,
            out byte[] responseOutput,
            out Packet_Header header,
            out IOCTL_Response ioctl) =>
            client.Smb2QueryNetworkInterfaceInfo(out responseInput, out responseOutput, out header, out ioctl);

        private static NtStatus ConnectRdma(Smb2OverSmbdTestClient client, TestConfig cfg)
        {
            IPAddress clientIp = IPAddress.Parse(cfg.ClientRNicIp);
            return client.ConnectToServerOverRDMA(
                cfg.ClientRNicIp,
                cfg.ServerRNicIp,
                cfg.SmbdTcpPort,
                clientIp.AddressFamily,
                cfg.InboundEntries,
                cfg.OutboundEntries,
                cfg.InboundReadLimit,
                cfg.MaxReceiveSize,
                cfg.NDVersion);
        }

        private static NtStatus SmbdNegotiate(Smb2OverSmbdTestClient client, TestConfig cfg)
        {
            SmbdNegotiateResponse response;
            return client.SmbdNegotiate(
                SmbdVersion.V1,
                SmbdVersion.V1,
                0,
                (ushort)cfg.SendCreditTarget,
                (ushort)cfg.ReceiveCreditMax,
                (uint)cfg.MaxSendSize,
                (uint)cfg.MaxReceiveSize,
                (uint)cfg.MaxFragmentedSize,
                out response);
        }

        /// <summary>RDMA connect, SMBD negotiate and SMB2 negotiate (3.0, the dialect used by the other multichannel tests).</summary>
        private static void ConnectAndNegotiate(Smb2OverSmbdTestClient client, TestConfig cfg, Guid clientId)
        {
            Require((uint)ConnectRdma(client, cfg), "RDMA connect");
            Require((uint)SmbdNegotiate(client, cfg), "SMBD negotiate");
            DialectRevision selected;
            Require(client.Smb2Negotiate(new[] { DialectRevision.Smb30 }, clientId, out selected), "SMB2 negotiate");
        }

        private static void EstablishSession(Smb2OverSmbdTestClient client, TestConfig cfg, Guid clientId, bool treeConnect)
        {
            ConnectAndNegotiate(client, cfg, clientId);
            Require(client.Smb2SessionSetup(cfg.SecurityPackageForSmb2UserAuthentication, cfg.DomainName, cfg.UserName, cfg.Password, cfg.ServerName), "SMB2 session setup");
            if (treeConnect)
            {
                Require(client.Smb2TreeConnect(cfg.ServerName, cfg.ShareFolder), "SMB2 tree connect");
            }
        }

        private static void RequireMultichannel(Smb2OverSmbdTestClient client)
        {
            if (!client.NegotiatedServerCapabilities.HasFlag(NEGOTIATE_Response_Capabilities_Values.GLOBAL_CAP_MULTI_CHANNEL))
            {
                throw new AssertInconclusiveException(
                    "The negotiated server capabilities do not enable multichannel; this binding/failover branch is not applicable.");
            }
        }

        private static int CreditWorkloadSize(uint initialCredits)
        {
            const int requestBudget = 128;
            if (initialCredits >= requestBudget)
            {
                throw new AssertInconclusiveException(
                    $"The observed SMBD send window ({initialCredits}) cannot be exceeded within the {requestBudget}-request fixture budget.");
            }
            return (int)Math.Min(requestBudget, Math.Max(24ul, (ulong)initialCredits * 3));
        }

        private static void RequireCreditCoverage(
            uint sendWindow, int completed, int peakOutstanding, long finalFragments, uint receiveWindow)
        {
            if ((ulong)completed <= sendWindow || peakOutstanding < 2 || receiveWindow == 0 || finalFragments <= receiveWindow)
            {
                throw new AssertInconclusiveException(
                    $"Credit coverage not reached: completed={completed}, observed send window={sendWindow}, " +
                    $"peak outstanding={peakOutstanding}, final READ fragments={finalFragments}, observed receive window={receiveWindow}. " +
                    "This fixture does not require the server to grant additional SMB2 concurrency or smaller transport windows.");
            }
        }

        /// <summary>Throws (works on any thread) when an SMB2/SMBD status is not success.</summary>
        private static void Require(uint status, string step)
        {
            if (status != 0)
            {
                throw new AssertFailedException(string.Format("{0} failed with status 0x{1:X8} ({2}).", step, status, (NtStatus)status));
            }
        }

        private static uint RoundUpTo8(uint value)
        {
            return (value + 7u) & ~7u;
        }

        private static byte[] MakePattern(int length, char start)
        {
            byte[] data = new byte[length];
            for (int i = 0; i < length; i++)
            {
                data[i] = (byte)(start + (i % 26));
            }
            return data;
        }

        // WHAT: read/write the client's private SMB2 message id and session id by reflection.
        // WHY: Smb2OverSmbdTestClient has no public member for raw IOCTL, binding or pipelined requests, and existing files must
        //      not be edited; the new tests need the current MessageId/SessionId to build those requests.
        // SPEC: not protocol behaviour (test plumbing). MessageId bookkeeping follows [MS-SMB2] 3.2.4.1.3 / 3.2.4.1.5.
        private static T GetClientField<T>(Smb2OverSmbdTestClient client, string name)
        {
            FieldInfo field = typeof(Smb2OverSmbdTestClient).GetField(name, BindingFlags.NonPublic | BindingFlags.Instance);
            if (field == null)
            {
                throw new InvalidOperationException("Smb2OverSmbdTestClient has no private field " + name);
            }
            return (T)field.GetValue(client);
        }

        private static void SetClientField<T>(Smb2OverSmbdTestClient client, string name, T value)
        {
            FieldInfo field = typeof(Smb2OverSmbdTestClient).GetField(name, BindingFlags.NonPublic | BindingFlags.Instance);
            if (field == null)
            {
                throw new InvalidOperationException("Smb2OverSmbdTestClient has no private field " + name);
            }
            field.SetValue(client, value);
        }

        /// <summary>Account for one raw request (1 credit consumed) and its response.</summary>
        private static void AfterRawResponse(Smb2OverSmbdTestClient client, Packet_Header header)
        {
            SetClientField<ulong>(client, "messageId", GetClientField<ulong>(client, "messageId") + 1);
            client.Smb2AvailableCredits = (ushort)(client.Smb2AvailableCredits + header.CreditRequestResponse - 1);
        }

        /// <summary>
        /// Send one SESSION_SETUP with SMB2_SESSION_FLAG_BINDING for <paramref name="targetSessionId"/> and return its status.
        /// The first token of the configured GSS mechanism is sent; the negative paths under test are decided before the server
        /// processes the token.
        /// </summary>
        private static uint SendBindRequest(Smb2OverSmbdTestClient client, TestConfig cfg, ulong targetSessionId, Packet_Header_Flags_Values flags)
        {
            SspiClientSecurityContext sspi = new SspiClientSecurityContext(
                cfg.SecurityPackageForSmb2UserAuthentication,
                new AccountCredential(cfg.DomainName, cfg.UserName, cfg.Password),
                Smb2Utility.GetCifsServicePrincipalName(cfg.ServerName),
                ClientSecurityContextAttribute.None,
                SecurityTargetDataRepresentation.SecurityNativeDrep);
            if (cfg.SecurityPackageForSmb2UserAuthentication == SecurityPackageType.Negotiate)
            {
                sspi.Initialize(GetClientField<byte[]>(client, "gssToken"));
            }
            else
            {
                sspi.Initialize(null);
            }

            ulong serverSessionId;
            byte[] serverToken;
            Packet_Header header;
            SESSION_SETUP_Response response;
            uint status = client.SessionSetup(
                1,
                64,
                flags,
                GetClientField<ulong>(client, "messageId"),
                targetSessionId,
                SESSION_SETUP_Request_Flags.SESSION_FLAG_BINDING,
                SESSION_SETUP_Request_SecurityMode_Values.NEGOTIATE_SIGNING_ENABLED,
                SESSION_SETUP_Request_Capabilities_Values.GLOBAL_CAP_DFS,
                0,
                sspi.Token,
                out serverSessionId,
                out serverToken,
                out header,
                out response);
            AfterRawResponse(client, header);
            return status;
        }

        /// <summary>One connection of the concurrency test. Returns null on success, otherwise the failure text.</summary>
        private string RunWorker(TestConfig cfg, int index, string fileName)
        {
            try
            {
                Smb2OverSmbdTestClient client = NewClient(cfg);
                // Connection set-up is serialised: the client-side NDSPI provider times out when many
                // connect requests are issued at the same instant (a harness limit, not a protocol one).
                // The connections themselves stay open together and do their I/O in parallel.
                lock (SetupLock)
                {
                    EstablishSession(client, cfg, Guid.NewGuid(), true);
                }
                Require(client.Smb2Create(fileName), "SMB2 create");

                byte[] content = MakePattern(4096, (char)('a' + index % 8));
                WRITE_Response writeResponse;
                Require(client.Smb2Write(0, content, out writeResponse), "SMB2 write");
                if (writeResponse.Count != content.Length)
                {
                    return "WRITE count " + writeResponse.Count;
                }

                byte[] readData;
                READ_Response readResponse;
                Require(client.Smb2Read(0, (uint)content.Length, out readData, out readResponse), "SMB2 read");
                if (!SmbdUtilities.CompareByteArray(content, readData))
                {
                    return "READ returned unexpected data";
                }

                Require(client.Smb2CloseFile(), "SMB2 close");
                Require(client.Smb2TreeDisconnect(), "SMB2 tree disconnect");
                Require(client.Smb2LogOff(), "SMB2 logoff");
                return null;
            }
            catch (Exception ex)
            {
                return ex.GetType().Name + ": " + ex.Message;
            }
        }

        private sealed class PendingRead
        {
            public int ChunkIndex;
            public ulong? AsyncId;
            public TimeSpan Deadline;
        }

        private sealed class ReadTraffic
        {
            public int Completed;
            public int PeakOutstanding;
            public long FinalFragments;
        }

        /// <summary>
        /// Pipeline READs within both credit layers; retain each request through interim responses.
        /// Reserve the last SMBD send credit while requests are outstanding to avoid a receive inside SEND.
        /// </summary>
        private ReadTraffic PipelinedReads(Smb2OverSmbdTestClient client, byte[] content, int chunk, int total)
        {
            int chunkCount = content.Length / chunk;
            ushort charge = checked((ushort)Math.Max(1L, (chunk + 65535L) / 65536));
            if (client.ClientConnection.MaxSendSize <
                new Smb2ReadRequestPacket().BufferOffset + SmbdDataTransferMessage.DEFAULT_DATA_OFFSET)
            {
                BaseTestSite.Assert.Inconclusive(
                    "This pipeline fixture needs each payload-free READ request to fit one SMBD send message.");
            }
            Dictionary<ulong, PendingRead> pending = new Dictionary<ulong, PendingRead>();
            ReadTraffic traffic = new ReadTraffic();
            Stopwatch watch = Stopwatch.StartNew();
            int sent = 0;

            while (traffic.Completed < total)
            {
                bool smb2Credit = client.Smb2AvailableCredits >= charge;
                bool smbdCredit = client.ClientConnection.SendCredits > 1 ||
                    (pending.Count == 0 && client.ClientConnection.SendCredits > 0);
                if (sent < total && smb2Credit && smbdCredit)
                {
                    int chunkIndex = sent % chunkCount;
                    ulong messageId = GetClientField<ulong>(client, "messageId");

                    Smb2ReadRequestPacket request = new Smb2ReadRequestPacket();
                    request.Header.CreditCharge = charge;
                    request.Header.Command = Smb2Command.READ;
                    request.Header.CreditRequestResponse = 64;
                    request.Header.Flags = Packet_Header_Flags_Values.FLAGS_SIGNED;
                    request.Header.MessageId = messageId;
                    request.Header.TreeId = client.TreeId;
                    request.Header.SessionId = GetClientField<ulong>(client, "sessionId");
                    request.PayLoad.Length = (uint)chunk;
                    request.PayLoad.Offset = (ulong)chunkIndex * (ulong)chunk;
                    request.PayLoad.FileId = client.FileId;
                    request.PayLoad.MinimumCount = 0;
                    request.PayLoad.Channel = Channel_Values.CHANNEL_NONE;
                    request.PayLoad.RemainingBytes = 0;
                    request.PayLoad.Flags = READ_Request_Flags_Values.ZERO;

                    SetClientField<ulong>(client, "messageId", messageId + charge);
                    client.Smb2AvailableCredits -= charge;
                    pending.Add(messageId, new PendingRead
                    {
                        ChunkIndex = chunkIndex,
                        Deadline = watch.Elapsed + SmbdTestConfig.Smb2ConnectionTimeout
                    });
                    client.SendPacket(request);
                    sent++;
                    traffic.PeakOutstanding = Math.Max(traffic.PeakOutstanding, pending.Count);
                }
                else
                {
                    if (pending.Count == 0)
                    {
                        BaseTestSite.Assert.Inconclusive(
                            "No outstanding request and insufficient SMB2/SMBD credits after {0} of {1} requests; cannot reach this fixture's coverage.",
                            traffic.Completed, total);
                    }

                    TimeSpan remaining = pending.Values.Min(p => p.Deadline) - watch.Elapsed;
                    BaseTestSite.Assert.IsTrue(remaining > TimeSpan.Zero, "A pipelined READ did not finish before its original deadline.");
                    var envelope = client.ReceiveSmb2Response(remaining);
                    if (!pending.TryGetValue(envelope.MessageId, out PendingRead outstanding) ||
                        !client.TryAcceptResponse(envelope, envelope.MessageId, ref outstanding.AsyncId))
                    {
                        continue;
                    }
                    if (envelope.IsInterim)
                    {
                        continue;
                    }
                    pending.Remove(envelope.MessageId);
                    client.Smb2AvailableCredits = checked((ushort)(
                        client.Smb2AvailableCredits + envelope.Packet.Header.CreditRequestResponse));

                    BaseTestSite.Assert.AreEqual<NtStatus>(NtStatus.STATUS_SUCCESS, (NtStatus)envelope.Packet.Header.Status,
                        "Status of pipelined READ {0} is {1}", traffic.Completed, (NtStatus)envelope.Packet.Header.Status);
                    BaseTestSite.Assert.IsTrue(envelope.Packet is Smb2ReadResponsePacket, "Final response is an SMB2 READ.");
                    Smb2ReadResponsePacket response = (Smb2ReadResponsePacket)envelope.Packet;
                    BaseTestSite.Assert.AreEqual<uint>((uint)chunk, response.PayLoad.DataLength, "DataLength of pipelined READ {0}", traffic.Completed);
                    int chunkIndex = outstanding.ChunkIndex;
                    byte[] data = response.Buffer.Skip((int)response.PayLoad.DataOffset - (int)response.BufferOffset).Take((int)response.PayLoad.DataLength).ToArray();
                    byte[] expected = content.Skip(chunkIndex * chunk).Take(chunk).ToArray();
                    BaseTestSite.Assert.IsTrue(SmbdUtilities.CompareByteArray(expected, data), "Data of pipelined READ {0} (chunk {1})", traffic.Completed, chunkIndex);
                    traffic.FinalFragments = envelope.TransportFragmentCount;
                    traffic.Completed++;
                }
            }

            BaseTestSite.Log.Add(LogEntryKind.Debug,
                "Completed {0} pipelined READs, peak outstanding {1}, last final READ fragments {2}.",
                traffic.Completed, traffic.PeakOutstanding, traffic.FinalFragments);
            return traffic;
        }

        #endregion
    }
}
