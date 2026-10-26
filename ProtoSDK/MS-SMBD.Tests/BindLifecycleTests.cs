// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.IO;
using System.Reflection;
using System.Reflection.Metadata;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Protocols.TestTools.StackSdk;
using Microsoft.Protocols.TestTools.StackSdk.FileAccessService.Smbd;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Protocols.TestTools.StackSdk.FileAccessService.RdmaLinux
{
    // The WINDOWS source imports this namespace but does not use a Linux adapter.
    internal class SourceLinkNamespace { }
}

namespace Microsoft.Protocols.TestTools.StackSdk.FileAccessService.Smbd
{
    internal static class RdmaServiceFactory
    {
        public static INativeRdmaService Create(NdspiVersion version) => new NativeDouble();
    }
}

namespace Smbd.Endpoint.Tests
{
    [TestClass]
    public class BindLifecycleTests
    {
        public TestContext TestContext { get; set; }

        [TestInitialize]
        public void RecordLoadedEndpointIdentity()
        {
            Assembly assembly = typeof(SmbdConnectionEndpoint).Assembly;
            TestContext.WriteLine($"ENDPOINT_ASSEMBLY {assembly.Location} MVID={assembly.ManifestModule.ModuleVersionId} SHA256={Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(assembly.Location)))}");
            TestContext.WriteLine($"RUNTIME {System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription}");
            using var stream = File.OpenRead(Path.ChangeExtension(assembly.Location, ".pdb"));
            using var provider = MetadataReaderProvider.FromPortablePdbStream(stream);
            MetadataReader reader = provider.GetMetadataReader();
            foreach (DocumentHandle handle in reader.Documents)
            {
                Document document = reader.GetDocument(handle);
                TestContext.WriteLine($"PDB_DOCUMENT {reader.GetString(document.Name)} HASH_ALGORITHM={reader.GetGuid(document.HashAlgorithm)} HASH={Convert.ToHexString(reader.GetBlobBytes(document.Hash))}");
            }
        }

        [DataTestMethod]
        [DataRow(RdmaReadWriteFlag.Read)]
        [DataRow(RdmaReadWriteFlag.Write)]
        [DataRow(RdmaReadWriteFlag.ReadAndWrite)]
        public void MemoryRegionFallbackPreservesPermissionsOnFirstAndCachedRegistration(RdmaReadWriteFlag flag)
        {
            using var fixture = new Fixture();
            fixture.Native.WindowStatus = NtStatus.STATUS_NOT_SUPPORTED;
            for (int attempt = 0; attempt < 2; attempt++)
            {
                RdmaReadWriteFlag requested = attempt == 0 ? flag
                    : (RdmaReadWriteFlag)(((int)flag + 1) % 3);
                Assert.AreEqual(NtStatus.STATUS_SUCCESS,
                    fixture.Endpoint.RegisterMemoryWindow(16, (uint)requested, false, out fixture.Descriptor));
                Assert.AreEqual(requested, fixture.Native.RegisteredPermissions,
                    "The published MR token must not grant permissions beyond this call's request.");
                Assert.AreEqual(88u, fixture.Descriptor.Token);
                Assert.AreEqual(1, fixture.Native.WindowCreations, "Cached fallback must skip window creation.");
                Assert.IsFalse(fixture.Native.BindSubmitted.IsSet);
                fixture.Endpoint.DeregisterMemoryWindow(fixture.Descriptor);
                Assert.AreEqual(0, fixture.Native.OwnedMemoryCount);
            }
        }

        [DataTestMethod]
        [DataRow(RdmaReadWriteFlag.Read)]
        [DataRow(RdmaReadWriteFlag.Write)]
        [DataRow(RdmaReadWriteFlag.ReadAndWrite)]
        public void MemoryWindowRegistrationAndBindUseTheSamePermissions(RdmaReadWriteFlag flag)
        {
            using var fixture = new Fixture();
            var call = Task.Run(() => fixture.Endpoint.RegisterMemoryWindow(16, (uint)flag, false, out fixture.Descriptor));
            Assert.IsTrue(fixture.Native.BindSubmitted.Wait(3000));
            fixture.Native.CompleteBind(NtStatus.STATUS_SUCCESS);
            Assert.AreEqual(NtStatus.STATUS_SUCCESS, call.GetAwaiter().GetResult());
            Assert.AreEqual(flag, fixture.Native.RegisteredPermissions);
            Assert.AreEqual(flag, fixture.Native.BoundPermissions);
            Assert.AreEqual(77u, fixture.Descriptor.Token);
        }

        [DataTestMethod]
        [DataRow(RdmaReadWriteFlag.Read, false)]
        [DataRow(RdmaReadWriteFlag.Write, false)]
        [DataRow(RdmaReadWriteFlag.ReadAndWrite, false)]
        [DataRow(RdmaReadWriteFlag.Read, true)]
        [DataRow(RdmaReadWriteFlag.Write, true)]
        [DataRow(RdmaReadWriteFlag.ReadAndWrite, true)]
        public void RejectedPermissionRegistrationDoesNotPublishAToken(RdmaReadWriteFlag flag, bool cached)
        {
            using var fixture = new Fixture();
            fixture.Native.WindowStatus = NtStatus.STATUS_NOT_SUPPORTED;
            if (cached)
            {
                Assert.AreEqual(NtStatus.STATUS_SUCCESS,
                    fixture.Endpoint.RegisterMemoryWindow(16, (uint)flag, false, out fixture.Descriptor));
                fixture.Endpoint.DeregisterMemoryWindow(fixture.Descriptor);
            }
            fixture.Native.RegisterStatus = NtStatus.STATUS_ACCESS_DENIED;
            Assert.AreEqual(NtStatus.STATUS_ACCESS_DENIED,
                fixture.Endpoint.RegisterMemoryWindow(16, (uint)flag, false, out fixture.Descriptor));
            Assert.AreEqual(flag, fixture.Native.RegisteredPermissions);
            Assert.AreEqual(0u, fixture.Descriptor.Token);
            Assert.AreEqual(0, fixture.PublishedWindows);
            Assert.AreEqual(0, fixture.Native.OwnedMemoryCount);
            Assert.IsFalse(fixture.Native.BindSubmitted.IsSet);
        }

        [TestMethod]
        public void InvalidRemotePermissionsAreRejectedBeforeAllocation()
        {
            using var fixture = new Fixture();
            Assert.AreEqual(NtStatus.STATUS_INVALID_PARAMETER,
                fixture.Endpoint.RegisterMemoryWindow(16, uint.MaxValue, false, out fixture.Descriptor));
            Assert.AreEqual(0, fixture.Native.Registrations);
            Assert.AreEqual(0, fixture.PublishedWindows);
        }

        [TestMethod]
        public void FailedBindCompletionAccountsOnceAndCleansOnce()
        {
            using var fixture = new Fixture();
            var call = fixture.Register();
            fixture.Native.CompleteBind(NtStatus.STATUS_UNSUCCESSFUL);
            Assert.AreEqual(NtStatus.STATUS_UNSUCCESSFUL, call.GetAwaiter().GetResult());
            Assert.AreEqual(0, fixture.Count);
            Assert.AreEqual(1, fixture.Native.Window.Disposals);
            Assert.AreEqual(1, fixture.Native.Deregistrations);
        }

        [TestMethod]
        public void RejectedBindDoesNotReserveACompletion()
        {
            using var fixture = new Fixture();
            fixture.Native.SubmitStatus = NtStatus.STATUS_UNSUCCESSFUL;
            Assert.AreEqual(NtStatus.STATUS_UNSUCCESSFUL, fixture.Register().GetAwaiter().GetResult());
            Assert.AreEqual(0, fixture.Count);
            Assert.AreEqual(1, fixture.Native.Window.Disposals);
            Assert.AreEqual(1, fixture.Native.Deregistrations);
        }

        [DataTestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public void TimeoutRetainsResourcesUntilMatchingLateCompletion(bool failed)
        {
            using var fixture = new Fixture();
            Assert.AreEqual(NtStatus.STATUS_TIMEOUT, fixture.Register().GetAwaiter().GetResult());
            Assert.AreEqual(1, fixture.Count, "A wait timeout does not cancel the submitted Bind.");
            Assert.AreEqual(0, fixture.Native.Window.Disposals);
            Assert.AreEqual(0, fixture.Native.Deregistrations);
            fixture.Native.CompleteBind(failed ? NtStatus.STATUS_UNSUCCESSFUL : NtStatus.STATUS_SUCCESS);
            Assert.IsTrue(SpinWait.SpinUntil(() => fixture.Native.Deregistrations == 1, 3000),
                "The matching late completion must reclaim the unpublished window.");
            Assert.AreEqual(0, fixture.Count);
            Assert.AreEqual(1, fixture.Native.Window.Disposals);
            fixture.ConfigureReceive();
            Assert.AreEqual(NtStatus.STATUS_SUCCESS, fixture.Endpoint.PostReceive(16));
            fixture.Native.CompleteBind(NtStatus.STATUS_SUCCESS);
            fixture.Native.Complete(400, NtStatus.STATUS_SUCCESS);
            Assert.AreEqual(400ul,
                fixture.Endpoint.GetRequestResult(TimeSpan.FromSeconds(3), RequestType.Receive).ResultId);
            Assert.AreEqual(0, fixture.Count);
            Assert.AreEqual(1, fixture.Native.Deregistrations);
            Assert.AreEqual(1, fixture.Native.Window.Disposals);
        }

        [TestMethod]
        public void SuccessfulBindIgnoresStaleResultAndRefreshesToken()
        {
            using var fixture = new Fixture();
            fixture.Results.Enqueue(new SmbdRequestResult
            {
                ResultId = 999,
                ResultInfo = new NdResult { Status = unchecked((int)NtStatus.STATUS_UNSUCCESSFUL) }
            });
            var call = fixture.Register();
            Assert.IsFalse(call.IsCompleted);
            fixture.Native.CompleteBind(NtStatus.STATUS_SUCCESS);
            Assert.AreEqual(NtStatus.STATUS_SUCCESS, call.GetAwaiter().GetResult());
            Assert.AreEqual(77u, fixture.Descriptor.Token);
            Assert.AreEqual(999ul, fixture.Results.Dequeue(TimeSpan.Zero).ResultId);
            Assert.AreEqual(0, fixture.Count);
            Assert.AreEqual(0, fixture.Native.Window.Disposals);
            Assert.AreEqual(0, fixture.Native.Deregistrations);
        }

        [TestMethod]
        public void PassiveInvalidNotificationDoesNotConsumeBindReservation()
        {
            using var fixture = new Fixture();
            var call = fixture.Register();
            fixture.Native.Complete(0, NtStatus.STATUS_SUCCESS);
            Assert.IsTrue(SpinWait.SpinUntil(() => fixture.Native.Drained >= 1, 3000));
            Assert.AreEqual(1, fixture.Count);
            Assert.IsFalse(call.IsCompleted);
            fixture.Native.CompleteBind(NtStatus.STATUS_SUCCESS);
            Assert.AreEqual(NtStatus.STATUS_SUCCESS, call.GetAwaiter().GetResult());
            Assert.AreEqual(0, fixture.Count);
        }

        [TestMethod]
        public void TimeoutBlocksAllocationThenAllowsSuccessfulNeighborAfterDrain()
        {
            using var fixture = new Fixture();
            Assert.AreEqual(NtStatus.STATUS_TIMEOUT, fixture.Register().GetAwaiter().GetResult());
            Assert.AreEqual(NtStatus.STATUS_DEVICE_BUSY, fixture.Register().GetAwaiter().GetResult());
            Assert.AreEqual(1, fixture.Native.Registrations);
            fixture.Native.CompleteBind(NtStatus.STATUS_UNSUCCESSFUL);
            Assert.IsTrue(SpinWait.SpinUntil(() => fixture.Native.Deregistrations == 1, 3000));
            fixture.WaitForDrain();
            var call = fixture.Register();
            fixture.Native.CompleteBind(NtStatus.STATUS_SUCCESS);
            Assert.AreEqual(NtStatus.STATUS_SUCCESS, call.GetAwaiter().GetResult());
            Assert.AreEqual(0, fixture.Count);
            Assert.AreEqual(1, fixture.Native.Window.Disposals);
            Assert.AreEqual(1, fixture.Native.Deregistrations);
        }

        [TestMethod]
        public void DisconnectFlushStillWaitsForMatchingCompletion()
        {
            using var fixture = new Fixture();
            Assert.AreEqual(NtStatus.STATUS_TIMEOUT, fixture.Register().GetAwaiter().GetResult());
            var disconnect = Task.Run(fixture.Endpoint.Disconnect);
            Assert.IsTrue(fixture.Native.Flushed.Wait(3000));
            Assert.IsFalse(disconnect.IsCompleted, "Flush return is not proof that Bind has completed.");
            Assert.AreEqual(0, fixture.Native.Window.Disposals);
            fixture.Native.CompleteBind(NtStatus.STATUS_CANCELLED);
            disconnect.GetAwaiter().GetResult();
            Assert.AreEqual(0, fixture.Count);
            Assert.AreEqual(1, fixture.Native.Window.Disposals);
            Assert.AreEqual(1, fixture.Native.Deregistrations);
        }

        [DataTestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public void MissingCompletionFailsDisconnectBoundedlyWithoutFreeingResources(bool flushFailed)
        {
            using var fixture = new Fixture();
            fixture.Native.FlushStatus = flushFailed ? NtStatus.STATUS_UNSUCCESSFUL : NtStatus.STATUS_SUCCESS;
            Assert.AreEqual(NtStatus.STATUS_TIMEOUT, fixture.Register().GetAwaiter().GetResult());
            Assert.ThrowsException<TimeoutException>(fixture.Endpoint.Disconnect);
            Assert.AreEqual(1, fixture.Count);
            Assert.AreEqual(0, fixture.Native.Window.Disposals);
            Assert.AreEqual(0, fixture.Native.Deregistrations);
            fixture.Native.CompleteBind(NtStatus.STATUS_CANCELLED);
            Assert.IsTrue(SpinWait.SpinUntil(() => fixture.Native.Deregistrations == 1, 3000));
            fixture.Endpoint.Disconnect();
            Assert.AreEqual(0, fixture.Count);
        }

        [TestMethod]
        public void FailedNativeCleanupRetainsRegistrationForExplicitDisconnectRetry()
        {
            using var fixture = new Fixture();
            fixture.Native.DeregisterStatus = NtStatus.STATUS_UNSUCCESSFUL;
            var call = fixture.Register();
            fixture.Native.CompleteBind(NtStatus.STATUS_UNSUCCESSFUL);
            Assert.AreEqual(NtStatus.STATUS_UNSUCCESSFUL, call.GetAwaiter().GetResult());
            Assert.AreEqual(0, fixture.Count);
            Assert.AreEqual(NtStatus.STATUS_DEVICE_BUSY, fixture.Register().GetAwaiter().GetResult());
            Assert.ThrowsException<InvalidOperationException>(fixture.Endpoint.Disconnect);
            Assert.AreEqual(1, fixture.Native.Window.Disposals);
            fixture.Native.DeregisterStatus = NtStatus.STATUS_SUCCESS;
            fixture.Endpoint.Disconnect();
            Assert.AreEqual(1, fixture.Native.Window.Disposals);
            Assert.AreEqual(3, fixture.Native.Deregistrations);
        }

        [DataTestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public void SuccessfulWindowDeregistrationWaitsForItsInvalidateCompletion(bool failed)
        {
            using var fixture = new Fixture();
            var call = fixture.Register();
            fixture.Native.CompleteBind(NtStatus.STATUS_SUCCESS);
            Assert.AreEqual(NtStatus.STATUS_SUCCESS, call.GetAwaiter().GetResult());
            fixture.Endpoint.DeregisterMemoryWindow(fixture.Descriptor);
            Assert.AreEqual(1, fixture.Count);
            Assert.AreEqual(0, fixture.Native.Window.Disposals);
            Assert.AreEqual(0, fixture.Native.Deregistrations);
            fixture.Native.Complete(200, failed ? NtStatus.STATUS_UNSUCCESSFUL : NtStatus.STATUS_SUCCESS);
            Assert.IsTrue(SpinWait.SpinUntil(() => fixture.Native.Deregistrations == 1, 3000));
            Assert.AreEqual(0, fixture.Count);
            Assert.AreEqual(1, fixture.Native.Window.Disposals);
        }

        [TestMethod]
        public void CompletionWinningTimeoutBoundaryIsConsumedWithoutAbandoningTheWindow()
        {
            using var fixture = new Fixture();
            using var timedOut = new ManualResetEventSlim();
            using var resume = new ManualResetEventSlim();
            fixture.OnTimeoutLog = () =>
            {
                timedOut.Set();
                Assert.IsTrue(resume.Wait(3000));
            };
            var call = fixture.Register();
            Assert.IsTrue(timedOut.Wait(6000));
            fixture.Native.CompleteBind(NtStatus.STATUS_SUCCESS);
            Assert.IsTrue(SpinWait.SpinUntil(() => fixture.Count == 0, 3000));
            resume.Set();
            Assert.AreEqual(NtStatus.STATUS_SUCCESS, call.GetAwaiter().GetResult());
            Assert.AreEqual(0, fixture.Count);
            Assert.AreEqual(0, fixture.Results.Count);
            Assert.AreEqual(0, fixture.Native.Window.Disposals);
            Assert.AreEqual(0, fixture.Native.Deregistrations);
        }

        [TestMethod]
        public void FailedBindDoesNotConsumeNeighboringSendCompletion()
        {
            using var fixture = new Fixture();
            var bind = fixture.Register();
            var send = Task.Run(() => fixture.Endpoint.SendData(new byte[16]));
            Assert.IsTrue(fixture.Native.SendSubmitted.Wait(3000));
            Assert.IsTrue(SpinWait.SpinUntil(() => fixture.Count == 2, 3000));
            fixture.Native.CompleteBind(NtStatus.STATUS_UNSUCCESSFUL);
            Assert.AreEqual(NtStatus.STATUS_UNSUCCESSFUL, bind.GetAwaiter().GetResult());
            Assert.AreEqual(1, fixture.Count);
            Assert.IsFalse(send.IsCompleted);
            fixture.Native.Complete(300, NtStatus.STATUS_SUCCESS);
            Assert.AreEqual(NtStatus.STATUS_SUCCESS, send.GetAwaiter().GetResult());
            Assert.AreEqual(0, fixture.Count);
        }

        [TestMethod]
        public void ConcurrentRegistrationDoesNotAllocateAnotherUnresolvedBind()
        {
            using var fixture = new Fixture();
            var call = fixture.Register();
            Assert.AreEqual(NtStatus.STATUS_DEVICE_BUSY,
                fixture.Endpoint.RegisterMemoryWindow(16, 0, false, out _));
            Assert.AreEqual(1, fixture.Native.Registrations);
            fixture.Native.CompleteBind(NtStatus.STATUS_UNSUCCESSFUL);
            Assert.AreEqual(NtStatus.STATUS_UNSUCCESSFUL, call.GetAwaiter().GetResult());
            Assert.AreEqual(0, fixture.Count);
        }

        [TestMethod]
        public void MemoryRegionFallbackFailureRetainsFailedNativeCleanup()
        {
            using var fixture = new Fixture();
            fixture.Native.WindowStatus = NtStatus.STATUS_NOT_SUPPORTED;
            fixture.Native.MemoryDescriptionStatus = NtStatus.STATUS_UNSUCCESSFUL;
            fixture.Native.DeregisterStatus = NtStatus.STATUS_UNSUCCESSFUL;
            Assert.AreEqual(NtStatus.STATUS_UNSUCCESSFUL,
                fixture.Endpoint.RegisterMemoryWindow(16, 0, false, out _));
            Assert.AreEqual(NtStatus.STATUS_DEVICE_BUSY,
                fixture.Endpoint.RegisterMemoryWindow(16, 0, false, out _));
            Assert.AreEqual(1, fixture.Native.Registrations);
            Assert.ThrowsException<InvalidOperationException>(fixture.Endpoint.Disconnect);
            fixture.Native.DeregisterStatus = NtStatus.STATUS_SUCCESS;
            fixture.Endpoint.Disconnect();
            Assert.AreEqual(0, fixture.Native.Window.Disposals);
            Assert.AreEqual(3, fixture.Native.Deregistrations);
        }

        [TestMethod]
        public void SendCleanupFailureIsReportedAndRetainedRatherThanForgotten()
        {
            using var fixture = new Fixture();
            fixture.Native.DeregisterStatus = NtStatus.STATUS_UNSUCCESSFUL;
            var call = Task.Run(() => fixture.Endpoint.SendData(new byte[16]));
            Assert.IsTrue(fixture.Native.SendSubmitted.Wait(3000));
            fixture.Native.Complete(300, NtStatus.STATUS_SUCCESS);
            Assert.AreEqual(NtStatus.STATUS_UNSUCCESSFUL, call.GetAwaiter().GetResult());
            Assert.AreEqual(NtStatus.STATUS_DEVICE_BUSY, fixture.Endpoint.SendData(new byte[16]));
            Assert.AreEqual(1, fixture.Native.Registrations);
            Assert.ThrowsException<InvalidOperationException>(fixture.Endpoint.Disconnect);
            fixture.Native.DeregisterStatus = NtStatus.STATUS_SUCCESS;
            fixture.Endpoint.Disconnect();
            Assert.AreEqual(3, fixture.Native.Deregistrations);
        }

        [TestMethod]
        public void FailedBindLeavesNeighboringReceiveAccountedUntilItsOwnCompletion()
        {
            using var fixture = new Fixture();
            fixture.ConfigureReceive();
            Assert.AreEqual(NtStatus.STATUS_SUCCESS, fixture.Endpoint.PostReceive(16));
            var bind = fixture.Register();
            fixture.Native.CompleteBind(NtStatus.STATUS_UNSUCCESSFUL);
            Assert.AreEqual(NtStatus.STATUS_UNSUCCESSFUL, bind.GetAwaiter().GetResult());
            Assert.AreEqual(1, fixture.Count);
            Assert.AreEqual(1, fixture.Endpoint.ReceivePostedCount);
            fixture.Native.Complete(400, NtStatus.STATUS_SUCCESS);
            var receive = fixture.Endpoint.GetRequestResult(TimeSpan.FromSeconds(3), RequestType.Receive);
            Assert.AreEqual(400ul, receive.ResultId);
            Assert.AreEqual(0, fixture.Count);
            Assert.IsTrue(SpinWait.SpinUntil(() => fixture.Endpoint.ReceivePostedCount == 0, 3000));
        }

        [DataTestMethod]
        [TestCategory("PrincipalFollowup")]
        [DataRow(false)]
        [DataRow(true)]
        public void LateBindCleanupSerializesWithWholeNativeSendRegistration(bool failed)
        {
            using var fixture = new Fixture();
            Assert.AreEqual(NtStatus.STATUS_TIMEOUT, fixture.Register().GetAwaiter().GetResult());
            using var entered = new ManualResetEventSlim();
            using var resume = new ManualResetEventSlim();
            fixture.Native.RejectMemoryOperationOverlap = true;
            fixture.Native.OnRegisterMemory = () => WaitAtBarrier(entered, resume);
            Task<NtStatus> send = Task.Run(() => fixture.Endpoint.SendData(new byte[16]));
            try
            {
                Assert.IsTrue(entered.Wait(3000));
                fixture.Native.CompleteBind(failed ? NtStatus.STATUS_UNSUCCESSFUL : NtStatus.STATUS_SUCCESS);
                Assert.IsTrue(fixture.Native.NotificationObserved.Wait(3000));
                fixture.Native.DeregisterEntered.Wait(250);
            }
            finally
            {
                resume.Set();
            }
            Assert.IsTrue(fixture.Native.SendSubmitted.Wait(3000));
            fixture.Native.Complete(300, NtStatus.STATUS_SUCCESS);
            Assert.AreEqual(NtStatus.STATUS_SUCCESS, send.GetAwaiter().GetResult());
            fixture.WaitForDrain();
            Assert.AreEqual(0, fixture.Native.MemoryOperationOverlaps,
                "Register/Deregister and their native waits share one OVERLAPPED and must not overlap.");
            Assert.AreEqual(2, fixture.Native.Deregistrations);
            Assert.AreEqual(0, fixture.Native.OwnedMemoryCount);
            Assert.AreEqual(1, fixture.Native.Window.Disposals);
            Assert.AreEqual(0, fixture.Count);
        }

        [TestMethod]
        [TestCategory("PrincipalFollowup")]
        public void ConcurrentSendsSerializeNativeRegistrationAndKeepDistinctCompletions()
        {
            using var fixture = new Fixture();
            using var entered = new ManualResetEventSlim();
            using var resume = new ManualResetEventSlim();
            using var secondStarted = new ManualResetEventSlim();
            int registrationsEntered = 0;
            fixture.Native.RejectMemoryOperationOverlap = true;
            fixture.Native.OnRegisterMemory = () =>
            {
                if (Interlocked.Increment(ref registrationsEntered) == 1) WaitAtBarrier(entered, resume);
            };
            Task<NtStatus> first = Task.Run(() => fixture.Endpoint.SendData(new byte[16]));
            Task<NtStatus> second = null;
            try
            {
                Assert.IsTrue(entered.Wait(3000));
                second = Task.Run(() =>
                {
                    secondStarted.Set();
                    return fixture.Endpoint.SendData(new byte[16]);
                });
                Assert.IsTrue(secondStarted.Wait(3000));
                fixture.Native.OverlapObserved.Wait(250);
            }
            finally
            {
                resume.Set();
            }
            Assert.IsTrue(SpinWait.SpinUntil(() => fixture.Native.SendCalls == 2, 3000));
            fixture.Native.Complete(301, NtStatus.STATUS_SUCCESS);
            fixture.Native.Complete(300, NtStatus.STATUS_SUCCESS);
            Assert.AreEqual(NtStatus.STATUS_SUCCESS, first.GetAwaiter().GetResult());
            Assert.AreEqual(NtStatus.STATUS_SUCCESS, second.GetAwaiter().GetResult());
            Assert.AreEqual(0, fixture.Native.MemoryOperationOverlaps);
            Assert.AreEqual(2, fixture.Native.Registrations);
            Assert.AreEqual(2, fixture.Native.Deregistrations);
            Assert.AreEqual(0, fixture.Native.OwnedMemoryCount);
            Assert.AreEqual(0, fixture.Count);
        }

        [DataTestMethod]
        [TestCategory("PrincipalFollowup")]
        [DataRow("Fallback", false)]
        [DataRow("Fallback", true)]
        [DataRow("Bind", false)]
        [DataRow("Bind", true)]
        [DataRow("BeforeBind", false)]
        [DataRow("BeforeBind", true)]
        public void ShutdownWinningPublicationReclaimsOrRetainsForExplicitRetry(string phase, bool cleanupFails)
        {
            using var fixture = new Fixture();
            using var entered = new ManualResetEventSlim();
            using var resume = new ManualResetEventSlim();
            fixture.Native.RejectMemoryOperationOverlap = true;
            fixture.Native.DeregisterStatus = cleanupFails ? NtStatus.STATUS_ACCESS_DENIED : NtStatus.STATUS_SUCCESS;
            Action pause = () => WaitAtBarrier(entered, resume);
            if (phase == "Fallback")
            {
                fixture.Native.WindowStatus = NtStatus.STATUS_NOT_SUPPORTED;
                fixture.Native.OnGetRegisteredMemory = pause;
            }
            else if (phase == "BeforeBind")
            {
                fixture.Native.OnCreateMemoryWindow = pause;
            }
            else
            {
                fixture.Native.Window.OnRemoteToken = pause;
            }
            Task<NtStatus> registration = Task.Run(() =>
                fixture.Endpoint.RegisterMemoryWindow(16, 0, false, out fixture.Descriptor));
            Task<Exception> disconnect = null;
            try
            {
                if (phase == "Bind")
                {
                    Assert.IsTrue(fixture.Native.BindSubmitted.Wait(3000));
                    fixture.Native.CompleteBind(NtStatus.STATUS_SUCCESS);
                }
                Assert.IsTrue(entered.Wait(3000));
                disconnect = Task.Run(() => CaptureDisconnect(fixture.Endpoint));
                Assert.IsTrue(fixture.Native.Disconnected.Wait(3000));
            }
            finally
            {
                resume.Set();
            }
            NtStatus registrationStatus = registration.GetAwaiter().GetResult();
            Exception disconnectFailure = disconnect.GetAwaiter().GetResult();
            Assert.AreEqual(cleanupFails ? NtStatus.STATUS_ACCESS_DENIED : NtStatus.STATUS_CONNECTION_DISCONNECTED,
                registrationStatus, "Shutdown must win atomically over descriptor publication and expose reclaim failure.");
            Assert.AreEqual(0u, fixture.Descriptor.Token);
            Assert.AreEqual(0, fixture.PublishedWindows);
            Assert.AreEqual(0, fixture.Count);
            Assert.AreEqual(phase == "Fallback" ? 0 : 1, fixture.Native.Window.Disposals);
            Assert.AreEqual(0, fixture.Native.MemoryOperationOverlaps);
            if (cleanupFails)
            {
                Assert.IsInstanceOfType<InvalidOperationException>(disconnectFailure);
                Assert.AreEqual(1, fixture.Native.OwnedMemoryCount);
                fixture.Native.DeregisterStatus = NtStatus.STATUS_SUCCESS;
                fixture.Endpoint.Disconnect();
                Assert.AreEqual(3, fixture.Native.Deregistrations);
            }
            else
            {
                Assert.IsNull(disconnectFailure);
                Assert.AreEqual(1, fixture.Native.Deregistrations);
            }
            Assert.AreEqual(0, fixture.Native.OwnedMemoryCount);
            Assert.IsTrue(fixture.HasLog(message => message.Contains("shutdown") ||
                message.Contains("disconnected")), "The denied publication must be explicit in diagnostics.");
        }

        [DataTestMethod]
        [TestCategory("PrincipalFollowup")]
        [DataRow(false)]
        [DataRow(true)]
        public void PublicationWinningShutdownKeepsExplicitDescriptorOwnership(bool fallback)
        {
            using var fixture = new Fixture();
            using var published = new ManualResetEventSlim();
            using var resume = new ManualResetEventSlim();
            fixture.Native.RejectMemoryOperationOverlap = true;
            if (fallback) fixture.Native.WindowStatus = NtStatus.STATUS_NOT_SUPPORTED;
            fixture.OnPublicationLog = () => WaitAtBarrier(published, resume);
            Task<NtStatus> registration = Task.Run(() =>
                fixture.Endpoint.RegisterMemoryWindow(16, 0, false, out fixture.Descriptor));
            Task<Exception> disconnect = null;
            try
            {
                if (!fallback)
                {
                    Assert.IsTrue(fixture.Native.BindSubmitted.Wait(3000));
                    fixture.Native.CompleteBind(NtStatus.STATUS_SUCCESS);
                }
                Assert.IsTrue(published.Wait(3000));
                Assert.AreEqual(1, fixture.PublishedWindows);
                disconnect = Task.Run(() => CaptureDisconnect(fixture.Endpoint));
                Assert.IsTrue(fixture.Native.Disconnected.Wait(3000));
            }
            finally
            {
                resume.Set();
            }
            Assert.AreEqual(NtStatus.STATUS_SUCCESS, registration.GetAwaiter().GetResult());
            Assert.IsNull(disconnect.GetAwaiter().GetResult());
            Assert.AreEqual(fallback ? 88u : 77u, fixture.Descriptor.Token);
            Assert.AreEqual(16u, fixture.Descriptor.Length);
            Assert.AreEqual(1, fixture.PublishedWindows);
            Assert.AreEqual(1, fixture.Native.OwnedMemoryCount,
                "A descriptor published first remains explicitly owned until its caller deregisters it.");
            fixture.Native.InvalidateStatus = NtStatus.STATUS_CONNECTION_DISCONNECTED;
            fixture.Endpoint.DeregisterMemoryWindow(fixture.Descriptor);
            Assert.AreEqual(0, fixture.PublishedWindows);
            Assert.AreEqual(0, fixture.Native.OwnedMemoryCount);
            Assert.AreEqual(fallback ? 0 : 1, fixture.Native.Window.Disposals);
            Assert.AreEqual(1, fixture.Native.Deregistrations);
            Assert.AreEqual(0, fixture.Native.MemoryOperationOverlaps);
            Assert.AreEqual(0, fixture.Count);
        }

        [TestMethod]
        [TestCategory("PrincipalFollowup")]
        public void NativeRegistrationFailurePreservesStatusWithoutPublishingOrBinding()
        {
            using var fixture = new Fixture();
            fixture.Native.RejectMemoryOperationOverlap = true;
            fixture.Native.RegisterStatus = NtStatus.STATUS_ACCESS_DENIED;
            Assert.AreEqual(NtStatus.STATUS_ACCESS_DENIED,
                fixture.Endpoint.RegisterMemoryWindow(16, 0, false, out fixture.Descriptor));
            Assert.IsFalse(fixture.Native.BindSubmitted.IsSet);
            Assert.AreEqual(0, fixture.PublishedWindows);
            Assert.AreEqual(0, fixture.Native.OwnedMemoryCount);
            Assert.AreEqual(0, fixture.Native.Deregistrations);
            Assert.AreEqual(0, fixture.Count);
            fixture.Endpoint.Disconnect();
        }

        [TestMethod]
        [TestCategory("PrincipalFollowup")]
        public void BlockedNativeRegistrationFailsDisconnectBoundedlyThenReclaimsOnResume()
        {
            using var fixture = new Fixture();
            using var entered = new ManualResetEventSlim();
            using var resume = new ManualResetEventSlim();
            fixture.Native.OnRegisterMemory = () => WaitAtBarrier(entered, resume);
            Task<NtStatus> registration = Task.Run(() =>
                fixture.Endpoint.RegisterMemoryWindow(16, 0, false, out fixture.Descriptor));
            Exception disconnectFailure;
            try
            {
                Assert.IsTrue(entered.Wait(3000));
                Task<Exception> disconnect = Task.Run(() => CaptureDisconnect(fixture.Endpoint));
                Assert.IsTrue(fixture.Native.Disconnected.Wait(3000));
                Assert.IsTrue(disconnect.Wait(7000), "An in-flight registration must not hold the shutdown-state lock.");
                disconnectFailure = disconnect.GetAwaiter().GetResult();
            }
            finally
            {
                resume.Set();
            }
            NtStatus registrationStatus = registration.GetAwaiter().GetResult();
            Assert.IsInstanceOfType<TimeoutException>(disconnectFailure,
                "Incomplete native registration must cause an explicit bounded drain failure, not successful disposal.");
            Assert.AreEqual(NtStatus.STATUS_CONNECTION_DISCONNECTED, registrationStatus);
            Assert.AreEqual(0, fixture.PublishedWindows);
            Assert.AreEqual(0, fixture.Native.OwnedMemoryCount);
            Assert.AreEqual(1, fixture.Native.Deregistrations);
            fixture.Endpoint.Disconnect();
        }

        private static void WaitAtBarrier(ManualResetEventSlim entered, ManualResetEventSlim resume)
        {
            entered.Set();
            if (!resume.Wait(15000)) throw new TimeoutException("Controlled native operation was not resumed.");
        }

        private static Exception CaptureDisconnect(SmbdConnectionEndpoint endpoint)
        {
            try { endpoint.Disconnect(); return null; }
            catch (Exception ex) { return ex; }
        }

        private sealed class Fixture : IDisposable
        {
            internal readonly NativeDouble Native = new NativeDouble();
            internal readonly SmbdConnectionEndpoint Endpoint = new SmbdConnectionEndpoint(0, 16, 1, 1, 0, 0, 16);
            private readonly Thread callback;
            internal Action OnTimeoutLog;
            internal Action OnPublicationLog;
            private readonly System.Collections.Generic.List<string> Logs = new System.Collections.Generic.List<string>();
            internal RdmaBufferDescriptor Descriptor;
            internal int Count => (int)Get("requestCount");
            internal int PublishedWindows => ((System.Collections.ICollection)Get("memoryWindowList")).Count;
            internal SyncFilterQueue<SmbdRequestResult> Results => (SyncFilterQueue<SmbdRequestResult>)Get("otherRequestResult");

            internal Fixture()
            {
                Set("rdmaAdapter", Native);
                Set("rdmaEndpoint", Native);
                Set("rdmaCompletionQueue", Native);
                Set("rdmaConnector", Native);
                Set("isConnected", true);
                Set("threadStartSemaphore", new Semaphore(0, 2));
                Set("logEndpointEvent", (SmbdLogEvent)(message =>
                {
                    lock (Logs) Logs.Add(message);
                    if (message.StartsWith("RegisterMemoryWindow: Timed out"))
                    {
                        OnTimeoutLog?.Invoke();
                    }
                    if (message.StartsWith("RegisterMemoryWindow: returning"))
                    {
                        OnPublicationLog?.Invoke();
                    }
                }));
                callback = new Thread(() => typeof(SmbdConnectionEndpoint)
                    .GetMethod("NotifyCallback", BindingFlags.Instance | BindingFlags.NonPublic)
                    .Invoke(Endpoint, new object[] { null })) { IsBackground = true };
                callback.Start();
            }

            internal Task<NtStatus> Register()
            {
                var call = Task.Run(() => Endpoint.RegisterMemoryWindow(16, 0, false, out Descriptor));
                Assert.IsTrue(Native.BindSubmitted.Wait(3000), "Bind was not submitted.");
                return call;
            }

            internal void WaitForDrain() =>
                Assert.IsTrue(((ManualResetEventSlim)Get("bindsDrained")).Wait(3000));

            internal bool HasLog(Predicate<string> predicate)
            {
                lock (Logs) return Logs.Exists(predicate);
            }

            internal void ConfigureReceive()
            {
                Set("inboundEntries", 1u);
                Set("receiveEntries", new[]
                {
                    new ReceiveEntry { Segment = new NdSegment { Length = 16, MemoryHandler = 55 } }
                });
            }

            private object Get(string name) => typeof(SmbdConnectionEndpoint)
                .GetField(name, BindingFlags.Instance | BindingFlags.NonPublic).GetValue(Endpoint);
            private void Set(string name, object value) => typeof(SmbdConnectionEndpoint)
                .GetField(name, BindingFlags.Instance | BindingFlags.NonPublic).SetValue(Endpoint, value);

            public void Dispose()
            {
                // Baseline assertions can fail with outstanding fake work. Teardown must not mask that failure.
                Set("isConnected", false);
                Set("requestCount", 0);
                ((Semaphore)Get("rdmaNotificationSemaphore")).Release();
                Native.Notified.Set();
                Assert.IsTrue(callback.Join(3000), "Completion callback failed to stop.");
            }
        }
    }
}

internal sealed class WindowDouble : INativeRdmaMemoryWindow
{
    internal int Disposals;
    internal Action OnRemoteToken;
    public uint RemoteToken { get { OnRemoteToken?.Invoke(); return 77; } }
    public void Dispose() => Interlocked.Increment(ref Disposals);
}

internal sealed class NativeDouble : INativeRdmaService, INativeRdmaAdapter, INativeRdmaEndpoint, INativeRdmaCompletionQueue, INativeRdmaConnector
{
    internal readonly ManualResetEventSlim Flushed = new ManualResetEventSlim();
    public int Flush() { Flushed.Set(); return (int)FlushStatus; }
    internal readonly WindowDouble Window = new WindowDouble();
    internal readonly ManualResetEventSlim BindSubmitted = new ManualResetEventSlim();
    internal readonly ManualResetEventSlim SendSubmitted = new ManualResetEventSlim();
    internal readonly ManualResetEventSlim Disconnected = new ManualResetEventSlim();
    internal readonly ManualResetEventSlim NotificationObserved = new ManualResetEventSlim();
    internal readonly ManualResetEventSlim DeregisterEntered = new ManualResetEventSlim();
    internal readonly ManualResetEventSlim OverlapObserved = new ManualResetEventSlim();
    internal readonly AutoResetEvent Notified = new AutoResetEvent(false);
    private readonly ConcurrentQueue<(ulong Id, NdResult Result)> completions = new ConcurrentQueue<(ulong, NdResult)>();
    internal NtStatus SubmitStatus;
    internal NtStatus DeregisterStatus;
    internal NtStatus FlushStatus;
    internal NtStatus WindowStatus;
    internal NtStatus MemoryDescriptionStatus;
    internal NtStatus RegisterStatus;
    internal NtStatus InvalidateStatus;
    internal Action OnRegisterMemory;
    internal Action OnGetRegisteredMemory;
    internal Action OnCreateMemoryWindow;
    internal bool RejectMemoryOperationOverlap;
    internal int MemoryOperationOverlaps;
    internal int SendCalls;
    private int memoryOperations;
    private readonly ConcurrentDictionary<ulong, uint> ownedMemory = new ConcurrentDictionary<ulong, uint>();
    internal int OwnedMemoryCount => ownedMemory.Count;
    internal int Deregistrations;
    internal int Registrations;
    internal int WindowCreations;
    internal RdmaReadWriteFlag RegisteredPermissions;
    internal RdmaReadWriteFlag BoundPermissions;
    internal int Drained;
    internal void CompleteBind(NtStatus status) => Complete(100, status);
    internal void Complete(ulong id, NtStatus status)
    {
        completions.Enqueue((id, new NdResult { Status = (int)status }));
        Notified.Set();
    }
    public int Notify() { Notified.WaitOne(); NotificationObserved.Set(); return 0; }
    public ulong GetResult(out ulong resultHandler, out NdResult requestResult)
    {
        if (completions.TryDequeue(out var item))
        {
            Interlocked.Increment(ref Drained);
            resultHandler = item.Id;
            requestResult = item.Result;
            return 1;
        }
        resultHandler = 0;
        requestResult = default;
        return 0;
    }
    public int Bind(ulong memoryHandler, INativeRdmaMemoryWindow window, RdmaReadWriteFlag flag,
        bool reverse, out RdmaBufferDescriptor descriptor, out ulong resultHandler)
    {
        descriptor = new RdmaBufferDescriptor { Length = 16 };
        BoundPermissions = flag;
        resultHandler = 100;
        BindSubmitted.Set();
        return (int)SubmitStatus;
    }
    public int RegisterMemory(uint size, out ulong handler)
        => RegisterMemory(size, RdmaReadWriteFlag.ReadAndWrite, out handler);
    public int RegisterMemory(uint size, RdmaReadWriteFlag flag, out ulong handler)
    {
        RegisteredPermissions = flag;
        handler = 0;
        int registration = Interlocked.Increment(ref Registrations);
        bool overlap = EnterMemoryOperation();
        try
        {
            if (overlap) return unchecked((int)NtStatus.STATUS_DEVICE_BUSY);
            OnRegisterMemory?.Invoke();
            if (RegisterStatus != NtStatus.STATUS_SUCCESS) return (int)RegisterStatus;
            handler = (ulong)(42 + registration);
            ownedMemory.TryAdd(handler, size);
            return 0;
        }
        finally { Interlocked.Decrement(ref memoryOperations); }
    }
    public int DeregisterMemory(ulong handler)
    {
        Interlocked.Increment(ref Deregistrations);
        DeregisterEntered.Set();
        bool overlap = EnterMemoryOperation();
        try
        {
            if (overlap) return unchecked((int)NtStatus.STATUS_DEVICE_BUSY);
            if (DeregisterStatus == NtStatus.STATUS_SUCCESS) ownedMemory.TryRemove(handler, out _);
            return (int)DeregisterStatus;
        }
        finally { Interlocked.Decrement(ref memoryOperations); }
    }
    private bool EnterMemoryOperation()
    {
        if (Interlocked.Increment(ref memoryOperations) == 1 || !RejectMemoryOperationOverlap) return false;
        Interlocked.Increment(ref MemoryOperationOverlaps);
        OverlapObserved.Set();
        return true;
    }
    public int CreateMemoryWindow(ulong result, out INativeRdmaMemoryWindow window)
    {
        Interlocked.Increment(ref WindowCreations);
        OnCreateMemoryWindow?.Invoke();
        window = WindowStatus == NtStatus.STATUS_SUCCESS ? Window : null;
        return (int)WindowStatus;
    }
    public int LoadProviders(out INativeRdmaProviderInfo[] providers) { providers = Array.Empty<INativeRdmaProviderInfo>(); return 0; }
    public int WriteToMemory(ulong handler, byte[] buffer) => 0;
    public int ReadFromMemory(ulong handler, byte[] buffer) => 0;
    public int Query(out NdAdapterInfo info) { info = null; return 0; }
    public int CreateCompletionQueue(uint size, out INativeRdmaCompletionQueue queue) { queue = this; return 0; }
    public int CreateConnector(out INativeRdmaConnector connector) => throw new NotSupportedException();
    public int GetRegisteredMemory(ulong handler, out RdmaRegisteredMemory memory)
    {
        OnGetRegisteredMemory?.Invoke();
        memory = new RdmaRegisteredMemory { Address = 0x1000, RemoteToken = 88, Length = ownedMemory[handler] };
        return (int)MemoryDescriptionStatus;
    }
    public int Listen(int protocol, ushort port, out INativeRdmaListen listen) => throw new NotSupportedException();
    public int Send(NdSegment[] segments, out ulong handler) { handler = (ulong)(299 + Interlocked.Increment(ref SendCalls)); SendSubmitted.Set(); return 0; }
    public int Receive(NdSegment[] segments, out ulong handler) { handler = 400; return 0; }
    public int Invalidate(INativeRdmaMemoryWindow window, out ulong handler) { handler = 200; return (int)InvalidateStatus; }
    public int CreateEndpoint(INativeRdmaCompletionQueue queue, uint inbound, uint outbound,
        uint inboundSegment, uint outboundSegment, uint inboundRead, uint outboundRead,
        out uint maxInlineData, out INativeRdmaEndpoint endpoint) => throw new NotSupportedException();
    public int Connect(INativeRdmaEndpoint endpoint, string address, int port, int protocol) => 0;
    public int CompleteConnect() => 0;
    public int Accept(INativeRdmaEndpoint endpoint) => 0;
    public int NotifyDisconnect() => 0;
    public void Disconnect() { Disconnected.Set(); }
}
