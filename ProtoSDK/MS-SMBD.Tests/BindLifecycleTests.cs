// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Reflection;
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

        private sealed class Fixture : IDisposable
        {
            internal readonly NativeDouble Native = new NativeDouble();
            internal readonly SmbdConnectionEndpoint Endpoint = new SmbdConnectionEndpoint(0, 16, 1, 1, 0, 0, 16);
            private readonly Thread callback;
            internal Action OnTimeoutLog;
            internal RdmaBufferDescriptor Descriptor;
            internal int Count => (int)Get("requestCount");
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
                    if (message.StartsWith("RegisterMemoryWindow: Timed out"))
                    {
                        OnTimeoutLog?.Invoke();
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
    public uint RemoteToken => 77;
    public void Dispose() => Interlocked.Increment(ref Disposals);
}

internal sealed class NativeDouble : INativeRdmaService, INativeRdmaAdapter, INativeRdmaEndpoint, INativeRdmaCompletionQueue, INativeRdmaConnector
{
    internal readonly ManualResetEventSlim Flushed = new ManualResetEventSlim();
    public int Flush() { Flushed.Set(); return (int)FlushStatus; }
    internal readonly WindowDouble Window = new WindowDouble();
    internal readonly ManualResetEventSlim BindSubmitted = new ManualResetEventSlim();
    internal readonly ManualResetEventSlim SendSubmitted = new ManualResetEventSlim();
    internal readonly AutoResetEvent Notified = new AutoResetEvent(false);
    private readonly ConcurrentQueue<(ulong Id, NdResult Result)> completions = new ConcurrentQueue<(ulong, NdResult)>();
    internal NtStatus SubmitStatus;
    internal NtStatus DeregisterStatus;
    internal NtStatus FlushStatus;
    internal NtStatus WindowStatus;
    internal NtStatus MemoryDescriptionStatus;
    internal int Deregistrations;
    internal int Registrations;
    internal int Drained;
    internal void CompleteBind(NtStatus status) => Complete(100, status);
    internal void Complete(ulong id, NtStatus status)
    {
        completions.Enqueue((id, new NdResult { Status = (int)status }));
        Notified.Set();
    }
    public int Notify() { Notified.WaitOne(); return 0; }
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
        resultHandler = 100;
        BindSubmitted.Set();
        return (int)SubmitStatus;
    }
    public int RegisterMemory(uint size, out ulong handler) { Interlocked.Increment(ref Registrations); handler = 42; return 0; }
    public int DeregisterMemory(ulong handler) { Interlocked.Increment(ref Deregistrations); return (int)DeregisterStatus; }
    public int CreateMemoryWindow(ulong result, out INativeRdmaMemoryWindow window)
    {
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
        memory = default;
        return (int)MemoryDescriptionStatus;
    }
    public int Listen(int protocol, ushort port, out INativeRdmaListen listen) => throw new NotSupportedException();
    public int Send(NdSegment[] segments, out ulong handler) { handler = 300; SendSubmitted.Set(); return 0; }
    public int Receive(NdSegment[] segments, out ulong handler) { handler = 400; return 0; }
    public int Invalidate(INativeRdmaMemoryWindow window, out ulong handler) { handler = 200; return 0; }
    public int CreateEndpoint(INativeRdmaCompletionQueue queue, uint inbound, uint outbound,
        uint inboundSegment, uint outboundSegment, uint inboundRead, uint outboundRead,
        out uint maxInlineData, out INativeRdmaEndpoint endpoint) => throw new NotSupportedException();
    public int Connect(INativeRdmaEndpoint endpoint, string address, int port, int protocol) => 0;
    public int CompleteConnect() => 0;
    public int Accept(INativeRdmaEndpoint endpoint) => 0;
    public int NotifyDisconnect() => 0;
    public void Disconnect() { }
}
