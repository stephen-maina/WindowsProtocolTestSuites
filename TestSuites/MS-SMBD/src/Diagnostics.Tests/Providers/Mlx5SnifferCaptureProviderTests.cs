// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Protocols.TestSuites.Diagnostics.Identity;
using Microsoft.Protocols.TestSuites.Diagnostics.Evidence;
using Microsoft.Protocols.TestSuites.Diagnostics.Providers;
using Microsoft.Protocols.TestSuites.Diagnostics.Storage;
using Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.TestSupport;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.Providers;

[TestClass]
public sealed class Mlx5SnifferCaptureProviderTests
{
    private const string ToolPath = @"C:\Tools\Mlx5Cmd.exe";
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(5);

    [DataTestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task StartAsync_IndeterminateNativeStart_BlocksReuseWithoutClaimingOwnership(bool cancelled)
    {
        using var context = SnifferContext.Create("192.168.10.12");
        var runner = new FakeSnifferRunner(context.OutputPath)
        {
            CommandHandler = (info, _) => info.ArgumentList.Contains("-start")
                ? Task.FromResult(cancelled ? ProcessCommandResult.Cancelled(true)
                    : ProcessCommandResult.TimedOut(true)) : null,
        };
        Mlx5SnifferCaptureProvider provider = CreateProvider(runner);
        CaptureProviderStartResult result = await provider.StartAsync(context.Request, default);
        int commands = runner.Commands.Count;
        CaptureProviderStartResult retry = await provider.StartAsync(context.Request, default);

        Assert.IsFalse(result.IsStarted);
        Assert.IsFalse(result.WriterResolved);
        Assert.IsNull(result.Handle);
        Assert.AreEqual(CaptureProviderFailureCode.CaptureBusy, retry.FailureCode);
        Assert.AreEqual(commands, runner.Commands.Count);
        Assert.IsFalse(runner.Commands.Any(command => command.EndsWith("-stop")));
    }

    [TestMethod]
    public async Task StartStopFinalize_SequentialInvocations_ReusesAdapterWithAddressableWriters()
    {
        using var first = SnifferContext.Create("192.168.10.12");
        using var second = SnifferContext.Create("192.168.10.12", "attempt-2");
        var runner = new FakeSnifferRunner(first.OutputPath);
        Mlx5SnifferCaptureProvider provider = CreateProvider(runner);
        CaptureProviderStartResult old = await provider.StartAsync(first.Request, default);
        Assert.IsTrue(old.IsStarted);
        Assert.IsTrue((await provider.RequestStopAsync(old.Handle!, default)).WriterResolved);

        CaptureProviderStartResult next = await provider.StartAsync(second.Request, default);
        CaptureProviderStopResult stopped = await provider.RequestStopAsync(next.Handle!, default);
        CaptureProviderFinalizationResult finalized =
            await provider.WaitForFinalizationAsync(next.Handle!, default);

        Assert.IsTrue(next.IsStarted, next.Detail);
        Assert.AreEqual(CaptureProviderStopStatus.Stopped, stopped.Status);
        Assert.AreEqual(CaptureProviderFinalizationStatus.Finalized, finalized.Status);
        Assert.IsTrue(finalized.CollectionComplete);
        Assert.AreEqual(new FileInfo(second.OutputPath).Length, finalized.Artifacts.Single().ByteCount);
        Assert.AreEqual(2, runner.Commands.Count(command => command.Contains("-start")));
        Assert.AreEqual(2, runner.Commands.Count(command => command.EndsWith("-stop")));
    }

    [TestMethod]
    public async Task StartAsync_DuplicateDuringPreflight_RejectsBeforeAnyAdditionalNativeCommand()
    {
        using var context = SnifferContext.Create("192.168.10.12");
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<ProcessCommandResult>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        int queries = 0;
        var runner = new FakeSnifferRunner(context.OutputPath)
        {
            CommandHandler = (info, _) =>
            {
                if (info.ArgumentList.Contains("-query") && Interlocked.Increment(ref queries) == 1)
                {
                    entered.SetResult();
                    return release.Task;
                }
                return null;
            },
        };
        Mlx5SnifferCaptureProvider provider = CreateProvider(runner);
        Task<CaptureProviderStartResult> first = provider.StartAsync(context.Request, default);
        CaptureProviderStartResult? duplicate = null;
        int commandsBeforeRelease = 0;
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            duplicate = await provider.StartAsync(context.Request, default);
            commandsBeforeRelease = runner.Commands.Count;
        }
        finally
        {
            release.TrySetResult(ProcessCommandResult.Completed(0, "Sniffer is not running."));
            CaptureProviderStartResult started = await first.WaitAsync(TimeSpan.FromSeconds(5));
            if (started.Handle is not null)
            {
                await provider.RequestStopAsync(started.Handle, default);
            }
            if (duplicate?.Handle is not null)
            {
                await provider.RequestStopAsync(duplicate.Handle, default);
            }
        }

        Assert.IsNotNull(duplicate);
        Assert.IsFalse(duplicate.IsStarted);
        Assert.IsNull(duplicate.Handle);
        Assert.AreEqual(CaptureProviderFailureCode.CaptureBusy, duplicate.FailureCode);
        Assert.AreEqual(1, commandsBeforeRelease, "Duplicate admission must not query or start the adapter.");
    }

    [TestMethod]
    public async Task StopAsync_StaleHandleAfterReuse_CannotControlNewWriter()
    {
        using var first = SnifferContext.Create("192.168.10.12");
        using var second = SnifferContext.Create("192.168.10.12", "attempt-2");
        var runner = new FakeSnifferRunner(first.OutputPath);
        Mlx5SnifferCaptureProvider provider = CreateProvider(runner);
        CaptureProviderStartResult old = await provider.StartAsync(first.Request, default);
        await provider.RequestStopAsync(old.Handle!, default);
        CaptureProviderStartResult next = await provider.StartAsync(second.Request, default);
        int commandsBeforeStaleStop = runner.Commands.Count;

        CaptureProviderStopResult stale = await provider.RequestStopAsync(old.Handle!, default);
        int commandsAfterStaleStop = runner.Commands.Count;
        CaptureProviderStopResult current = await provider.RequestStopAsync(next.Handle!, default);

        Assert.AreEqual(CaptureProviderFailureCode.OwnershipMismatch, stale.FailureCode);
        Assert.AreEqual(commandsBeforeStaleStop, commandsAfterStaleStop);
        Assert.IsTrue(next.IsStarted);
        Assert.AreEqual(CaptureProviderStopStatus.Stopped, current.Status);
    }

    [TestMethod]
    public async Task StopAsync_UnresolvedWriter_BlocksReuseUntilSuccessfulRetry()
    {
        using var context = SnifferContext.Create("192.168.10.12");
        int stops = 0;
        var runner = new FakeSnifferRunner(context.OutputPath)
        {
            CommandHandler = (info, _) =>
                info.ArgumentList.Contains("-stop") && Interlocked.Increment(ref stops) == 1
                    ? Task.FromResult(ProcessCommandResult.TimedOut(true))
                    : null,
        };
        Mlx5SnifferCaptureProvider provider = CreateProvider(runner);
        CaptureProviderStartResult first = await provider.StartAsync(context.Request, default);
        CaptureProviderStopResult unresolved = await provider.RequestStopAsync(first.Handle!, default);
        int commandsBeforeDuplicate = runner.Commands.Count;
        CaptureProviderStartResult duplicate = await provider.StartAsync(context.Request, default);
        int commandsAfterDuplicate = runner.Commands.Count;
        CaptureProviderStopResult retry = await provider.RequestStopAsync(first.Handle!, default);
        CaptureProviderStartResult next = await provider.StartAsync(context.Request, default);
        CaptureProviderStopResult final = await provider.RequestStopAsync(next.Handle!, default);

        Assert.IsFalse(unresolved.WriterResolved);
        Assert.AreEqual(CaptureProviderFailureCode.StopTimeout, unresolved.FailureCode);
        Assert.AreEqual(CaptureProviderFailureCode.CaptureBusy, duplicate.FailureCode);
        Assert.IsNull(duplicate.Handle);
        Assert.AreEqual(commandsBeforeDuplicate, commandsAfterDuplicate);
        Assert.IsTrue(retry.WriterResolved);
        Assert.IsTrue(next.IsStarted);
        Assert.IsTrue(final.WriterResolved);
    }

    [DataTestMethod]
    [DataRow("-query")]
    [DataRow("-start")]
    public async Task StartAsync_NativeFailure_ReleasesReservationForRetry(string operation)
    {
        using var context = SnifferContext.Create("192.168.10.12");
        int attempts = 0;
        var runner = new FakeSnifferRunner(context.OutputPath)
        {
            CommandHandler = (info, _) =>
                info.ArgumentList.Contains(operation) && Interlocked.Increment(ref attempts) == 1
                    ? Task.FromResult(operation == "-query"
                        ? ProcessCommandResult.StartFailed()
                        : ProcessCommandResult.Completed(1, "", "controlled failure"))
                    : null,
        };
        Mlx5SnifferCaptureProvider provider = CreateProvider(runner);

        CaptureProviderStartResult failure = await provider.StartAsync(context.Request, default);
        CaptureProviderStartResult retry = await provider.StartAsync(context.Request, default);
        CaptureProviderStopResult stopped = await provider.RequestStopAsync(retry.Handle!, default);

        Assert.IsFalse(failure.IsStarted);
        Assert.IsNull(failure.Handle);
        Assert.IsTrue(retry.IsStarted);
        Assert.IsTrue(stopped.WriterResolved);
    }

    [TestMethod]
    public async Task StartAsync_SecondInvocation_EnforcesItsOwnDurationAndIgnoresOldTimer()
    {
        using var first = SnifferContext.Create("192.168.10.12");
        using var second = SnifferContext.Create("192.168.10.12", "attempt-2");
        var oldDelay = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var newDelay = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var durationStop = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var durations = new List<TimeSpan>();
        int stops = 0;
        var runner = new FakeSnifferRunner(first.OutputPath)
        {
            CommandHandler = (info, _) =>
            {
                if (info.ArgumentList.Contains("-stop") && Interlocked.Increment(ref stops) == 2)
                {
                    durationStop.TrySetResult();
                }
                return null;
            },
        };
        var provider = new Mlx5SnifferCaptureProvider(
            ToolPath, CommandTimeout, runner, _ => "Ethernet",
            (duration, _) =>
            {
                durations.Add(duration);
                return durations.Count == 1 ? oldDelay.Task : newDelay.Task;
            });
        CaptureProviderStartResult old = await provider.StartAsync(first.Request, default);
        await provider.RequestStopAsync(old.Handle!, default);
        CaptureProviderStartResult next = await provider.StartAsync(second.Request, default);
        oldDelay.SetResult();
        newDelay.SetResult();
        bool stoppedByDuration;
        try
        {
            stoppedByDuration = await Task.WhenAny(durationStop.Task, Task.Delay(1000)) == durationStop.Task;
        }
        finally
        {
            await provider.RequestStopAsync(next.Handle!, default);
        }
        CaptureProviderFinalizationResult finalized =
            await provider.WaitForFinalizationAsync(next.Handle!, default);

        Assert.IsTrue(next.IsStarted);
        Assert.AreEqual(CaptureProviderFinalizationStatus.Finalized, finalized.Status);
        Assert.IsFalse(finalized.CollectionComplete);
        CollectionAssert.AreEqual(
            new[] { first.Request.MaxDuration, second.Request.MaxDuration }, durations);
        Assert.IsTrue(stoppedByDuration, "The second writer must stop without explicit cleanup.");
        Assert.AreEqual(2, runner.Commands.Count(command => command.EndsWith("-stop")));
        Assert.AreEqual(CaptureProviderHealthStatus.ExitedEarly,
            (await provider.ObserveHealthAsync(next.Handle!, default)).Status);
    }

    [TestMethod]
    public async Task StartStopFinalize_RunsSnifferCommandsAndRecordsPcap()
    {
        using var context = SnifferContext.Create("192.168.10.12");
        var runner = new FakeSnifferRunner(context.OutputPath);
        Mlx5SnifferCaptureProvider provider = CreateProvider(runner);

        CaptureProviderProbeResult probe =
            await provider.ProbeAsync(context.Request, CancellationToken.None);
        CaptureProviderStartResult start =
            await provider.StartAsync(context.Request, CancellationToken.None);
        Assert.IsTrue(start.IsStarted);
        CaptureProviderReadinessResult ready =
            await provider.WaitForReadinessAsync(start.Handle!, CancellationToken.None);
        CaptureProviderStopResult stop =
            await provider.RequestStopAsync(start.Handle!, CancellationToken.None);
        CaptureProviderFinalizationResult final =
            await provider.WaitForFinalizationAsync(start.Handle!, CancellationToken.None);

        Assert.IsTrue(probe.IsAvailable);
        Assert.AreEqual(CaptureProviderReadinessStatus.Ready, ready.Status);
        Assert.AreEqual(CaptureProviderStopStatus.Stopped, stop.Status);
        Assert.AreEqual(CaptureProviderFinalizationStatus.Finalized, final.Status);
        Assert.AreEqual(1, final.Artifacts.Count);
        Assert.AreEqual("rdma.pcap", final.Artifacts[0].RelativePath);
        Assert.AreEqual(
            "-Sniffer -Name Ethernet -start -filename " + context.OutputPath +
                " -limit_file_size 8",
            runner.Commands.First(c => c.Contains("-start")));
        Assert.IsTrue(runner.Commands.Any(c => c == "-Sniffer -Name Ethernet -stop"));
    }

    [TestMethod]
    public async Task Probe_ReportsUnavailable_WhenToolOrAdapterMissing()
    {
        using var context = SnifferContext.Create("192.168.10.12");
        var missingTool = new FakeSnifferRunner(context.OutputPath)
        {
            ExecutableAvailable = false,
        };
        CaptureProviderProbeResult toolResult =
            await CreateProvider(missingTool)
                .ProbeAsync(context.Request, CancellationToken.None);

        var runner = new FakeSnifferRunner(context.OutputPath);
        var noAdapter = new Mlx5SnifferCaptureProvider(
            ToolPath,
            CommandTimeout,
            runner,
            _ => null,
            (_, token) => Task.Delay(Timeout.Infinite, token));
        CaptureProviderProbeResult adapterResult =
            await noAdapter.ProbeAsync(context.Request, CancellationToken.None);

        Assert.IsFalse(toolResult.IsAvailable);
        Assert.AreEqual(CaptureProviderFailureCode.ToolMissing, toolResult.FailureCode);
        Assert.IsFalse(adapterResult.IsAvailable);
        Assert.AreEqual(0, runner.Commands.Count);
    }

    [TestMethod]
    public async Task Finalize_Fails_WhenPcapIsEmpty()
    {
        using var context = SnifferContext.Create("192.168.10.12");
        var runner = new FakeSnifferRunner(context.OutputPath) { PcapBytes = 0 };
        Mlx5SnifferCaptureProvider provider = CreateProvider(runner);

        CaptureProviderStartResult start =
            await provider.StartAsync(context.Request, CancellationToken.None);
        await provider.RequestStopAsync(start.Handle!, CancellationToken.None);
        CaptureProviderFinalizationResult final =
            await provider.WaitForFinalizationAsync(start.Handle!, CancellationToken.None);

        Assert.AreEqual(CaptureProviderFinalizationStatus.Failed, final.Status);
    }

    [TestMethod]
    public async Task Auxiliary_AddsSnifferArtifactToPrimaryResult()
    {
        using var context = SnifferContext.Create("192.168.10.12");
        var runner = new FakeSnifferRunner(context.OutputPath);
        var primary = new FakePrimaryProvider();
        var composite = new AuxiliaryCaptureProvider(primary, CreateProvider(runner));

        CaptureProviderStartResult start =
            await composite.StartAsync(context.Request, CancellationToken.None);
        await composite.WaitForReadinessAsync(start.Handle!, CancellationToken.None);
        CaptureProviderStopResult stop =
            await composite.RequestStopAsync(start.Handle!, CancellationToken.None);
        CaptureProviderFinalizationResult final =
            await composite.WaitForFinalizationAsync(start.Handle!, CancellationToken.None);

        Assert.AreEqual("Primary", composite.ProviderId);
        Assert.AreEqual(CaptureProviderStopStatus.Stopped, stop.Status);
        CollectionAssert.AreEqual(
            new[] { "capture.etl", "rdma.pcap" },
            final.Artifacts.Select(a => a.RelativePath).ToArray());
    }

    [TestMethod]
    public async Task Auxiliary_IgnoresUnavailableSniffer()
    {
        using var context = SnifferContext.Create("192.168.10.12");
        var runner = new FakeSnifferRunner(context.OutputPath)
        {
            ExecutableAvailable = false,
        };
        var composite = new AuxiliaryCaptureProvider(
            new FakePrimaryProvider(),
            CreateProvider(runner));

        CaptureProviderStartResult start =
            await composite.StartAsync(context.Request, CancellationToken.None);
        await composite.RequestStopAsync(start.Handle!, CancellationToken.None);
        CaptureProviderFinalizationResult final =
            await composite.WaitForFinalizationAsync(start.Handle!, CancellationToken.None);

        Assert.IsTrue(start.IsStarted);
        Assert.AreEqual(CaptureProviderFinalizationStatus.Finalized, final.Status);
        CollectionAssert.AreEqual(
            new[] { "capture.etl" },
            final.Artifacts.Select(a => a.RelativePath).ToArray());
    }

    private static Mlx5SnifferCaptureProvider CreateProvider(
        FakeSnifferRunner runner)
    {
        return new Mlx5SnifferCaptureProvider(
            ToolPath,
            CommandTimeout,
            runner,
            _ => "Ethernet",
            (_, _) => Task.Delay(Timeout.Infinite));
    }

    private sealed class FakeSnifferRunner : IProcessCommandRunner
    {
        private string outputPath;
        private bool running;

        internal FakeSnifferRunner(string outputPath)
        {
            this.outputPath = outputPath;
        }

        internal bool ExecutableAvailable { get; set; } = true;

        internal int PcapBytes { get; set; } = 64;

        internal ConcurrentQueue<string> Commands { get; } = new();

        internal Func<ProcessStartInfo, CancellationToken, Task<ProcessCommandResult>?>? CommandHandler { get; set; }

        public bool ExecutableExists(string executablePath) => ExecutableAvailable;

        public Task<ProcessCommandResult> RunAsync(
            ProcessStartInfo startInfo,
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            string command = string.Join(' ', startInfo.ArgumentList);
            Commands.Enqueue(command);
            Task<ProcessCommandResult>? controlled = CommandHandler?.Invoke(startInfo, cancellationToken);
            if (controlled is not null)
            {
                return controlled;
            }

            if (command.Contains("-start"))
            {
                running = true;
                outputPath = startInfo.ArgumentList[startInfo.ArgumentList.IndexOf("-filename") + 1];
                File.WriteAllBytes(outputPath, new byte[PcapBytes]);
                return Task.FromResult(
                    ProcessCommandResult.Completed(0, "Sniffer is running.", string.Empty));
            }

            if (command.EndsWith("-stop", StringComparison.Ordinal))
            {
                running = false;
                return Task.FromResult(
                    ProcessCommandResult.Completed(0, "Sniffer stopped.", string.Empty));
            }

            return Task.FromResult(
                ProcessCommandResult.Completed(
                    0,
                    running ? "Sniffer is running." : "Sniffer is not running.",
                    string.Empty));
        }
    }

    private sealed class FakePrimaryProvider : ICaptureProvider
    {
        public string ProviderId => "Primary";

        public Task<CaptureProviderProbeResult> ProbeAsync(
            CaptureProviderStartRequest request,
            CancellationToken cancellationToken) =>
            Task.FromResult(
                CaptureProviderProbeResult.Unavailable(
                    CaptureProviderFailureCode.ProbeFailed,
                    "unused"));

        public Task<CaptureProviderStartResult> StartAsync(
            CaptureProviderStartRequest request,
            CancellationToken cancellationToken) =>
            Task.FromResult(
                CaptureProviderStartResult.Started(
                    CaptureProviderSessionHandle.Create(
                        ProviderId,
                        request.Identity.InvocationId,
                        "primary-session")));

        public Task<CaptureProviderReadinessResult> WaitForReadinessAsync(
            CaptureProviderSessionHandle handle,
            CancellationToken cancellationToken) =>
            Task.FromResult(CaptureProviderReadinessResult.Ready("ready"));

        public Task<CaptureProviderHealthResult> ObserveHealthAsync(
            CaptureProviderSessionHandle handle,
            CancellationToken cancellationToken) =>
            Task.FromResult(CaptureProviderHealthResult.Healthy("healthy"));

        public Task<CaptureProviderStopResult> RequestStopAsync(
            CaptureProviderSessionHandle handle,
            CancellationToken cancellationToken) =>
            Task.FromResult(CaptureProviderStopResult.Stopped("stopped"));

        public Task<CaptureProviderFinalizationResult> WaitForFinalizationAsync(
            CaptureProviderSessionHandle handle,
            CancellationToken cancellationToken) =>
            Task.FromResult(
                CaptureProviderFinalizationResult.Finalized(
                    "done",
                    new[]
                    {
                        ArtifactRecord.CreateFinalized(
                            "capture.etl",
                            "Primary",
                            1,
                            new string('A', 64),
                            ArtifactConfidentiality.Restricted,
                            ArtifactRelation.Original,
                            "application/octet-stream"),
                    }));
    }

    private sealed class SnifferContext : IDisposable
    {
        private readonly TemporaryDirectory temporaryDirectory;
        private readonly ArtifactStore artifactStore;
        private readonly ArtifactInvocation artifactInvocation;

        private SnifferContext(
            TemporaryDirectory temporaryDirectory,
            ArtifactStore artifactStore,
            ArtifactInvocation artifactInvocation,
            CaptureProviderStartRequest request)
        {
            this.temporaryDirectory = temporaryDirectory;
            this.artifactStore = artifactStore;
            this.artifactInvocation = artifactInvocation;
            Request = request;
        }

        internal CaptureProviderStartRequest Request { get; }

        internal string OutputPath =>
            Path.Combine(
                artifactInvocation.DirectoryPath,
                Mlx5SnifferCaptureProvider.OutputFileName);

        internal static SnifferContext Create(string target, string attempt = "attempt-1")
        {
            TemporaryDirectory temporaryDirectory = TemporaryDirectory.Create();
            ArtifactStore artifactStore = ArtifactStore.Open(
                temporaryDirectory.CreateSubdirectory("artifacts"),
                temporaryDirectory.CreateSubdirectory("source"),
                temporaryDirectory.CreateSubdirectory("build"));
            InvocationIdentity identity = InvocationIdentity.Create(
                "run-sniffer",
                "Mlx5SnifferCaptureProviderTests.Test",
                attempt,
                "row-1");
            ArtifactInvocation invocation = artifactStore.CreateInvocation(identity);
            var request = new CaptureProviderStartRequest(
                identity,
                invocation,
                new[] { target },
                "Native",
                TimeSpan.FromMinutes(5),
                8L * 1024 * 1024);
            return new SnifferContext(
                temporaryDirectory,
                artifactStore,
                invocation,
                request);
        }

        public void Dispose()
        {
            artifactInvocation.Dispose();
            artifactStore.Dispose();
            temporaryDirectory.Dispose();
        }
    }
}
