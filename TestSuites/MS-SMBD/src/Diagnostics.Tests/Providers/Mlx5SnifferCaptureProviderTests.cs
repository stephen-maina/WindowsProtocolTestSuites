// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
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
            (_, _) => Task.Delay(Timeout.Infinite));
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
        private readonly string outputPath;
        private bool running;

        internal FakeSnifferRunner(string outputPath)
        {
            this.outputPath = outputPath;
        }

        internal bool ExecutableAvailable { get; set; } = true;

        internal int PcapBytes { get; set; } = 64;

        internal List<string> Commands { get; } = new();

        public bool ExecutableExists(string executablePath) => ExecutableAvailable;

        public Task<ProcessCommandResult> RunAsync(
            ProcessStartInfo startInfo,
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            string command = string.Join(' ', startInfo.ArgumentList);
            Commands.Add(command);
            if (command.Contains("-start"))
            {
                running = true;
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

        internal static SnifferContext Create(string target)
        {
            TemporaryDirectory temporaryDirectory = TemporaryDirectory.Create();
            ArtifactStore artifactStore = ArtifactStore.Open(
                temporaryDirectory.CreateSubdirectory("artifacts"),
                temporaryDirectory.CreateSubdirectory("source"),
                temporaryDirectory.CreateSubdirectory("build"));
            InvocationIdentity identity = InvocationIdentity.Create(
                "run-sniffer",
                "Mlx5SnifferCaptureProviderTests.Test",
                "attempt-1",
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
