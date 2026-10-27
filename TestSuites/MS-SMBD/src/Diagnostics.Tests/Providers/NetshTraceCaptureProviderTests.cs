// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Protocols.TestSuites.Diagnostics.Evidence;
using Microsoft.Protocols.TestSuites.Diagnostics.Identity;
using Microsoft.Protocols.TestSuites.Diagnostics.Providers;
using Microsoft.Protocols.TestSuites.Diagnostics.Storage;
using Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.TestSupport;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.Providers;

[TestClass]
public sealed class NetshTraceCaptureProviderTests
{
    private const string NetshPath = @"C:\Windows\System32\netsh.exe";
    private const long Mebibyte = 1024L * 1024L;
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(5);

    [DataTestMethod]
    [DataRow("timeout")]
    [DataRow("denied")]
    [DataRow("unparseable")]
    [DataRow("foreign")]
    [DataRow("prefix")]
    [DataRow("cancelled")]
    public async Task StartAsync_IndeterminateRecovery_PreservesUnresolvedWriterWithoutStopping(string status)
    {
        using NetshProviderTestContext context = NetshProviderTestContext.Create();
        var runner = new FakeProcessCommandRunner();
        runner.Enqueue(NoSession());
        runner.Enqueue(status == "cancelled"
            ? ProcessCommandResult.Cancelled(true) : ProcessCommandResult.TimedOut(true));
        runner.Enqueue(status switch
        {
            "timeout" => ProcessCommandResult.TimedOut(true),
            "denied" => ProcessCommandResult.PermissionDenied(),
            "foreign" => Completed(stdout: RunningStatus(
                ExpectedSessionName(context.Request.Identity), Path.Combine(Path.GetDirectoryName(context.OutputPath)!, "foreign.etl"))),
            "prefix" => Completed(stdout: RunningStatus(
                ExpectedSessionName(context.Request.Identity), context.OutputPath + ".foreign")),
            _ => Completed(stdout: "Unknown localized state."),
        });
        CaptureProviderStartResult result =
            await CreateProvider(runner).StartAsync(context.Request, default);

        Assert.IsFalse(result.IsStarted);
        Assert.IsFalse(result.WriterResolved);
        Assert.AreEqual(status == "cancelled" ? CaptureProviderFailureCode.Cancelled
            : CaptureProviderFailureCode.StartTimeout, result.FailureCode);
        Assert.IsNull(result.Handle);
        Assert.IsFalse(runner.Commands.Any(command => command.Arguments.Contains("stop")));
    }

    [TestMethod]
    public async Task StartReadyStopAsync_UsesDirectNamedNetshCommandsAndBoundedArguments()
    {
        using NetshProviderTestContext context = NetshProviderTestContext.Create(
            new[] { "10.1.2.3" },
            maxBytes: (8 * Mebibyte) + 4095);
        var runner = new FakeProcessCommandRunner();
        runner.Enqueue(NoSession());
        runner.Enqueue(Completed());
        NetshTraceCaptureProvider provider = CreateProvider(runner);

        CaptureProviderProbeResult probe =
            await provider.ProbeAsync(context.Request, CancellationToken.None);
        CaptureProviderStartResult start =
            await provider.StartAsync(context.Request, CancellationToken.None);
        Assert.IsTrue(start.IsStarted);
        string sessionName = start.Handle!.SessionId;
        runner.Enqueue(Completed(stdout: RunningStatus(sessionName, context.OutputPath)));
        CaptureProviderReadinessResult readiness =
            await provider.WaitForReadinessAsync(start.Handle, CancellationToken.None);
        runner.Enqueue(Completed());
        CaptureProviderStopResult stop =
            await provider.RequestStopAsync(start.Handle, CancellationToken.None);

        Assert.IsTrue(probe.IsAvailable);
        Assert.AreEqual(CaptureProviderReadinessStatus.Ready, readiness.Status);
        Assert.AreEqual(CaptureProviderStopStatus.Stopped, stop.Status);
        Assert.AreEqual(2, runner.ExecutableProbes.Count);
        Assert.IsTrue(
            runner.ExecutableProbes.All(
                path => string.Equals(path, NetshPath, StringComparison.Ordinal)));
        Assert.AreEqual(4, runner.Commands.Count);
        AssertStatusCommand(runner.Commands[0], sessionName);
        AssertCommand(
            runner.Commands[1],
            "trace",
            "start",
            $"sessionname={sessionName}",
            "capture=yes",
            "capturetype=physical",
            "report=disabled",
            "persistent=no",
            $"traceFile={context.OutputPath}",
            "maxSize=8",
            "fileMode=single",
            "overwrite=no",
            "correlation=disabled",
            "IPv4.Address=10.1.2.3");
        AssertStatusCommand(runner.Commands[2], sessionName);
        AssertCommand(
            runner.Commands[3],
            "trace",
            "stop",
            $"sessionname={sessionName}");
        Assert.IsTrue(
            runner.Commands.All(command => command.Timeout == CommandTimeout));
    }

    [TestMethod]
    public async Task StartAsync_HostileIdentityToolPathAndPathShapeRemainSingleArguments()
    {
        const string HostileExecutable =
            @"C:\Program Files\Tracing & Tools\netsh.exe";
        using NetshProviderTestContext context = NetshProviderTestContext.Create(
            new[] { "192.0.2.25" },
            testIdentity:
                @"Provider & trace stop sessionname=foreign ..\..\escape.etl");
        var runner = new FakeProcessCommandRunner();
        runner.Enqueue(NoSession());
        runner.Enqueue(Completed());
        runner.Enqueue(Completed());
        NetshTraceCaptureProvider provider = CreateProvider(
            runner,
            executablePath: HostileExecutable);

        CaptureProviderStartResult start =
            await provider.StartAsync(context.Request, CancellationToken.None);
        Assert.IsTrue(start.IsStarted);
        CaptureProviderStopResult stop =
            await provider.RequestStopAsync(start.Handle!, CancellationToken.None);

        Assert.AreEqual(CaptureProviderStopStatus.Stopped, stop.Status);
        Assert.AreEqual(3, runner.Commands.Count);
        Assert.AreEqual(
            @"C:\Program Files\Tracing & Tools\logman.exe",
            runner.Commands[0].FileName);
        Assert.IsTrue(runner.Commands.All(command => !command.UseShellExecute));
        Assert.IsTrue(runner.Commands.All(command => command.CreateNoWindow));
        Assert.IsTrue(
            Regex.IsMatch(
                start.Handle!.SessionId,
                @"^WPTS_[a-f0-9]{32}$",
                RegexOptions.CultureInvariant));
        Assert.IsFalse(
            start.Handle.SessionId.Contains(
                "foreign",
                StringComparison.OrdinalIgnoreCase));
        CollectionAssert.AreEqual(
            new[]
            {
                "query",
                $"{start.Handle.SessionId}-NetTrace-1",
                "-ets",
            },
            runner.Commands[0].Arguments.ToArray());
        CollectionAssert.AreEqual(
            new[]
            {
                "trace",
                "start",
                $"sessionname={start.Handle.SessionId}",
                "capture=yes",
                "capturetype=physical",
                "report=disabled",
                "persistent=no",
                $"traceFile={context.OutputPath}",
                "maxSize=8",
                "fileMode=single",
                "overwrite=no",
                "correlation=disabled",
                "IPv4.Address=192.0.2.25",
            },
            runner.Commands[1].Arguments.ToArray());
        CollectionAssert.AreEqual(
            new[]
            {
                "trace",
                "stop",
                $"sessionname={start.Handle.SessionId}",
            },
            runner.Commands[2].Arguments.ToArray());
        Assert.IsTrue(
            runner.Commands[1].Arguments.Contains("IPv4.Address=192.0.2.25"));
        string traceFileArgument = runner.Commands[1].Arguments
            .Single(argument => argument.StartsWith("traceFile=", StringComparison.Ordinal));
        string traceFilePath = traceFileArgument["traceFile=".Length..];
        Assert.AreEqual(context.OutputPath, traceFilePath);
        Assert.IsTrue(
            Path.GetFullPath(traceFilePath).StartsWith(
                Path.GetFullPath(context.InvocationDirectory) +
                    Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase));
    }

    [TestMethod]
    public async Task StartAsync_ExistingNamedSessionReturnsCaptureBusyWithoutStopping()
    {
        using NetshProviderTestContext context = NetshProviderTestContext.Create();
        var runner = new FakeProcessCommandRunner();
        NetshTraceCaptureProvider provider = CreateProvider(runner);
        string expectedSession = ExpectedSessionName(context.Request.Identity);
        runner.Enqueue(
            Completed(stdout: RunningStatus(expectedSession, context.OutputPath)));

        CaptureProviderStartResult result =
            await provider.StartAsync(context.Request, CancellationToken.None);

        Assert.IsFalse(result.IsStarted);
        Assert.AreEqual(CaptureProviderFailureCode.CaptureBusy, result.FailureCode);
        Assert.AreEqual(1, runner.Commands.Count);
        CollectionAssert.DoesNotContain(
            runner.Commands[0].Arguments.ToList(),
            "stop");
    }

    [TestMethod]
    public async Task ProbeAsync_MissingExecutableReturnsToolMissingWithoutStartingProcess()
    {
        using NetshProviderTestContext context = NetshProviderTestContext.Create();
        var runner = new FakeProcessCommandRunner
        {
            ExecutableAvailable = false,
        };
        NetshTraceCaptureProvider provider = CreateProvider(runner);

        CaptureProviderProbeResult result =
            await provider.ProbeAsync(context.Request, CancellationToken.None);

        Assert.IsFalse(result.IsAvailable);
        Assert.AreEqual(CaptureProviderFailureCode.ToolMissing, result.FailureCode);
        Assert.AreEqual(0, runner.Commands.Count);
    }

    [TestMethod]
    public async Task StartAsync_ExitFiveReturnsPermissionDenied()
    {
        using NetshProviderTestContext context = NetshProviderTestContext.Create();
        var runner = new FakeProcessCommandRunner();
        runner.Enqueue(Completed(exitCode: 5));
        NetshTraceCaptureProvider provider = CreateProvider(runner);

        CaptureProviderStartResult result =
            await provider.StartAsync(context.Request, CancellationToken.None);

        Assert.IsFalse(result.IsStarted);
        Assert.AreEqual(
            CaptureProviderFailureCode.PermissionDenied,
            result.FailureCode);
        Assert.AreEqual(1, runner.Commands.Count);
    }

    [TestMethod]
    public async Task StartAsync_PreflightOtherNonzeroFailureReturnsStartFailedWithoutStart()
    {
        using NetshProviderTestContext context = NetshProviderTestContext.Create();
        var runner = new FakeProcessCommandRunner();
        runner.Enqueue(Completed(exitCode: 1, stdout: "The parameter is incorrect."));
        NetshTraceCaptureProvider provider = CreateProvider(runner);

        CaptureProviderStartResult result =
            await provider.StartAsync(context.Request, CancellationToken.None);

        Assert.IsFalse(result.IsStarted);
        Assert.AreEqual(CaptureProviderFailureCode.StartFailed, result.FailureCode);
        Assert.AreEqual(1, runner.Commands.Count);
        Assert.IsFalse(
            runner.Commands.Any(command => command.Arguments.Contains("start")));
    }

    [TestMethod]
    public async Task StartAsync_NonzeroStartReturnsStartFailed()
    {
        using NetshProviderTestContext context = NetshProviderTestContext.Create();
        var runner = new FakeProcessCommandRunner();
        runner.Enqueue(NoSession());
        runner.Enqueue(Completed(exitCode: 1, stderr: "controlled failure"));
        NetshTraceCaptureProvider provider = CreateProvider(runner);

        CaptureProviderStartResult result =
            await provider.StartAsync(context.Request, CancellationToken.None);

        Assert.IsFalse(result.IsStarted);
        Assert.AreEqual(CaptureProviderFailureCode.StartFailed, result.FailureCode);
        Assert.IsFalse(
            result.Detail!.Contains("controlled failure", StringComparison.Ordinal));
    }

    [TestMethod]
    public async Task StartAsync_TimeoutKillsOnlySpawnedCommandAndDoesNotStopUnprovenSession()
    {
        using NetshProviderTestContext context = NetshProviderTestContext.Create();
        var runner = new FakeProcessCommandRunner();
        runner.Enqueue(NoSession());
        runner.Enqueue(ProcessCommandResult.TimedOut(spawnedProcessTerminated: true));
        runner.Enqueue(NoSession());
        NetshTraceCaptureProvider provider = CreateProvider(runner);

        CaptureProviderStartResult result =
            await provider.StartAsync(context.Request, CancellationToken.None);

        Assert.IsFalse(result.IsStarted);
        Assert.AreEqual(CaptureProviderFailureCode.StartTimeout, result.FailureCode);
        Assert.AreEqual(3, runner.Commands.Count);
        Assert.IsTrue(result.WriterResolved, "Explicit no-session status proves absence.");
        Assert.IsTrue(runner.ReturnedResults[1].SpawnedProcessTerminated);
        Assert.IsFalse(
            runner.Commands.Any(
                command => command.Arguments.Contains("stop")));
    }

    [TestMethod]
    public async Task StartAsync_TimeoutStopsOnlyStatusProvenOwnedSession()
    {
        using NetshProviderTestContext context = NetshProviderTestContext.Create();
        var runner = new FakeProcessCommandRunner();
        string expectedSession = ExpectedSessionName(context.Request.Identity);
        runner.Enqueue(NoSession());
        runner.Enqueue(ProcessCommandResult.TimedOut(spawnedProcessTerminated: true));
        runner.Enqueue(
            Completed(stdout: RunningStatus(expectedSession, context.OutputPath)));
        runner.Enqueue(Completed());
        NetshTraceCaptureProvider provider = CreateProvider(runner);

        CaptureProviderStartResult result =
            await provider.StartAsync(context.Request, CancellationToken.None);

        Assert.IsFalse(result.IsStarted);
        Assert.AreEqual(CaptureProviderFailureCode.StartTimeout, result.FailureCode);
        Assert.AreEqual(4, runner.Commands.Count);
        AssertCommand(
            runner.Commands[3],
            "trace",
            "stop",
            $"sessionname={expectedSession}");
    }

    [TestMethod]
    public async Task RequestStopAsync_ForeignHandleIsRejectedAndOwnedStopIsIdempotent()
    {
        using NetshProviderTestContext context = NetshProviderTestContext.Create();
        var runner = new FakeProcessCommandRunner();
        runner.Enqueue(NoSession());
        runner.Enqueue(Completed());
        runner.Enqueue(Completed());
        NetshTraceCaptureProvider provider = CreateProvider(runner);
        CaptureProviderStartResult start =
            await provider.StartAsync(context.Request, CancellationToken.None);
        var foreign = CaptureProviderSessionHandle.Create(
            NetshTraceCaptureProvider.ProviderIdentifier,
            context.Request.Identity.InvocationId,
            "WPTS_00000000000000000000000000000000");

        CaptureProviderStopResult foreignStop =
            await provider.RequestStopAsync(foreign, CancellationToken.None);
        CaptureProviderStopResult first =
            await provider.RequestStopAsync(start.Handle!, CancellationToken.None);
        CaptureProviderStopResult second =
            await provider.RequestStopAsync(start.Handle!, CancellationToken.None);

        Assert.AreEqual(CaptureProviderFailureCode.OwnershipMismatch, foreignStop.FailureCode);
        Assert.AreEqual(CaptureProviderStopStatus.Stopped, first.Status);
        Assert.AreEqual(CaptureProviderStopStatus.AlreadyStopped, second.Status);
        Assert.AreEqual(
            1,
            runner.Commands.Count(command => command.Arguments.Contains("stop")));
    }

    [TestMethod]
    public async Task StartAsync_MultipleTargetsAreRejectedWithoutSilentlyNarrowing()
    {
        using NetshProviderTestContext context = NetshProviderTestContext.Create(
            new[] { "10.1.2.3", "10.1.2.4" });
        var runner = new FakeProcessCommandRunner();
        NetshTraceCaptureProvider provider = CreateProvider(runner);

        CaptureProviderStartResult result =
            await provider.StartAsync(context.Request, CancellationToken.None);

        Assert.IsFalse(result.IsStarted);
        Assert.AreEqual(CaptureProviderFailureCode.TargetAmbiguous, result.FailureCode);
        Assert.AreEqual(0, runner.Commands.Count);
    }

    [TestMethod]
    public async Task StartAsync_NonCanonicalOrHostileTargetIsRejectedBeforeCommandExecution()
    {
        using NetshProviderTestContext context = NetshProviderTestContext.Create(
            new[] { "10.1.2.3 & trace stop sessionname=foreign" });
        var runner = new FakeProcessCommandRunner();
        NetshTraceCaptureProvider provider = CreateProvider(runner);

        CaptureProviderStartResult result =
            await provider.StartAsync(context.Request, CancellationToken.None);

        Assert.IsFalse(result.IsStarted);
        Assert.AreEqual(CaptureProviderFailureCode.TargetAmbiguous, result.FailureCode);
        Assert.AreEqual(0, runner.Commands.Count);
    }

    [TestMethod]
    public async Task WaitForFinalizationAsync_NonemptyClosedEtlReturnsSizeAndUppercaseSha256()
    {
        using NetshProviderTestContext context = NetshProviderTestContext.Create();
        var runner = new FakeProcessCommandRunner();
        runner.Enqueue(NoSession());
        runner.Enqueue(Completed());
        runner.Enqueue(Completed());
        NetshTraceCaptureProvider provider = CreateProvider(runner);
        CaptureProviderStartResult start =
            await provider.StartAsync(context.Request, CancellationToken.None);
        CaptureProviderStopResult stop =
            await provider.RequestStopAsync(start.Handle!, CancellationToken.None);
        byte[] content = { 0x01, 0xA2, 0xFF, 0x10, 0x42 };
        File.WriteAllBytes(context.OutputPath, content);

        CaptureProviderFinalizationResult result =
            await provider.WaitForFinalizationAsync(
                start.Handle!,
                CancellationToken.None);

        Assert.AreEqual(CaptureProviderStopStatus.Stopped, stop.Status);
        Assert.AreEqual(CaptureProviderFinalizationStatus.Finalized, result.Status);
        ArtifactRecord artifact = result.Artifacts.Single();
        Assert.AreEqual(NetshTraceCaptureProvider.OutputFileName, artifact.RelativePath);
        Assert.AreEqual(content.LongLength, artifact.ByteCount);
        Assert.AreEqual(
            Convert.ToHexString(SHA256.HashData(content)),
            artifact.Sha256);
        Assert.AreEqual(
            ArtifactFinalizationState.Finalized,
            artifact.FinalizationState);
        Assert.AreEqual("application/octet-stream", artifact.MediaType);
    }

    [DataTestMethod]
    [DataRow("missing")]
    [DataRow("empty")]
    [DataRow("locked")]
    public async Task WaitForFinalizationAsync_UnusableEtlFailsSafely(string scenario)
    {
        using NetshProviderTestContext context = NetshProviderTestContext.Create();
        var runner = new FakeProcessCommandRunner();
        runner.Enqueue(NoSession());
        runner.Enqueue(Completed());
        runner.Enqueue(Completed());
        NetshTraceCaptureProvider provider = CreateProvider(runner);
        CaptureProviderStartResult start =
            await provider.StartAsync(context.Request, CancellationToken.None);
        await provider.RequestStopAsync(start.Handle!, CancellationToken.None);
        FileStream? locked = null;
        try
        {
            if (scenario == "empty")
            {
                File.WriteAllBytes(context.OutputPath, Array.Empty<byte>());
            }
            else if (scenario == "locked")
            {
                File.WriteAllBytes(context.OutputPath, new byte[] { 0x42 });
                locked = new FileStream(
                    context.OutputPath,
                    FileMode.Open,
                    FileAccess.ReadWrite,
                    FileShare.None);
            }

            CaptureProviderFinalizationResult result =
                await provider.WaitForFinalizationAsync(
                    start.Handle!,
                    CancellationToken.None);

            Assert.AreEqual(CaptureProviderFinalizationStatus.Failed, result.Status);
            Assert.AreEqual(
                CaptureProviderFailureCode.FinalizationFailed,
                result.FailureCode);
            Assert.AreEqual(0, result.Artifacts.Count);
            Assert.IsFalse(
                result.Detail.Contains(context.OutputPath, StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            locked?.Dispose();
        }
    }

    [TestMethod]
    public async Task MaximumDuration_UsesSameOwnedNamedStopPath()
    {
        var durationGate =
            new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using NetshProviderTestContext context = NetshProviderTestContext.Create(
            maxDuration: TimeSpan.FromSeconds(30));
        var runner = new FakeProcessCommandRunner();
        runner.Enqueue(NoSession());
        runner.Enqueue(Completed());
        runner.Enqueue(Completed());
        NetshTraceCaptureProvider provider = CreateProvider(
            runner,
            delayAsync: (_, _) => durationGate.Task);
        CaptureProviderStartResult start =
            await provider.StartAsync(context.Request, CancellationToken.None);

        durationGate.SetResult();
        await runner.StopObserved.Task.WaitAsync(TimeSpan.FromSeconds(2));
        CaptureProviderStopResult repeated =
            await provider.RequestStopAsync(start.Handle!, CancellationToken.None);
        File.WriteAllText(context.OutputPath, "synthetic closed ETL");
        CaptureProviderFinalizationResult finalized =
            await provider.WaitForFinalizationAsync(start.Handle!, default);

        Assert.AreEqual(CaptureProviderStopStatus.AlreadyStopped, repeated.Status);
        Assert.AreEqual(CaptureProviderFinalizationStatus.Finalized, finalized.Status);
        Assert.IsFalse(finalized.CollectionComplete);
        ObservedCommand stop = runner.Commands.Single(
            command => command.Arguments.Contains("stop"));
        AssertCommand(
            stop,
            "trace",
            "stop",
            $"sessionname={start.Handle!.SessionId}");
    }

    [TestMethod]
    public async Task MaximumDuration_CoordinationFaultIsReportedAfterNamedStop()
    {
        using NetshProviderTestContext context = NetshProviderTestContext.Create(
            maxDuration: TimeSpan.FromSeconds(30));
        var runner = new FakeProcessCommandRunner();
        runner.Enqueue(NoSession());
        runner.Enqueue(Completed());
        runner.Enqueue(Completed());
        NetshTraceCaptureProvider provider = CreateProvider(
            runner,
            delayAsync: (_, _) => Task.FromException(
                new InvalidOperationException("Synthetic delay failure.")));
        CaptureProviderStartResult start =
            await provider.StartAsync(context.Request, CancellationToken.None);

        CaptureProviderHealthResult health =
            await provider.ObserveHealthAsync(
                start.Handle!,
                CancellationToken.None);
        CaptureProviderStopResult stop =
            await provider.RequestStopAsync(
                start.Handle!,
                CancellationToken.None);

        Assert.AreEqual(CaptureProviderHealthStatus.Failed, health.Status);
        Assert.AreEqual(CaptureProviderFailureCode.HealthFailed, health.FailureCode);
        Assert.AreEqual(CaptureProviderStopStatus.Failed, stop.Status);
        Assert.AreEqual(CaptureProviderFailureCode.HealthFailed, stop.FailureCode);
        Assert.IsTrue(stop.WriterResolved);
        Assert.AreEqual(
            1,
            runner.Commands.Count(command => command.Arguments.Contains("stop")));
    }

    private static NetshTraceCaptureProvider CreateProvider(
        FakeProcessCommandRunner runner,
        string executablePath = NetshPath,
        Func<TimeSpan, CancellationToken, Task>? delayAsync = null)
    {
        return new NetshTraceCaptureProvider(
            executablePath,
            CommandTimeout,
            CommandTimeout,
            runner,
            delayAsync ?? DelayUntilCancelledAsync);
    }

    private static Task DelayUntilCancelledAsync(
        TimeSpan _,
        CancellationToken cancellationToken)
    {
        return Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
    }

    private static ProcessCommandResult Completed(
        int exitCode = 0,
        string stdout = "",
        string stderr = "")
    {
        return ProcessCommandResult.Completed(exitCode, stdout, stderr);
    }

    private static ProcessCommandResult NoSession()
    {
        return Completed(
            exitCode: -2144337918,
            stdout: "Data Collector Set was not found.");
    }

    private static string ExpectedSessionName(InvocationIdentity identity)
    {
        return $"WPTS_{identity.InvocationId}";
    }

    private static string RunningStatus(string sessionName, string outputPath)
    {
        return
            $"Name:                 {sessionName}-NetTrace-1{Environment.NewLine}" +
            $"Status:               Running{Environment.NewLine}" +
            $"Root Path:            {Path.GetDirectoryName(outputPath)}{Environment.NewLine}" +
            $"Output Location:      {outputPath}{Environment.NewLine}";
    }

    private static void AssertStatusCommand(
        ObservedCommand command,
        string sessionName)
    {
        Assert.AreEqual(@"C:\Windows\System32\logman.exe", command.FileName);
        Assert.IsFalse(command.UseShellExecute);
        Assert.IsTrue(command.CreateNoWindow);
        CollectionAssert.AreEqual(
            new[] { "query", $"{sessionName}-NetTrace-1", "-ets" },
            command.Arguments.ToArray());
    }

    private static void AssertCommand(
        ObservedCommand command,
        params string[] expectedArguments)
    {
        Assert.AreEqual(NetshPath, command.FileName);
        Assert.IsFalse(command.UseShellExecute);
        Assert.IsTrue(command.CreateNoWindow);
        CollectionAssert.AreEqual(
            expectedArguments,
            command.Arguments.ToArray());
    }

    private sealed class FakeProcessCommandRunner : IProcessCommandRunner
    {
        private readonly Queue<ProcessCommandResult> results = new();

        internal bool ExecutableAvailable { get; set; } = true;

        internal List<string> ExecutableProbes { get; } = new();

        internal List<ObservedCommand> Commands { get; } = new();

        internal List<ProcessCommandResult> ReturnedResults { get; } = new();

        internal TaskCompletionSource StopObserved { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        internal void Enqueue(ProcessCommandResult result)
        {
            results.Enqueue(result);
        }

        public bool ExecutableExists(string executablePath)
        {
            ExecutableProbes.Add(executablePath);
            return ExecutableAvailable;
        }

        public Task<ProcessCommandResult> RunAsync(
            ProcessStartInfo startInfo,
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var command = new ObservedCommand(
                startInfo.FileName,
                startInfo.UseShellExecute,
                startInfo.CreateNoWindow,
                startInfo.ArgumentList.ToArray(),
                timeout);
            Commands.Add(command);
            if (command.Arguments.Contains("stop"))
            {
                StopObserved.TrySetResult();
            }

            ProcessCommandResult result = results.Dequeue();
            ReturnedResults.Add(result);
            return Task.FromResult(result);
        }
    }

    private sealed record ObservedCommand(
        string FileName,
        bool UseShellExecute,
        bool CreateNoWindow,
        IReadOnlyList<string> Arguments,
        TimeSpan Timeout);

    private sealed class NetshProviderTestContext : IDisposable
    {
        private readonly TemporaryDirectory temporaryDirectory;
        private readonly ArtifactStore artifactStore;
        private readonly ArtifactInvocation artifactInvocation;

        private NetshProviderTestContext(
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

        internal string InvocationDirectory => artifactInvocation.DirectoryPath;

        internal string OutputPath =>
            Path.Combine(InvocationDirectory, NetshTraceCaptureProvider.OutputFileName);

        internal static NetshProviderTestContext Create(
            IReadOnlyList<string>? targets = null,
            TimeSpan? maxDuration = null,
            long maxBytes = 8 * Mebibyte,
            string testIdentity = "NetshTraceCaptureProviderTests.Test")
        {
            TemporaryDirectory temporaryDirectory = TemporaryDirectory.Create();
            string sourceRoot = temporaryDirectory.CreateSubdirectory("source");
            string buildRoot = temporaryDirectory.CreateSubdirectory("build");
            string artifactRoot = temporaryDirectory.CreateSubdirectory("artifacts");
            ArtifactStore artifactStore = ArtifactStore.Open(
                artifactRoot,
                sourceRoot,
                buildRoot);
            InvocationIdentity identity = InvocationIdentity.Create(
                "run-netsh",
                testIdentity,
                "attempt-1",
                "row-1");
            ArtifactInvocation artifactInvocation =
                artifactStore.CreateInvocation(identity);
            var request = new CaptureProviderStartRequest(
                identity,
                artifactInvocation,
                targets ?? new[] { "10.1.2.3" },
                "Native",
                maxDuration ?? TimeSpan.FromMinutes(5),
                maxBytes);

            return new NetshProviderTestContext(
                temporaryDirectory,
                artifactStore,
                artifactInvocation,
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
