// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Protocols.TestSuites.Diagnostics.Evidence;
using Microsoft.Protocols.TestSuites.Diagnostics.Manifest;
using Microsoft.Protocols.TestSuites.Diagnostics.Storage;
using StorageArtifactPath =
    Microsoft.Protocols.TestSuites.Diagnostics.Storage.ArtifactPath;

namespace Microsoft.Protocols.TestSuites.Diagnostics.Providers;

public sealed class NetshTraceCaptureProvider : ICaptureProvider
{
    public const string ProviderIdentifier = "NetshTrace";
    public const string DefaultExecutablePath = @"C:\Windows\System32\netsh.exe";
    public const string OutputFileName = "capture.etl";

    private const long BytesPerMebibyte = 1024 * 1024;
    private const string EtwSessionSuffix = "-NetTrace-1";

    private readonly string executablePath;
    private readonly string statusExecutablePath;
    private readonly TimeSpan startCommandTimeout;
    private readonly TimeSpan stopCommandTimeout;
    private readonly IProcessCommandRunner commandRunner;
    private readonly Func<TimeSpan, CancellationToken, Task> delayAsync;
    private readonly ConcurrentDictionary<string, OwnedSession> ownedSessions =
        new(StringComparer.Ordinal);

    public NetshTraceCaptureProvider(
        string executablePath,
        TimeSpan startCommandTimeout,
        TimeSpan stopCommandTimeout)
        : this(
            executablePath,
            startCommandTimeout,
            stopCommandTimeout,
            new ProcessCommandRunner(),
            static (delay, cancellationToken) =>
                Task.Delay(delay, cancellationToken))
    {
    }

    public NetshTraceCaptureProvider(
        string executablePath,
        TimeSpan startCommandTimeout,
        TimeSpan stopCommandTimeout,
        IProcessCommandRunner commandRunner,
        Func<TimeSpan, CancellationToken, Task> delayAsync)
    {
        this.executablePath = ProviderContractValidation.RequireText(
            executablePath,
            nameof(executablePath));
        statusExecutablePath = Path.Combine(
            Path.GetDirectoryName(this.executablePath) ?? string.Empty,
            "logman.exe");
        this.startCommandTimeout =
            ProviderContractValidation.ValidatePositiveTimeout(
                startCommandTimeout,
                nameof(startCommandTimeout));
        this.stopCommandTimeout =
            ProviderContractValidation.ValidatePositiveTimeout(
                stopCommandTimeout,
                nameof(stopCommandTimeout));
        this.commandRunner = commandRunner ??
            throw new ArgumentNullException(nameof(commandRunner));
        this.delayAsync = delayAsync ??
            throw new ArgumentNullException(nameof(delayAsync));
    }

    public string ProviderId => ProviderIdentifier;

    public Task<CaptureProviderProbeResult> ProbeAsync(
        CaptureProviderStartRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (cancellationToken.IsCancellationRequested)
        {
            return Task.FromResult(
                CaptureProviderProbeResult.Unavailable(
                    CaptureProviderFailureCode.Cancelled,
                    "The capture provider probe was cancelled."));
        }

        if (!commandRunner.ExecutableExists(executablePath))
        {
            return Task.FromResult(
                CaptureProviderProbeResult.Unavailable(
                    CaptureProviderFailureCode.ToolMissing,
                    "The configured capture executable is unavailable."));
        }

        return Task.FromResult(
            CaptureProviderProbeResult.Available(
                new CaptureProviderCapabilities(
                    ProviderIdentifier,
                    new[] { "IPv4" },
                    new[] { "ETL" },
                    "Windows physical capture selected for one canonical IPv4 target.",
                    "Whole-MiB file size and provider-coordinated duration limits.",
                    "Owned named sessions are stopped only by exact session name.",
                    "Readiness requires named status to prove the running session and ETL path.",
                    new[]
                    {
                        "RDMA/RoCE visibility is not qualified by provider availability.",
                        "ETL presence does not prove complete SMB Direct payload visibility.",
                    },
                    CoverageQualification.Unverified)));
    }

    public async Task<CaptureProviderStartResult> StartAsync(
        CaptureProviderStartRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (cancellationToken.IsCancellationRequested)
        {
            return CaptureProviderStartResult.Failed(
                CaptureProviderFailureCode.Cancelled,
                "Capture start was cancelled.");
        }

        if (!TryPrepareStart(
                request,
                out string sessionName,
                out string outputPath,
                out string canonicalTarget,
                out long maximumMebibytes,
                out CaptureProviderStartResult? preparationFailure))
        {
            return preparationFailure!;
        }

        if (!commandRunner.ExecutableExists(executablePath))
        {
            return CaptureProviderStartResult.Failed(
                CaptureProviderFailureCode.ToolMissing,
                "The configured capture executable is unavailable.");
        }

        ProcessCommandResult preflight = await RunStatusAsync(
            sessionName,
            startCommandTimeout,
            cancellationToken).ConfigureAwait(false);
        CaptureProviderFailureCode preflightFailure =
            StatusShowsNoActiveSession(preflight)
                ? CaptureProviderFailureCode.None
                : ClassifyCommandFailure(
                    preflight,
                    CaptureProviderFailureCode.StartFailed,
                    CaptureProviderFailureCode.StartTimeout);
        if (preflightFailure != CaptureProviderFailureCode.None)
        {
            return CaptureProviderStartResult.Failed(
                preflightFailure,
                "The named capture-session preflight failed.");
        }

        if (StatusShowsRunningSession(preflight, sessionName))
        {
            return CaptureProviderStartResult.Failed(
                CaptureProviderFailureCode.CaptureBusy,
                "The provider session name is already active.");
        }

        ProcessCommandResult start = await commandRunner.RunAsync(
            CreateStartInfo(
                "trace",
                "start",
                $"sessionname={sessionName}",
                "capture=yes",
                "capturetype=physical",
                "report=disabled",
                "persistent=no",
                $"traceFile={outputPath}",
                $"maxSize={maximumMebibytes.ToString(CultureInfo.InvariantCulture)}",
                "fileMode=single",
                "overwrite=no",
                "correlation=disabled",
                $"IPv4.Address={canonicalTarget}"),
            startCommandTimeout,
            cancellationToken).ConfigureAwait(false);

        CaptureProviderFailureCode startFailure = ClassifyCommandFailure(
            start,
            CaptureProviderFailureCode.StartFailed,
            CaptureProviderFailureCode.StartTimeout);
        if (startFailure == CaptureProviderFailureCode.None)
        {
            CaptureProviderSessionHandle handle =
                CaptureProviderSessionHandle.Create(
                    ProviderIdentifier,
                    request.Identity.InvocationId,
                    sessionName);
            var state = new OwnedSession(
                handle,
                outputPath,
                request.MaxDuration);
            if (!ownedSessions.TryAdd(sessionName, state))
            {
                return CaptureProviderStartResult.Failed(
                    CaptureProviderFailureCode.CaptureBusy,
                    "The provider session name is already owned by this provider.");
            }

            state.DurationTask = EnforceMaximumDurationAsync(state);
            return CaptureProviderStartResult.Started(handle);
        }

        if (startFailure == CaptureProviderFailureCode.StartTimeout)
        {
            return await ResolveTimedOutStartAsync(
                request,
                sessionName,
                outputPath,
                cancellationToken).ConfigureAwait(false);
        }

        return CaptureProviderStartResult.Failed(
            startFailure,
            "The capture provider could not start the named session.");
    }

    public async Task<CaptureProviderReadinessResult> WaitForReadinessAsync(
        CaptureProviderSessionHandle handle,
        CancellationToken cancellationToken)
    {
        if (!TryGetOwnedSession(handle, out OwnedSession state))
        {
            return CaptureProviderReadinessResult.Failed(
                CaptureProviderFailureCode.OwnershipMismatch,
                "The capture session is not owned by this provider instance.");
        }

        ProcessCommandResult status = await RunStatusAsync(
            state.Handle.SessionId,
            startCommandTimeout,
            cancellationToken).ConfigureAwait(false);
        CaptureProviderFailureCode failure = ClassifyCommandFailure(
            status,
            CaptureProviderFailureCode.ReadinessUnverified,
            CaptureProviderFailureCode.StartTimeout);
        if (failure != CaptureProviderFailureCode.None)
        {
            return CaptureProviderReadinessResult.Failed(
                failure,
                "Named capture readiness could not be verified.");
        }

        return StatusProvesExpectedSession(
            status,
            state.Handle.SessionId,
            state.OutputPath)
            ? CaptureProviderReadinessResult.Ready(
                "Named status confirmed the running provider session and ETL path.")
            : CaptureProviderReadinessResult.Unverified(
                "Named status did not confirm the expected running session and ETL path.");
    }

    public async Task<CaptureProviderHealthResult> ObserveHealthAsync(
        CaptureProviderSessionHandle handle,
        CancellationToken cancellationToken)
    {
        if (!TryGetOwnedSession(handle, out OwnedSession state))
        {
            return CaptureProviderHealthResult.Failed(
                CaptureProviderFailureCode.OwnershipMismatch,
                "The capture session is not owned by this provider instance.");
        }

        if (Volatile.Read(ref state.StopCompleted) != 0)
        {
            return CaptureProviderHealthResult.ExitedEarly(
                "The capture session has already stopped.");
        }

        if (state.MaximumDurationCoordinationFailed)
        {
            return CaptureProviderHealthResult.Failed(
                CaptureProviderFailureCode.HealthFailed,
                "Maximum-duration coordination failed.");
        }

        ProcessCommandResult status = await RunStatusAsync(
            state.Handle.SessionId,
            startCommandTimeout,
            cancellationToken).ConfigureAwait(false);
        CaptureProviderFailureCode failure = ClassifyCommandFailure(
            status,
            CaptureProviderFailureCode.HealthFailed,
            CaptureProviderFailureCode.HealthTimeout);
        if (failure != CaptureProviderFailureCode.None)
        {
            return failure == CaptureProviderFailureCode.HealthTimeout
                ? CaptureProviderHealthResult.TimedOut(
                    "Named capture health inspection timed out.")
                : CaptureProviderHealthResult.Failed(
                    failure,
                    "Named capture health inspection failed.");
        }

        return StatusProvesExpectedSession(
            status,
            state.Handle.SessionId,
            state.OutputPath)
            ? CaptureProviderHealthResult.Healthy(
                "Named status confirmed the expected running provider session.")
            : CaptureProviderHealthResult.ExitedEarly(
                "Named status did not confirm the expected running provider session.");
    }

    public Task<CaptureProviderStopResult> RequestStopAsync(
        CaptureProviderSessionHandle handle,
        CancellationToken cancellationToken)
    {
        if (!TryGetOwnedSession(handle, out OwnedSession state))
        {
            return Task.FromResult(
                CaptureProviderStopResult.Failed(
                    writerResolved: true,
                    CaptureProviderFailureCode.OwnershipMismatch,
                    "The capture session is not owned by this provider instance."));
        }

        return StopOwnedSessionAsync(state, cancellationToken);
    }

    public async Task<CaptureProviderFinalizationResult> WaitForFinalizationAsync(
        CaptureProviderSessionHandle handle,
        CancellationToken cancellationToken)
    {
        if (!TryGetOwnedSession(handle, out OwnedSession state))
        {
            return CaptureProviderFinalizationResult.Failed(
                CaptureProviderFailureCode.OwnershipMismatch,
                "The capture session is not owned by this provider instance.");
        }

        if (cancellationToken.IsCancellationRequested)
        {
            return CaptureProviderFinalizationResult.Failed(
                CaptureProviderFailureCode.Cancelled,
                "Capture finalization was cancelled.");
        }

        if (Volatile.Read(ref state.StopCompleted) == 0)
        {
            return CaptureProviderFinalizationResult.Failed(
                CaptureProviderFailureCode.FinalizationFailed,
                "The capture writer has not been resolved.");
        }

        try
        {
            StorageArtifactPath.EnsureNoReparsePoints(
                state.ArtifactRoot,
                state.OutputPath);
            using var stream = new FileStream(
                state.OutputPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.None,
                bufferSize: 81920,
                FileOptions.SequentialScan);
            if (stream.Length == 0)
            {
                return CaptureProviderFinalizationResult.Failed(
                    CaptureProviderFailureCode.FinalizationFailed,
                    "The capture ETL is empty.");
            }

            long byteCount = stream.Length;
            string sha256 = Convert.ToHexString(SHA256.HashData(stream));
            ArtifactRecord artifact = ArtifactRecord.CreateFinalized(
                OutputFileName,
                ProviderIdentifier,
                byteCount,
                sha256,
                ArtifactConfidentiality.Restricted,
                ArtifactRelation.Original,
                "application/octet-stream");
            return CaptureProviderFinalizationResult.Finalized(
                "The closed, nonempty capture ETL was finalized.",
                new[] { artifact });
        }
        catch (Exception exception)
            when (exception is IOException
                or UnauthorizedAccessException
                or ArtifactStorageException)
        {
            return CaptureProviderFinalizationResult.Failed(
                CaptureProviderFailureCode.FinalizationFailed,
                "The capture ETL could not be finalized safely.");
        }
    }

    private bool TryPrepareStart(
        CaptureProviderStartRequest request,
        out string sessionName,
        out string outputPath,
        out string canonicalTarget,
        out long maximumMebibytes,
        out CaptureProviderStartResult? failure)
    {
        sessionName = $"WPTS_{request.Identity.InvocationId.ToLowerInvariant()}";
        outputPath = string.Empty;
        canonicalTarget = string.Empty;
        maximumMebibytes = 0;
        failure = null;

        if (!string.Equals(
                request.NativeFormat,
                "Native",
                StringComparison.OrdinalIgnoreCase))
        {
            failure = CaptureProviderStartResult.Failed(
                CaptureProviderFailureCode.StartFailed,
                "The requested native capture format is unsupported.");
            return false;
        }

        if (request.TargetIds.Count != 1 ||
            !IPAddress.TryParse(request.TargetIds[0], out IPAddress? address) ||
            address.AddressFamily != AddressFamily.InterNetwork ||
            !string.Equals(
                request.TargetIds[0],
                address.ToString(),
                StringComparison.Ordinal))
        {
            failure = CaptureProviderStartResult.Failed(
                CaptureProviderFailureCode.TargetAmbiguous,
                "Netsh capture requires exactly one canonical IPv4 target.");
            return false;
        }

        maximumMebibytes = request.MaxBytes / BytesPerMebibyte;
        if (maximumMebibytes <= 0)
        {
            failure = CaptureProviderStartResult.Failed(
                CaptureProviderFailureCode.StartFailed,
                "The maximum capture size cannot be represented as a positive whole MiB.");
            return false;
        }

        try
        {
            outputPath = StorageArtifactPath.CombineUnderRoot(
                request.ArtifactInvocation.DirectoryPath,
                OutputFileName);
            StorageArtifactPath.EnsureNoReparsePoints(
                request.ArtifactInvocation.DirectoryPath,
                outputPath);
        }
        catch (ArtifactStorageException)
        {
            failure = CaptureProviderStartResult.Failed(
                CaptureProviderFailureCode.StartFailed,
                "The capture output path is not safe.");
            return false;
        }

        canonicalTarget = address.ToString();
        return true;
    }

    private async Task<CaptureProviderStartResult> ResolveTimedOutStartAsync(
        CaptureProviderStartRequest request,
        string sessionName,
        string outputPath,
        CancellationToken cancellationToken)
    {
        ProcessCommandResult status = await RunStatusAsync(
            sessionName,
            startCommandTimeout,
            cancellationToken).ConfigureAwait(false);
        if (!StatusProvesExpectedSession(status, sessionName, outputPath))
        {
            return CaptureProviderStartResult.Failed(
                CaptureProviderFailureCode.StartTimeout,
                "Capture start timed out without proving an owned running session.");
        }

        CaptureProviderSessionHandle handle = CaptureProviderSessionHandle.Create(
            ProviderIdentifier,
            request.Identity.InvocationId,
            sessionName);
        var state = new OwnedSession(handle, outputPath, request.MaxDuration);
        if (!ownedSessions.TryAdd(sessionName, state))
        {
            return CaptureProviderStartResult.Failed(
                CaptureProviderFailureCode.CaptureBusy,
                "The provider session name is already owned by this provider.");
        }

        CaptureProviderStopResult cleanup = await StopOwnedSessionAsync(
            state,
            CancellationToken.None).ConfigureAwait(false);
        if (cleanup.WriterResolved)
        {
            return CaptureProviderStartResult.Failed(
                CaptureProviderFailureCode.StartTimeout,
                "Capture start timed out and the proven named session was cleaned up.");
        }

        return CaptureProviderStartResult.FailedWithOwnedHandle(
            handle,
            CaptureProviderFailureCode.StartTimeout,
            "Capture start timed out and the proven named session still requires cleanup.");
    }

    private async Task<CaptureProviderStopResult> StopOwnedSessionAsync(
        OwnedSession state,
        CancellationToken cancellationToken)
    {
        try
        {
            await state.StopGate.WaitAsync(cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return CaptureProviderStopResult.Failed(
                writerResolved: false,
                CaptureProviderFailureCode.Cancelled,
                "Capture stop was cancelled.");
        }

        try
        {
            if (Volatile.Read(ref state.StopCompleted) != 0)
            {
                return CaptureProviderStopResult.AlreadyStopped(
                    "The owned named capture session is already stopped.");
            }

            ProcessCommandResult stop = await commandRunner.RunAsync(
                CreateStartInfo(
                    "trace",
                    "stop",
                    $"sessionname={state.Handle.SessionId}"),
                stopCommandTimeout,
                cancellationToken).ConfigureAwait(false);
            CaptureProviderFailureCode failure = ClassifyCommandFailure(
                stop,
                CaptureProviderFailureCode.StopFailed,
                CaptureProviderFailureCode.StopTimeout);
            if (failure != CaptureProviderFailureCode.None)
            {
                return CaptureProviderStopResult.Failed(
                    writerResolved: false,
                    failure,
                    "The owned named capture session could not be stopped.");
            }

            Volatile.Write(ref state.StopCompleted, 1);
            state.DurationCancellation.Cancel();
            if (state.MaximumDurationCoordinationFailed)
            {
                return CaptureProviderStopResult.Failed(
                    writerResolved: true,
                    CaptureProviderFailureCode.HealthFailed,
                    "Maximum-duration coordination failed; the named trace writer was resolved.");
            }

            return CaptureProviderStopResult.Stopped(
                "The owned named capture session stopped.");
        }
        finally
        {
            state.StopGate.Release();
        }
    }

    private async Task EnforceMaximumDurationAsync(OwnedSession state)
    {
        try
        {
            await delayAsync(
                    state.MaximumDuration,
                    state.DurationCancellation.Token)
                .ConfigureAwait(false);
            await StopOwnedSessionAsync(state, CancellationToken.None)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
            when (state.DurationCancellation.IsCancellationRequested)
        {
        }
        catch (Exception)
        {
            state.MarkMaximumDurationCoordinationFailed();
        }
    }

    private Task<ProcessCommandResult> RunStatusAsync(
        string sessionName,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        // "netsh trace show status" cannot address a named session on current
        // Windows builds; the session is visible to ETW as "<name>-NetTrace-1".
        return commandRunner.RunAsync(
            CreateStartInfoFor(
                statusExecutablePath,
                "query",
                $"{sessionName}{EtwSessionSuffix}",
                "-ets"),
            timeout,
            cancellationToken);
    }

    private ProcessStartInfo CreateStartInfo(params string[] arguments)
    {
        return CreateStartInfoFor(executablePath, arguments);
    }

    private static ProcessStartInfo CreateStartInfoFor(
        string fileName,
        params string[] arguments)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };

        foreach (string argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        return startInfo;
    }

    private static CaptureProviderFailureCode ClassifyCommandFailure(
        ProcessCommandResult result,
        CaptureProviderFailureCode defaultFailure,
        CaptureProviderFailureCode timeoutFailure)
    {
        if (result.Status == ProcessCommandStatus.Completed &&
            result.ExitCode == 0)
        {
            return CaptureProviderFailureCode.None;
        }

        if (result.Status == ProcessCommandStatus.ToolMissing)
        {
            return CaptureProviderFailureCode.ToolMissing;
        }

        if (result.Status == ProcessCommandStatus.PermissionDenied ||
            result.Status == ProcessCommandStatus.Completed &&
            result.ExitCode == 5)
        {
            return CaptureProviderFailureCode.PermissionDenied;
        }

        if (result.Status == ProcessCommandStatus.TimedOut)
        {
            return timeoutFailure;
        }

        if (result.Status == ProcessCommandStatus.Cancelled)
        {
            return CaptureProviderFailureCode.Cancelled;
        }

        return defaultFailure;
    }

    private static bool StatusShowsRunningSession(
        ProcessCommandResult result,
        string sessionName)
    {
        return IsSuccessful(result) &&
            ContainsStatusValue(result, sessionName) &&
            ContainsStatusValue(result, "running");
    }

    private static bool StatusShowsNoActiveSession(
        ProcessCommandResult result)
    {
        return result.Status == ProcessCommandStatus.Completed &&
            result.ExitCode is not 0 &&
            ContainsStatusValue(result, "Data Collector Set was not found");
    }

    private static bool StatusProvesExpectedSession(
        ProcessCommandResult result,
        string sessionName,
        string outputPath)
    {
        return StatusShowsRunningSession(result, sessionName) &&
            ContainsStatusValue(result, outputPath);
    }

    private static bool IsSuccessful(ProcessCommandResult result)
    {
        return result.Status == ProcessCommandStatus.Completed &&
            result.ExitCode == 0;
    }

    private static bool ContainsStatusValue(
        ProcessCommandResult result,
        string expected)
    {
        return result.StandardOutput.Contains(
                expected,
                StringComparison.OrdinalIgnoreCase) ||
            result.StandardError.Contains(
                expected,
                StringComparison.OrdinalIgnoreCase);
    }

    private bool TryGetOwnedSession(
        CaptureProviderSessionHandle handle,
        out OwnedSession state)
    {
        state = null!;
        if (handle is null ||
            !string.Equals(
                handle.ProviderId,
                ProviderIdentifier,
                StringComparison.Ordinal) ||
            !ownedSessions.TryGetValue(
                handle.SessionId,
                out OwnedSession? owned) ||
            owned is null ||
            !ReferenceEquals(handle, owned.Handle) ||
            !string.Equals(
                handle.OwnerInvocationId,
                owned.Handle.OwnerInvocationId,
                StringComparison.Ordinal))
        {
            return false;
        }

        state = owned;
        return true;
    }

    private sealed class OwnedSession
    {
        private int maximumDurationCoordinationFailed;

        public OwnedSession(
            CaptureProviderSessionHandle handle,
            string outputPath,
            TimeSpan maximumDuration)
        {
            Handle = handle;
            OutputPath = outputPath;
            ArtifactRoot = Path.GetDirectoryName(outputPath) ??
                throw new ArgumentException(
                    "The capture output path must have a parent directory.",
                    nameof(outputPath));
            MaximumDuration = maximumDuration;
        }

        public CaptureProviderSessionHandle Handle { get; }

        public string OutputPath { get; }

        public string ArtifactRoot { get; }

        public TimeSpan MaximumDuration { get; }

        public CancellationTokenSource DurationCancellation { get; } = new();

        public SemaphoreSlim StopGate { get; } = new(1, 1);

        public Task? DurationTask { get; set; }

        public bool MaximumDurationCoordinationFailed =>
            Volatile.Read(ref maximumDurationCoordinationFailed) != 0;

        public int StopCompleted;

        public void MarkMaximumDurationCoordinationFailed()
        {
            Interlocked.Exchange(ref maximumDurationCoordinationFailed, 1);
        }
    }
}
