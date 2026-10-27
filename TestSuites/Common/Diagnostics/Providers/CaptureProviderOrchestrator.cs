// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Protocols.TestSuites.Diagnostics.Errors;
using Microsoft.Protocols.TestSuites.Diagnostics.Evidence;

namespace Microsoft.Protocols.TestSuites.Diagnostics.Providers;

public enum CaptureProviderLifecycleState
{
    Disabled,
    Allocated,
    Starting,
    Capturing,
    Stopping,
    Finalizing,
    Completed,
    Unavailable,
    Failed,
    Abandoned,
}

public sealed class CaptureProviderCompletionResult
{
    internal CaptureProviderCompletionResult(
        CaptureProviderLifecycleState state,
        CaptureProviderStopStatus? stopStatus,
        CaptureProviderFinalizationStatus? finalizationStatus,
        CaptureProviderFailureCode failureCode,
        bool writerResolved,
        string? stopDetail,
        string? finalizationDetail,
        IReadOnlyList<ArtifactRecord>? artifacts,
        bool collectionComplete = true)
    {
        State = state;
        StopStatus = stopStatus;
        FinalizationStatus = finalizationStatus;
        FailureCode = failureCode;
        WriterResolved = writerResolved;
        StopDetail = stopDetail;
        FinalizationDetail = finalizationDetail;
        Artifacts = artifacts ?? Array.Empty<ArtifactRecord>();
        CollectionComplete = collectionComplete;
    }

    public CaptureProviderLifecycleState State { get; }

    public CaptureProviderStopStatus? StopStatus { get; }

    public CaptureProviderFinalizationStatus? FinalizationStatus { get; }

    public CaptureProviderFailureCode FailureCode { get; }

    public bool WriterResolved { get; }

    public string? StopDetail { get; }

    public string? FinalizationDetail { get; }

    public IReadOnlyList<ArtifactRecord> Artifacts { get; }

    public bool CollectionComplete { get; }
}

public sealed class CaptureProviderOrchestrator
{
    private readonly bool enabled;
    private readonly DiagnosticErrorLedger errors;

    private CaptureProviderOrchestrator(bool enabled, DiagnosticErrorLedger errors)
    {
        this.enabled = enabled;
        this.errors = errors ?? throw new ArgumentNullException(nameof(errors));
    }

    public static CaptureProviderOrchestrator CreateDisabled(
        DiagnosticErrorLedger errors)
    {
        return new CaptureProviderOrchestrator(enabled: false, errors);
    }

    public static CaptureProviderOrchestrator CreateEnabled(
        DiagnosticErrorLedger errors)
    {
        return new CaptureProviderOrchestrator(enabled: true, errors);
    }

    public async Task<CaptureProviderSession> StartAsync(
        Func<CaptureProviderStartRequest> requestFactory,
        Func<ICaptureProvider> providerFactory,
        CaptureProviderTimeouts timeouts,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestFactory);
        ArgumentNullException.ThrowIfNull(providerFactory);
        ArgumentNullException.ThrowIfNull(timeouts);

        if (!enabled)
        {
            return CaptureProviderSession.Disabled(errors);
        }

        if (cancellationToken.IsCancellationRequested)
        {
            return Unavailable(
                CaptureProviderFailureCode.Cancelled,
                "Capture provider startup was cancelled before any provider work began.");
        }

        CaptureProviderStartRequest request;
        try
        {
            request = requestFactory() ??
                throw new InvalidOperationException(
                    "The capture provider request factory returned null.");
        }
        catch (Exception)
        {
            return Unavailable(
                CaptureProviderFailureCode.RequestCreationFailed,
                "Capture provider request creation failed.");
        }

        ICaptureProvider provider;
        string providerId;
        try
        {
            provider = providerFactory() ??
                throw new InvalidOperationException(
                    "The capture provider factory returned null.");
            providerId = ProviderContractValidation.RequireText(
                provider.ProviderId,
                nameof(provider.ProviderId));
        }
        catch (Exception)
        {
            return Unavailable(
                CaptureProviderFailureCode.ProviderCreationFailed,
                "Capture provider creation failed.");
        }

        CaptureProviderProbeResult probe;
        try
        {
            probe = await ProviderOperationRunner.RunAsync(
                    token => provider.ProbeAsync(request, token),
                    timeouts.StartTimeout,
                    cancellationToken)
                .ConfigureAwait(false) ??
                throw new InvalidOperationException(
                    "The capture provider returned a null probe result.");
        }
        catch (TimeoutException)
        {
            return Unavailable(
                CaptureProviderFailureCode.StartTimeout,
                "Capture provider probing exceeded the startup timeout.");
        }
        catch (OperationCanceledException)
        {
            return Unavailable(
                CaptureProviderFailureCode.Cancelled,
                "Capture provider probing was cancelled.");
        }
        catch (Exception)
        {
            return Unavailable(
                CaptureProviderFailureCode.ProbeFailed,
                "Capture provider probing failed.");
        }

        if (!probe.IsAvailable)
        {
            return Unavailable(
                probe.FailureCode,
                probe.Detail ?? "Capture provider probing reported unavailable.");
        }

        if (!string.Equals(
                providerId,
                probe.Capabilities?.ProviderId,
                StringComparison.Ordinal))
        {
            return Unavailable(
                CaptureProviderFailureCode.OwnershipMismatch,
                "The provider probe identity did not match the selected provider.");
        }

        CaptureProviderStartResult start;
        try
        {
            start = await ProviderOperationRunner.RunAsync(
                    token => provider.StartAsync(request, token),
                    timeouts.StartTimeout,
                    cancellationToken)
                .ConfigureAwait(false) ??
                throw new InvalidOperationException(
                    "The capture provider returned a null start result.");
        }
        catch (TimeoutException)
        {
            return Unresolved(
                CaptureProviderFailureCode.StartTimeout,
                "Capture provider startup exceeded the startup timeout; a partial writer may still exist.");
        }
        catch (OperationCanceledException)
        {
            return Unresolved(
                CaptureProviderFailureCode.Cancelled,
                "Capture provider startup was cancelled; a partial writer may still exist.");
        }
        catch (Exception)
        {
            return Unresolved(
                CaptureProviderFailureCode.StartFailed,
                "Capture provider startup failed and may have left a partial writer.");
        }

        if (!start.IsStarted)
        {
            if (start.Handle is not null)
            {
                if (!CaptureProviderSession.IsOwnedHandle(
                        providerId,
                        request,
                        start.Handle))
                {
                    return Unresolved(
                        CaptureProviderFailureCode.OwnershipMismatch,
                        "The failed start returned a partial handle not owned by this invocation.");
                }

                CaptureProviderFailureCode failureCode =
                    ProviderContractValidation.RequireFailure(
                        start.FailureCode,
                        nameof(start.FailureCode));
                string detail =
                    start.Detail ?? "Capture provider startup reported partial failure.";
                Record(DiagnosticErrorCategory.Capture, failureCode, detail);
                return CaptureProviderSession.OwnedFailure(
                    provider,
                    providerId,
                    request,
                    start.Handle,
                    probe.Capabilities!,
                    failureCode,
                    detail,
                    errors);
            }

            if (!start.WriterResolved)
            {
                return Unresolved(
                    start.FailureCode,
                    start.Detail ??
                    "Capture provider startup reported an unresolved writer without an owned handle.");
            }

            return Unavailable(
                start.FailureCode,
                start.Detail ?? "Capture provider startup reported failure.");
        }

        if (start.Handle is null)
        {
            return Unresolved(
                CaptureProviderFailureCode.StartFailed,
                "Capture provider startup reported success without an owned handle.");
        }

        CaptureProviderSessionHandle handle = start.Handle;
        if (!CaptureProviderSession.IsOwnedHandle(providerId, request, handle))
        {
            return Unresolved(
                CaptureProviderFailureCode.OwnershipMismatch,
                "The provider returned a handle that is not owned by this invocation.");
        }

        CaptureProviderReadinessStatus readinessStatus;
        CaptureProviderFailureCode startupFailureCode;
        string readinessDetail;
        try
        {
            CaptureProviderReadinessResult readiness =
                await ProviderOperationRunner.RunAsync(
                        token => provider.WaitForReadinessAsync(handle, token),
                        timeouts.StartTimeout,
                        cancellationToken)
                    .ConfigureAwait(false) ??
                    throw new InvalidOperationException(
                        "The capture provider returned a null readiness result.");
            readinessStatus = readiness.Status;
            startupFailureCode = readiness.FailureCode;
            readinessDetail = readiness.Detail;
            if (readiness.FailureCode != CaptureProviderFailureCode.None)
            {
                Record(
                    DiagnosticErrorCategory.Capture,
                    readiness.FailureCode,
                    readiness.Detail);
            }
        }
        catch (TimeoutException)
        {
            readinessStatus = CaptureProviderReadinessStatus.TimedOut;
            startupFailureCode = CaptureProviderFailureCode.StartTimeout;
            readinessDetail =
                "Capture provider readiness exceeded the startup timeout.";
            Record(
                DiagnosticErrorCategory.Capture,
                startupFailureCode,
                readinessDetail);
        }
        catch (OperationCanceledException)
        {
            readinessStatus = CaptureProviderReadinessStatus.Cancelled;
            startupFailureCode = CaptureProviderFailureCode.Cancelled;
            readinessDetail = "Capture provider readiness was cancelled.";
            Record(
                DiagnosticErrorCategory.Capture,
                startupFailureCode,
                readinessDetail);
        }
        catch (Exception)
        {
            readinessStatus = CaptureProviderReadinessStatus.Failed;
            startupFailureCode = CaptureProviderFailureCode.StartFailed;
            readinessDetail = "Capture provider readiness failed.";
            Record(
                DiagnosticErrorCategory.Capture,
                startupFailureCode,
                readinessDetail);
        }

        return CaptureProviderSession.Active(
            provider,
            providerId,
            request,
            handle,
            probe.Capabilities!,
            readinessStatus,
            readinessDetail,
            startupFailureCode,
            errors);
    }

    private CaptureProviderSession Unavailable(
        CaptureProviderFailureCode failureCode,
        string message)
    {
        Record(DiagnosticErrorCategory.Capture, failureCode, message);
        return CaptureProviderSession.Unavailable(failureCode, errors);
    }

    private CaptureProviderSession Unresolved(
        CaptureProviderFailureCode failureCode,
        string message)
    {
        Record(DiagnosticErrorCategory.Capture, failureCode, message);
        return CaptureProviderSession.Unavailable(
            failureCode,
            errors,
            writerResolved: false);
    }

    private void Record(
        DiagnosticErrorCategory category,
        CaptureProviderFailureCode failureCode,
        string message)
    {
        errors.Record(
            category,
            failureCode.ToString(),
            message,
            DateTimeOffset.UtcNow);
    }
}

public sealed class CaptureProviderSession
{
    private readonly object syncRoot = new();
    private readonly ICaptureProvider? provider;
    private readonly string? providerId;
    private readonly CaptureProviderStartRequest? request;
    private readonly CaptureProviderSessionHandle? handle;
    private readonly DiagnosticErrorLedger errors;
    private readonly List<CaptureProviderLifecycleState> stateHistory;
    private readonly bool writerResolvedWithoutHandle;
    private Task<CaptureProviderCompletionResult>? completionTask;
    private CaptureProviderLifecycleState state;

    private CaptureProviderSession(
        CaptureProviderLifecycleState state,
        ICaptureProvider? provider,
        string? providerId,
        CaptureProviderStartRequest? request,
        CaptureProviderSessionHandle? handle,
        CaptureProviderCapabilities? capabilities,
        CaptureProviderReadinessStatus readinessStatus,
        string? readinessDetail,
        CaptureProviderFailureCode startupFailureCode,
        DiagnosticErrorLedger errors,
        IEnumerable<CaptureProviderLifecycleState> initialStateHistory,
        bool writerResolvedWithoutHandle)
    {
        this.state = state;
        this.provider = provider;
        this.providerId = providerId;
        this.request = request;
        this.handle = handle;
        this.errors = errors;
        stateHistory = initialStateHistory.ToList();
        ReadinessStatus = readinessStatus;
        ReadinessDetail = readinessDetail;
        StartupFailureCode = startupFailureCode;
        Capabilities = capabilities;
        this.writerResolvedWithoutHandle = writerResolvedWithoutHandle;
    }

    public CaptureProviderLifecycleState State
    {
        get
        {
            lock (syncRoot)
            {
                return state;
            }
        }
    }

    public CaptureProviderReadinessStatus ReadinessStatus { get; }

    public string? ReadinessDetail { get; }

    public CaptureProviderFailureCode StartupFailureCode { get; }

    public CaptureProviderCapabilities? Capabilities { get; }

    public IReadOnlyList<CaptureProviderLifecycleState> StateHistory
    {
        get
        {
            lock (syncRoot)
            {
                return stateHistory.ToArray();
            }
        }
    }

    internal static CaptureProviderSession Disabled(DiagnosticErrorLedger errors)
    {
        return new CaptureProviderSession(
            CaptureProviderLifecycleState.Disabled,
            provider: null,
            providerId: null,
            request: null,
            handle: null,
            capabilities: null,
            CaptureProviderReadinessStatus.NotStarted,
            readinessDetail: null,
            CaptureProviderFailureCode.None,
            errors,
            new[] { CaptureProviderLifecycleState.Disabled },
            writerResolvedWithoutHandle: true);
    }

    internal static CaptureProviderSession Unavailable(
        CaptureProviderFailureCode failureCode,
        DiagnosticErrorLedger errors,
        bool writerResolved = true)
    {
        return new CaptureProviderSession(
            CaptureProviderLifecycleState.Unavailable,
            provider: null,
            providerId: null,
            request: null,
            handle: null,
            capabilities: null,
            CaptureProviderReadinessStatus.NotStarted,
            readinessDetail: null,
            failureCode,
            errors,
            new[]
            {
                CaptureProviderLifecycleState.Allocated,
                CaptureProviderLifecycleState.Starting,
                CaptureProviderLifecycleState.Unavailable,
            },
            writerResolved);
    }

    internal static CaptureProviderSession Active(
        ICaptureProvider provider,
        string providerId,
        CaptureProviderStartRequest request,
        CaptureProviderSessionHandle handle,
        CaptureProviderCapabilities capabilities,
        CaptureProviderReadinessStatus readinessStatus,
        string readinessDetail,
        CaptureProviderFailureCode startupFailureCode,
        DiagnosticErrorLedger errors)
    {
        return new CaptureProviderSession(
            CaptureProviderLifecycleState.Capturing,
            provider,
            providerId,
            request,
            handle,
            capabilities,
            readinessStatus,
            readinessDetail,
            startupFailureCode,
            errors,
            new[]
            {
                CaptureProviderLifecycleState.Allocated,
                CaptureProviderLifecycleState.Starting,
                CaptureProviderLifecycleState.Capturing,
            },
            writerResolvedWithoutHandle: false);
    }

    internal static CaptureProviderSession OwnedFailure(
        ICaptureProvider provider,
        string providerId,
        CaptureProviderStartRequest request,
        CaptureProviderSessionHandle handle,
        CaptureProviderCapabilities capabilities,
        CaptureProviderFailureCode failureCode,
        string detail,
        DiagnosticErrorLedger errors)
    {
        return new CaptureProviderSession(
            CaptureProviderLifecycleState.Unavailable,
            provider,
            providerId,
            request,
            handle,
            capabilities,
            CaptureProviderReadinessStatus.NotStarted,
            detail,
            failureCode,
            errors,
            new[]
            {
                CaptureProviderLifecycleState.Allocated,
                CaptureProviderLifecycleState.Starting,
                CaptureProviderLifecycleState.Unavailable,
            },
            writerResolvedWithoutHandle: false);
    }

    internal static bool IsOwnedHandle(
        string providerId,
        CaptureProviderStartRequest request,
        CaptureProviderSessionHandle handle)
    {
        return string.Equals(
                   providerId,
                   handle.ProviderId,
                   StringComparison.Ordinal)
               && string.Equals(
                   request.Identity.InvocationId,
                   handle.OwnerInvocationId,
                   StringComparison.Ordinal);
    }

    public Task<CaptureProviderCompletionResult> CompleteAsync(
        CaptureProviderTimeouts timeouts,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(timeouts);

        lock (syncRoot)
        {
            completionTask ??= Task.Run(
                () => CompleteCoreAsync(timeouts, cancellationToken),
                CancellationToken.None);
            return completionTask;
        }
    }

    public async Task<CaptureProviderHealthResult> ObserveHealthAsync(
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        ProviderContractValidation.ValidateTimeout(timeout, nameof(timeout));
        if (State == CaptureProviderLifecycleState.Disabled)
        {
            return CaptureProviderHealthResult.Disabled();
        }

        if (State != CaptureProviderLifecycleState.Capturing)
        {
            const string Message =
                "Capture health can be observed only while the owned session is capturing.";
            Record(
                DiagnosticErrorCategory.Capture,
                CaptureProviderFailureCode.HealthFailed,
                Message);
            return CaptureProviderHealthResult.Failed(
                CaptureProviderFailureCode.HealthFailed,
                Message);
        }

        if (provider is null ||
            providerId is null ||
            request is null ||
            handle is null)
        {
            return CaptureProviderHealthResult.Failed(
                CaptureProviderFailureCode.HealthFailed,
                "Capture health is unavailable because no provider session is active.");
        }

        if (!IsOwnedHandle(providerId, request, handle))
        {
            const string Message =
                "Capture health observation refused a handle not owned by this invocation.";
            Record(
                DiagnosticErrorCategory.Capture,
                CaptureProviderFailureCode.OwnershipMismatch,
                Message);
            return CaptureProviderHealthResult.Failed(
                CaptureProviderFailureCode.OwnershipMismatch,
                Message);
        }

        if (cancellationToken.IsCancellationRequested)
        {
            const string Message = "Capture health observation was cancelled.";
            Record(
                DiagnosticErrorCategory.Capture,
                CaptureProviderFailureCode.Cancelled,
                Message);
            return CaptureProviderHealthResult.Cancelled(Message);
        }

        CaptureProviderHealthResult health;
        try
        {
            health = await ProviderOperationRunner.RunAsync(
                    token => provider.ObserveHealthAsync(handle, token),
                    timeout,
                    cancellationToken)
                .ConfigureAwait(false) ??
                throw new InvalidOperationException(
                    "The capture provider returned a null health result.");
        }
        catch (TimeoutException)
        {
            const string Message =
                "Capture health observation exceeded its bounded timeout.";
            Record(
                DiagnosticErrorCategory.Capture,
                CaptureProviderFailureCode.HealthTimeout,
                Message);
            return CaptureProviderHealthResult.TimedOut(Message);
        }
        catch (OperationCanceledException)
        {
            const string Message = "Capture health observation was cancelled.";
            Record(
                DiagnosticErrorCategory.Capture,
                CaptureProviderFailureCode.Cancelled,
                Message);
            return CaptureProviderHealthResult.Cancelled(Message);
        }
        catch (Exception)
        {
            const string message = "Capture health observation failed.";
            Record(
                DiagnosticErrorCategory.Capture,
                CaptureProviderFailureCode.HealthFailed,
                message);
            return CaptureProviderHealthResult.Failed(
                CaptureProviderFailureCode.HealthFailed,
                message);
        }

        if (health.FailureCode != CaptureProviderFailureCode.None)
        {
            Record(
                DiagnosticErrorCategory.Capture,
                health.FailureCode,
                health.Detail);
        }

        return health;
    }

    private async Task<CaptureProviderCompletionResult> CompleteCoreAsync(
        CaptureProviderTimeouts timeouts,
        CancellationToken cancellationToken)
    {
        if (State == CaptureProviderLifecycleState.Disabled)
        {
            return Result(
                CaptureProviderLifecycleState.Disabled,
                stopStatus: null,
                finalizationStatus: null,
                CaptureProviderFailureCode.None,
                writerResolved: true);
        }

        if (provider is null ||
            providerId is null ||
            request is null ||
            handle is null)
        {
            CaptureProviderLifecycleState terminalState =
                writerResolvedWithoutHandle
                    ? CaptureProviderLifecycleState.Unavailable
                    : CaptureProviderLifecycleState.Abandoned;
            return Result(
                terminalState,
                stopStatus: null,
                finalizationStatus: null,
                StartupFailureCode,
                writerResolvedWithoutHandle);
        }

        if (!IsOwnedHandle(providerId, request, handle))
        {
            return Failure(
                DiagnosticErrorCategory.Cleanup,
                CaptureProviderLifecycleState.Abandoned,
                CaptureProviderFailureCode.OwnershipMismatch,
                "Capture cleanup refused a handle not owned by this invocation.",
                stopStatus: null,
                finalizationStatus: null,
                writerResolved: false);
        }

        if (cancellationToken.IsCancellationRequested)
        {
            return Failure(
                DiagnosticErrorCategory.Cleanup,
                CaptureProviderLifecycleState.Abandoned,
                CaptureProviderFailureCode.Cancelled,
                "Capture provider cleanup was cancelled before stop began.",
                stopStatus: null,
                finalizationStatus: null,
                writerResolved: false);
        }

        SetState(CaptureProviderLifecycleState.Stopping);
        CaptureProviderStopResult stop;
        try
        {
            stop = await ProviderOperationRunner.RunAsync(
                    token => provider.RequestStopAsync(handle, token),
                    timeouts.StopTimeout,
                    cancellationToken)
                .ConfigureAwait(false) ??
                throw new InvalidOperationException(
                    "The capture provider returned a null stop result.");
        }
        catch (TimeoutException)
        {
            return Failure(
                DiagnosticErrorCategory.Cleanup,
                CaptureProviderLifecycleState.Abandoned,
                CaptureProviderFailureCode.StopTimeout,
                "Capture provider stop exceeded the stop timeout; the writer is unresolved.",
                stopStatus: null,
                finalizationStatus: null,
                writerResolved: false);
        }
        catch (OperationCanceledException)
        {
            return Failure(
                DiagnosticErrorCategory.Cleanup,
                CaptureProviderLifecycleState.Abandoned,
                CaptureProviderFailureCode.Cancelled,
                "Capture provider stop was cancelled; the writer is unresolved.",
                stopStatus: null,
                finalizationStatus: null,
                writerResolved: false);
        }
        catch (Exception)
        {
            return Failure(
                DiagnosticErrorCategory.Cleanup,
                CaptureProviderLifecycleState.Abandoned,
                CaptureProviderFailureCode.StopFailed,
                "Capture provider stop failed.",
                stopStatus: null,
                finalizationStatus: null,
                writerResolved: false);
        }

        CaptureProviderFailureCode completionFailure = StartupFailureCode;
        if (stop.FailureCode != CaptureProviderFailureCode.None)
        {
            completionFailure = stop.FailureCode;
            Record(DiagnosticErrorCategory.Cleanup, stop.FailureCode, stop.Detail);
        }

        if (!stop.WriterResolved)
        {
            return Result(
                CaptureProviderLifecycleState.Abandoned,
                stop.Status,
                finalizationStatus: null,
                stop.FailureCode,
                writerResolved: false);
        }

        SetState(CaptureProviderLifecycleState.Finalizing);
        CaptureProviderFinalizationResult finalization;
        try
        {
            finalization = await ProviderOperationRunner.RunAsync(
                    token => provider.WaitForFinalizationAsync(handle, token),
                    timeouts.FinalizationTimeout,
                    cancellationToken)
                .ConfigureAwait(false) ??
                throw new InvalidOperationException(
                    "The capture provider returned a null finalization result.");
        }
        catch (TimeoutException)
        {
            return Failure(
                DiagnosticErrorCategory.Finalization,
                CaptureProviderLifecycleState.Failed,
                CaptureProviderFailureCode.FinalizationTimeout,
                "Capture provider finalization exceeded the finalization timeout.",
                stop.Status,
                finalizationStatus: null,
                writerResolved: true);
        }
        catch (OperationCanceledException)
        {
            return Failure(
                DiagnosticErrorCategory.Finalization,
                CaptureProviderLifecycleState.Failed,
                CaptureProviderFailureCode.Cancelled,
                "Capture provider finalization was cancelled.",
                stop.Status,
                finalizationStatus: null,
                writerResolved: true);
        }
        catch (Exception)
        {
            return Failure(
                DiagnosticErrorCategory.Finalization,
                CaptureProviderLifecycleState.Failed,
                CaptureProviderFailureCode.FinalizationFailed,
                "Capture provider finalization failed.",
                stop.Status,
                finalizationStatus: null,
                writerResolved: true);
        }

        if (finalization.FailureCode != CaptureProviderFailureCode.None)
        {
            return Failure(
                DiagnosticErrorCategory.Finalization,
                CaptureProviderLifecycleState.Failed,
                finalization.FailureCode,
                finalization.Detail,
                stop.Status,
                finalization.Status,
                writerResolved: true,
                stopDetail: stop.Detail,
                finalizationDetail: finalization.Detail,
                artifacts: finalization.Artifacts);
        }

        return Result(
            CaptureProviderLifecycleState.Completed,
            stop.Status,
            finalization.Status,
            completionFailure,
            writerResolved: true,
            stop.Detail,
            finalization.Detail,
            finalization.Artifacts,
            finalization.CollectionComplete);
    }

    private CaptureProviderCompletionResult Failure(
        DiagnosticErrorCategory category,
        CaptureProviderLifecycleState terminalState,
        CaptureProviderFailureCode failureCode,
        string message,
        CaptureProviderStopStatus? stopStatus,
        CaptureProviderFinalizationStatus? finalizationStatus,
        bool writerResolved,
        string? stopDetail = null,
        string? finalizationDetail = null,
        IReadOnlyList<ArtifactRecord>? artifacts = null)
    {
        Record(category, failureCode, message);
        return Result(
            terminalState,
            stopStatus,
            finalizationStatus,
            failureCode,
            writerResolved,
            stopDetail,
            finalizationDetail,
            artifacts);
    }

    private void Record(
        DiagnosticErrorCategory category,
        CaptureProviderFailureCode failureCode,
        string message)
    {
        errors.Record(
            category,
            failureCode.ToString(),
            GetSafeErrorMessage(failureCode, message),
            DateTimeOffset.UtcNow);
    }

    private static string GetSafeErrorMessage(
        CaptureProviderFailureCode failureCode,
        string message)
    {
        return failureCode switch
        {
            CaptureProviderFailureCode.None => message,
            CaptureProviderFailureCode.Cancelled =>
                "The capture provider operation was cancelled.",
            CaptureProviderFailureCode.StartTimeout =>
                "The capture provider startup operation timed out.",
            CaptureProviderFailureCode.StopTimeout =>
                "The capture provider stop operation timed out.",
            CaptureProviderFailureCode.FinalizationTimeout =>
                "The capture provider finalization operation timed out.",
            CaptureProviderFailureCode.HealthTimeout =>
                "The capture provider health operation timed out.",
            _ => "The capture provider operation failed.",
        };
    }

    private CaptureProviderCompletionResult Result(
        CaptureProviderLifecycleState terminalState,
        CaptureProviderStopStatus? stopStatus,
        CaptureProviderFinalizationStatus? finalizationStatus,
        CaptureProviderFailureCode failureCode,
        bool writerResolved,
        string? stopDetail = null,
        string? finalizationDetail = null,
        IReadOnlyList<ArtifactRecord>? artifacts = null,
        bool collectionComplete = true)
    {
        SetState(terminalState);
        return new CaptureProviderCompletionResult(
            terminalState,
            stopStatus,
            finalizationStatus,
            failureCode,
            writerResolved,
            stopDetail,
            finalizationDetail,
            artifacts,
            collectionComplete);
    }

    private void SetState(CaptureProviderLifecycleState value)
    {
        lock (syncRoot)
        {
            state = value;
            if (stateHistory.Count == 0 || stateHistory[^1] != value)
            {
                stateHistory.Add(value);
            }
        }
    }
}

internal static class ProviderOperationRunner
{
    public static async Task<T> RunAsync<T>(
        Func<CancellationToken, Task<T>> operation,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        CancellationTokenSource linkedCancellation =
            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        Task? timeoutCancellationTask = null;
        Task<T> operationTask = Task.Run(
            async () =>
            {
                Task<T> providerTask = operation(linkedCancellation.Token) ??
                    throw new InvalidOperationException(
                        "The capture provider operation returned a null task.");
                return await providerTask.ConfigureAwait(false);
            },
            CancellationToken.None);

        // A timed-out provider may finish later; observe any late fault so it
        // cannot surface as an unobserved task exception.
        ObserveFault(operationTask);

        try
        {
            return await operationTask
                .WaitAsync(timeout, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            timeoutCancellationTask = linkedCancellation.CancelAsync();
            ObserveFault(timeoutCancellationTask);
            throw;
        }
        finally
        {
            Task lifetime = timeoutCancellationTask is null
                ? operationTask
                : Task.WhenAll(operationTask, timeoutCancellationTask);
            DisposeWhenComplete(linkedCancellation, lifetime);
        }
    }

    private static void ObserveFault(Task task)
    {
        _ = task.ContinueWith(
            static completedTask =>
            {
                _ = completedTask.Exception;
            },
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously |
            TaskContinuationOptions.OnlyOnFaulted,
            TaskScheduler.Default);
    }

    private static void DisposeWhenComplete(
        CancellationTokenSource cancellation,
        Task lifetime)
    {
        if (lifetime.IsCompleted)
        {
            _ = lifetime.Exception;
            cancellation.Dispose();
            return;
        }

        _ = lifetime.ContinueWith(
            static (completedTask, state) =>
            {
                _ = completedTask.Exception;
                ((CancellationTokenSource)state!).Dispose();
            },
            cancellation,
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }
}
