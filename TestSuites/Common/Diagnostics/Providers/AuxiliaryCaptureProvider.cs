// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Protocols.TestSuites.Diagnostics.Evidence;

namespace Microsoft.Protocols.TestSuites.Diagnostics.Providers;

/// <summary>
/// Runs a best-effort auxiliary capture provider (for example the RDMA NIC
/// sniffer) alongside a primary provider. The orchestrator sees only the
/// primary provider's identity and results; the auxiliary provider only adds
/// artifacts and never fails the invocation.
/// </summary>
public sealed class AuxiliaryCaptureProvider : ICaptureProvider
{
    private readonly ICaptureProvider primary;
    private readonly ICaptureProvider auxiliary;
    private readonly ConcurrentDictionary<string, AuxiliarySession> sessions =
        new(StringComparer.Ordinal);

    public AuxiliaryCaptureProvider(
        ICaptureProvider primary,
        ICaptureProvider auxiliary)
    {
        this.primary = primary ?? throw new ArgumentNullException(nameof(primary));
        this.auxiliary = auxiliary ?? throw new ArgumentNullException(nameof(auxiliary));
    }

    public string ProviderId => primary.ProviderId;

    public Task<CaptureProviderProbeResult> ProbeAsync(
        CaptureProviderStartRequest request,
        CancellationToken cancellationToken)
    {
        return primary.ProbeAsync(request, cancellationToken);
    }

    public async Task<CaptureProviderStartResult> StartAsync(
        CaptureProviderStartRequest request,
        CancellationToken cancellationToken)
    {
        CaptureProviderStartResult primaryResult = await primary
            .StartAsync(request, cancellationToken)
            .ConfigureAwait(false);
        if (!primaryResult.IsStarted || primaryResult.Handle is null)
        {
            return primaryResult;
        }

        var session = new AuxiliarySession();
        sessions[primaryResult.Handle.SessionId] = session;
        try
        {
            CaptureProviderProbeResult probe = await auxiliary
                .ProbeAsync(request, cancellationToken)
                .ConfigureAwait(false);
            if (probe.IsAvailable)
            {
                CaptureProviderStartResult started = await auxiliary
                    .StartAsync(request, cancellationToken)
                    .ConfigureAwait(false);
                session.Handle = started.IsStarted ? started.Handle : null;
                session.Note = started.IsStarted
                    ? null
                    : $"{auxiliary.ProviderId} start failed: {started.FailureCode}";
            }
            else
            {
                session.Note =
                    $"{auxiliary.ProviderId} unavailable: {probe.FailureCode}";
            }
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            session.Note = $"{auxiliary.ProviderId} start threw {exception.GetType().Name}";
        }

        return primaryResult;
    }

    public async Task<CaptureProviderReadinessResult> WaitForReadinessAsync(
        CaptureProviderSessionHandle handle,
        CancellationToken cancellationToken)
    {
        CaptureProviderReadinessResult result = await primary
            .WaitForReadinessAsync(handle, cancellationToken)
            .ConfigureAwait(false);
        if (TryGetAuxiliaryHandle(handle, out CaptureProviderSessionHandle? aux))
        {
            await IgnoreFailuresAsync(
                () => auxiliary.WaitForReadinessAsync(aux!, cancellationToken))
                .ConfigureAwait(false);
        }

        return result;
    }

    public Task<CaptureProviderHealthResult> ObserveHealthAsync(
        CaptureProviderSessionHandle handle,
        CancellationToken cancellationToken)
    {
        return primary.ObserveHealthAsync(handle, cancellationToken);
    }

    public async Task<CaptureProviderStopResult> RequestStopAsync(
        CaptureProviderSessionHandle handle,
        CancellationToken cancellationToken)
    {
        // Stop the sniffer first so it does not outlive the primary capture.
        if (TryGetAuxiliaryHandle(handle, out CaptureProviderSessionHandle? aux) &&
            sessions.TryGetValue(handle.SessionId, out AuxiliarySession? session))
        {
            CaptureProviderStopResult? stop = await IgnoreFailuresAsync(
                () => auxiliary.RequestStopAsync(aux!, cancellationToken))
                .ConfigureAwait(false);
            session.Stopped = stop is not null &&
                (stop.Status == CaptureProviderStopStatus.Stopped ||
                    stop.Status == CaptureProviderStopStatus.AlreadyStopped);
        }

        return await primary
            .RequestStopAsync(handle, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<CaptureProviderFinalizationResult> WaitForFinalizationAsync(
        CaptureProviderSessionHandle handle,
        CancellationToken cancellationToken)
    {
        CaptureProviderFinalizationResult result = await primary
            .WaitForFinalizationAsync(handle, cancellationToken)
            .ConfigureAwait(false);

        if (result.Status != CaptureProviderFinalizationStatus.Finalized ||
            !TryGetAuxiliaryHandle(handle, out CaptureProviderSessionHandle? aux) ||
            !sessions.TryGetValue(handle.SessionId, out AuxiliarySession? session) ||
            !session.Stopped)
        {
            return result;
        }

        CaptureProviderFinalizationResult? extra = await IgnoreFailuresAsync(
            () => auxiliary.WaitForFinalizationAsync(aux!, cancellationToken))
            .ConfigureAwait(false);
        if (extra is null ||
            extra.Status != CaptureProviderFinalizationStatus.Finalized)
        {
            return result;
        }

        var artifacts = new List<ArtifactRecord>(result.Artifacts);
        artifacts.AddRange(extra.Artifacts);
        return CaptureProviderFinalizationResult.Finalized(
            result.Detail,
            artifacts);
    }

    private bool TryGetAuxiliaryHandle(
        CaptureProviderSessionHandle handle,
        out CaptureProviderSessionHandle? auxiliaryHandle)
    {
        auxiliaryHandle = null;
        if (handle is not null &&
            sessions.TryGetValue(handle.SessionId, out AuxiliarySession? session))
        {
            auxiliaryHandle = session.Handle;
        }

        return auxiliaryHandle is not null;
    }

    private static async Task<T?> IgnoreFailuresAsync<T>(Func<Task<T>> action)
        where T : class
    {
        try
        {
            return await action().ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            return null;
        }
    }

    private sealed class AuxiliarySession
    {
        public CaptureProviderSessionHandle? Handle { get; set; }

        public string? Note { get; set; }

        public bool Stopped { get; set; }
    }
}
