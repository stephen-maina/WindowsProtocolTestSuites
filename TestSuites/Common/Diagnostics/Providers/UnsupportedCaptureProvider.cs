// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.Protocols.TestSuites.Diagnostics.Providers;

public sealed class UnsupportedCaptureProvider : ICaptureProvider
{
    private const string DefaultReason =
        "No capture provider is available in this build.";
    private readonly string reason;

    public UnsupportedCaptureProvider()
        : this(DefaultReason)
    {
    }

    public UnsupportedCaptureProvider(string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        this.reason = reason;
    }

    public const string Identifier = "unsupported";

    public string ProviderId => Identifier;

    public Task<CaptureProviderProbeResult> ProbeAsync(
        CaptureProviderStartRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        return Task.FromResult(
            CaptureProviderProbeResult.Unavailable(
                CaptureProviderFailureCode.ProviderUnsupported,
                reason));
    }

    public Task<CaptureProviderStartResult> StartAsync(
        CaptureProviderStartRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        return Task.FromResult(
            CaptureProviderStartResult.Failed(
                CaptureProviderFailureCode.ProviderUnsupported,
                reason));
    }

    public Task<CaptureProviderReadinessResult> WaitForReadinessAsync(
        CaptureProviderSessionHandle handle,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(handle);
        return Task.FromResult(
            CaptureProviderReadinessResult.Failed(
                CaptureProviderFailureCode.ProviderUnsupported,
                reason));
    }

    public Task<CaptureProviderHealthResult> ObserveHealthAsync(
        CaptureProviderSessionHandle handle,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(handle);
        return Task.FromResult(
            CaptureProviderHealthResult.Failed(
                CaptureProviderFailureCode.ProviderUnsupported,
                reason));
    }

    public Task<CaptureProviderStopResult> RequestStopAsync(
        CaptureProviderSessionHandle handle,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(handle);
        return Task.FromResult(
            CaptureProviderStopResult.Failed(
                writerResolved: true,
                CaptureProviderFailureCode.ProviderUnsupported,
                reason));
    }

    public Task<CaptureProviderFinalizationResult> WaitForFinalizationAsync(
        CaptureProviderSessionHandle handle,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(handle);
        return Task.FromResult(
            CaptureProviderFinalizationResult.Failed(
                CaptureProviderFailureCode.ProviderUnsupported,
                reason));
    }
}
