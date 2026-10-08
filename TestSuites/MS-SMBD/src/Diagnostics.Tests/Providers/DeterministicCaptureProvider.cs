// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Protocols.TestSuites.Diagnostics.Identity;
using Microsoft.Protocols.TestSuites.Diagnostics.Manifest;
using Microsoft.Protocols.TestSuites.Diagnostics.Providers;
using Microsoft.Protocols.TestSuites.Diagnostics.Storage;
using Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.TestSupport;

namespace Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.Providers;

internal sealed class DeterministicCaptureProvider : ICaptureProvider
{
    private readonly List<string> calls = new();
    private readonly object syncRoot = new();
    private int providerIdReadCount;

    public string ProviderIdValue { get; set; } = "deterministic";

    public Func<int, string>? ProviderIdReadHandler { get; set; }

    public int ProviderIdReadCount => Volatile.Read(ref providerIdReadCount);

    public string ProviderId
    {
        get
        {
            int readCount = Interlocked.Increment(ref providerIdReadCount);
            return ProviderIdReadHandler?.Invoke(readCount) ?? ProviderIdValue;
        }
    }

    public IReadOnlyList<string> Calls
    {
        get
        {
            lock (syncRoot)
            {
                return calls.ToArray();
            }
        }
    }

    public Func<CaptureProviderStartRequest, CancellationToken, Task<CaptureProviderProbeResult>> ProbeAsyncHandler { get; set; } =
        static (_, _) => Task.FromResult(CaptureProviderProbeResult.Available(CreateCapabilities()));

    public Func<CaptureProviderStartRequest, CancellationToken, Task<CaptureProviderStartResult>> StartAsyncHandler { get; set; } =
        static (request, _) => Task.FromResult(
            CaptureProviderStartResult.Started(
                CaptureProviderSessionHandle.Create(
                    "deterministic",
                    request.Identity.InvocationId,
                    "session-1")));

    public Func<CaptureProviderSessionHandle, CancellationToken, Task<CaptureProviderReadinessResult>> WaitForReadinessAsyncHandler { get; set; } =
        static (_, _) => Task.FromResult(
            CaptureProviderReadinessResult.Ready("Deterministic readiness evidence."));

    public Func<CaptureProviderSessionHandle, CancellationToken, Task<CaptureProviderHealthResult>> ObserveHealthAsyncHandler { get; set; } =
        static (_, _) => Task.FromResult(
            CaptureProviderHealthResult.Healthy("Deterministic health evidence."));

    public Func<CaptureProviderSessionHandle, CancellationToken, Task<CaptureProviderStopResult>> RequestStopAsyncHandler { get; set; } =
        static (_, _) => Task.FromResult(CaptureProviderStopResult.Stopped("Deterministic graceful stop."));

    public Func<CaptureProviderSessionHandle, CancellationToken, Task<CaptureProviderFinalizationResult>> WaitForFinalizationAsyncHandler { get; set; } =
        static (_, _) => Task.FromResult(
            CaptureProviderFinalizationResult.Finalized("Deterministic finalization evidence."));

    public Task<CaptureProviderProbeResult> ProbeAsync(
        CaptureProviderStartRequest request,
        CancellationToken cancellationToken)
    {
        RecordCall("Probe");
        return ProbeAsyncHandler(request, cancellationToken);
    }

    public Task<CaptureProviderStartResult> StartAsync(
        CaptureProviderStartRequest request,
        CancellationToken cancellationToken)
    {
        RecordCall("Start");
        return StartAsyncHandler(request, cancellationToken);
    }

    public Task<CaptureProviderReadinessResult> WaitForReadinessAsync(
        CaptureProviderSessionHandle handle,
        CancellationToken cancellationToken)
    {
        RecordCall("Readiness");
        return WaitForReadinessAsyncHandler(handle, cancellationToken);
    }

    public Task<CaptureProviderStopResult> RequestStopAsync(
        CaptureProviderSessionHandle handle,
        CancellationToken cancellationToken)
    {
        RecordCall("Stop");
        return RequestStopAsyncHandler(handle, cancellationToken);
    }

    public Task<CaptureProviderHealthResult> ObserveHealthAsync(
        CaptureProviderSessionHandle handle,
        CancellationToken cancellationToken)
    {
        RecordCall("Health");
        return ObserveHealthAsyncHandler(handle, cancellationToken);
    }

    public Task<CaptureProviderFinalizationResult> WaitForFinalizationAsync(
        CaptureProviderSessionHandle handle,
        CancellationToken cancellationToken)
    {
        RecordCall("Finalization");
        return WaitForFinalizationAsyncHandler(handle, cancellationToken);
    }

    public static CaptureProviderCapabilities CreateCapabilities()
    {
        return new CaptureProviderCapabilities(
            providerId: "deterministic",
            supportedTargetKinds: new[] { "TestTarget" },
            nativeFormats: new[] { "pcap" },
            trafficVisibility: "Controlled test-double traffic only.",
            limitSemantics: "Deterministic limits supplied by the test.",
            stopSemantics: "Deterministic owned-handle stop.",
            readinessSemantics: "Deterministic explicit readiness result.",
            knownExclusions: new[] { "No hardware visibility." },
            CoverageQualification.Unverified);
    }

    private void RecordCall(string operation)
    {
        lock (syncRoot)
        {
            calls.Add(operation);
        }
    }
}

internal sealed class ProviderTestContext : IDisposable
{
    private readonly TemporaryDirectory temporaryDirectory;
    private readonly ArtifactStore artifactStore;
    private readonly ArtifactInvocation artifactInvocation;

    private ProviderTestContext(
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

    public CaptureProviderStartRequest Request { get; }

    public static ProviderTestContext Create()
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
            "run-1",
            "ProviderContracts.Test",
            "attempt-1",
            "row-1");
        ArtifactInvocation artifactInvocation = artifactStore.CreateInvocation(identity);
        var request = new CaptureProviderStartRequest(
            identity,
            artifactInvocation,
            new[] { "target-1" },
            "pcap",
            TimeSpan.FromMinutes(1),
            1024 * 1024);

        return new ProviderTestContext(
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
