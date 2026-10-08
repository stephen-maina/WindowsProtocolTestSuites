// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Protocols.TestSuites.Diagnostics.Evidence;
using Microsoft.Protocols.TestSuites.Diagnostics.Identity;
using Microsoft.Protocols.TestSuites.Diagnostics.Manifest;
using Microsoft.Protocols.TestSuites.Diagnostics.Storage;

namespace Microsoft.Protocols.TestSuites.Diagnostics.Providers;

public enum CaptureProviderFailureCode
{
    None,
    ProviderCreationFailed,
    RequestCreationFailed,
    ProbeFailed,
    ToolMissing,
    PermissionDenied,
    TargetAmbiguous,
    CaptureBusy,
    ProviderUnsupported,
    StartFailed,
    StartTimeout,
    Cancelled,
    OwnershipMismatch,
    ReadinessUnverified,
    ExitedEarly,
    HealthFailed,
    HealthTimeout,
    StopFailed,
    StopTimeout,
    ForcedStop,
    FinalizationFailed,
    FinalizationTimeout,
}

public enum CaptureProviderReadinessStatus
{
    NotStarted,
    Ready,
    Unverified,
    ExitedEarly,
    Failed,
    TimedOut,
    Cancelled,
}

public enum CaptureProviderStopStatus
{
    Stopped,
    AlreadyStopped,
    Forced,
    Failed,
}

public enum CaptureProviderHealthStatus
{
    Disabled,
    Healthy,
    ExitedEarly,
    Failed,
    TimedOut,
    Cancelled,
}

public enum CaptureProviderFinalizationStatus
{
    Finalized,
    Failed,
}

public sealed class CaptureProviderTimeouts
{
    public CaptureProviderTimeouts(
        TimeSpan startTimeout,
        TimeSpan stopTimeout,
        TimeSpan finalizationTimeout)
    {
        StartTimeout = ProviderContractValidation.ValidateTimeout(
            startTimeout,
            nameof(startTimeout));
        StopTimeout = ProviderContractValidation.ValidateTimeout(
            stopTimeout,
            nameof(stopTimeout));
        FinalizationTimeout = ProviderContractValidation.ValidateTimeout(
            finalizationTimeout,
            nameof(finalizationTimeout));
    }

    public TimeSpan StartTimeout { get; }

    public TimeSpan StopTimeout { get; }

    public TimeSpan FinalizationTimeout { get; }

}

public sealed class CaptureProviderCapabilities
{
    public CaptureProviderCapabilities(
        string providerId,
        IEnumerable<string> supportedTargetKinds,
        IEnumerable<string> nativeFormats,
        string trafficVisibility,
        string limitSemantics,
        string stopSemantics,
        string readinessSemantics,
        IEnumerable<string> knownExclusions,
        CoverageQualification qualification)
    {
        ProviderId = ProviderContractValidation.RequireText(providerId, nameof(providerId));
        SupportedTargetKinds = ProviderContractValidation.RequireTextValues(
            supportedTargetKinds,
            nameof(supportedTargetKinds));
        NativeFormats = ProviderContractValidation.RequireTextValues(
            nativeFormats,
            nameof(nativeFormats));
        TrafficVisibility = ProviderContractValidation.RequireText(
            trafficVisibility,
            nameof(trafficVisibility));
        LimitSemantics = ProviderContractValidation.RequireText(
            limitSemantics,
            nameof(limitSemantics));
        StopSemantics = ProviderContractValidation.RequireText(
            stopSemantics,
            nameof(stopSemantics));
        ReadinessSemantics = ProviderContractValidation.RequireText(
            readinessSemantics,
            nameof(readinessSemantics));
        KnownExclusions = ProviderContractValidation.RequireTextValues(
            knownExclusions,
            nameof(knownExclusions),
            allowEmpty: true);
        if (!Enum.IsDefined(qualification))
        {
            throw new ArgumentOutOfRangeException(
                nameof(qualification),
                "A defined coverage qualification is required.");
        }

        Qualification = qualification;
    }

    public string ProviderId { get; }

    public IReadOnlyList<string> SupportedTargetKinds { get; }

    public IReadOnlyList<string> NativeFormats { get; }

    public string TrafficVisibility { get; }

    public string LimitSemantics { get; }

    public string StopSemantics { get; }

    public string ReadinessSemantics { get; }

    public IReadOnlyList<string> KnownExclusions { get; }

    public CoverageQualification Qualification { get; }
}

public sealed class CaptureProviderStartRequest
{
    public CaptureProviderStartRequest(
        InvocationIdentity identity,
        ArtifactInvocation artifactInvocation,
        IEnumerable<string> targetIds,
        string nativeFormat,
        TimeSpan maxDuration,
        long maxBytes)
    {
        Identity = identity ?? throw new ArgumentNullException(nameof(identity));
        ArtifactInvocation = artifactInvocation ??
            throw new ArgumentNullException(nameof(artifactInvocation));
        TargetIds = ProviderContractValidation.RequireTextValues(
            targetIds,
            nameof(targetIds));
        NativeFormat = ProviderContractValidation.RequireText(
            nativeFormat,
            nameof(nativeFormat));
        MaxDuration = ProviderContractValidation.ValidatePositiveTimeout(
            maxDuration,
            nameof(maxDuration));
        if (maxBytes <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maxBytes),
                "The maximum capture size must be positive.");
        }

        MaxBytes = maxBytes;
    }

    public InvocationIdentity Identity { get; }

    public ArtifactInvocation ArtifactInvocation { get; }

    public IReadOnlyList<string> TargetIds { get; }

    public string NativeFormat { get; }

    public TimeSpan MaxDuration { get; }

    public long MaxBytes { get; }
}

public sealed class CaptureProviderSessionHandle
{
    private CaptureProviderSessionHandle(
        string providerId,
        string ownerInvocationId,
        string sessionId)
    {
        ProviderId = providerId;
        OwnerInvocationId = ownerInvocationId;
        SessionId = sessionId;
    }

    public string ProviderId { get; }

    public string OwnerInvocationId { get; }

    public string SessionId { get; }

    public static CaptureProviderSessionHandle Create(
        string providerId,
        string ownerInvocationId,
        string sessionId)
    {
        return new CaptureProviderSessionHandle(
            ProviderContractValidation.RequireText(providerId, nameof(providerId)),
            ProviderContractValidation.RequireText(
                ownerInvocationId,
                nameof(ownerInvocationId)),
            ProviderContractValidation.RequireText(sessionId, nameof(sessionId)));
    }
}

public sealed class CaptureProviderProbeResult
{
    private CaptureProviderProbeResult(
        CaptureProviderCapabilities? capabilities,
        CaptureProviderFailureCode failureCode,
        string? detail)
    {
        Capabilities = capabilities;
        FailureCode = failureCode;
        Detail = detail;
    }

    public bool IsAvailable => Capabilities is not null;

    public CaptureProviderCapabilities? Capabilities { get; }

    public CaptureProviderFailureCode FailureCode { get; }

    public string? Detail { get; }

    public static CaptureProviderProbeResult Available(
        CaptureProviderCapabilities capabilities)
    {
        return new CaptureProviderProbeResult(
            capabilities ?? throw new ArgumentNullException(nameof(capabilities)),
            CaptureProviderFailureCode.None,
            detail: null);
    }

    public static CaptureProviderProbeResult Unavailable(
        CaptureProviderFailureCode failureCode,
        string detail)
    {
        return new CaptureProviderProbeResult(
            capabilities: null,
            ProviderContractValidation.RequireFailure(failureCode, nameof(failureCode)),
            ProviderContractValidation.RequireText(detail, nameof(detail)));
    }
}

public sealed class CaptureProviderStartResult
{
    private CaptureProviderStartResult(
        bool isStarted,
        CaptureProviderSessionHandle? handle,
        bool writerResolved,
        CaptureProviderFailureCode failureCode,
        string? detail)
    {
        IsStarted = isStarted;
        Handle = handle;
        WriterResolved = writerResolved;
        FailureCode = failureCode;
        Detail = detail;
    }

    public bool IsStarted { get; }

    public CaptureProviderSessionHandle? Handle { get; }

    public bool WriterResolved { get; }

    public CaptureProviderFailureCode FailureCode { get; }

    public string? Detail { get; }

    public static CaptureProviderStartResult Started(
        CaptureProviderSessionHandle handle)
    {
        return new CaptureProviderStartResult(
            isStarted: true,
            handle ?? throw new ArgumentNullException(nameof(handle)),
            writerResolved: false,
            CaptureProviderFailureCode.None,
            detail: null);
    }

    public static CaptureProviderStartResult Failed(
        CaptureProviderFailureCode failureCode,
        string detail)
    {
        return new CaptureProviderStartResult(
            isStarted: false,
            handle: null,
            writerResolved: true,
            ProviderContractValidation.RequireFailure(failureCode, nameof(failureCode)),
            ProviderContractValidation.RequireText(detail, nameof(detail)));
    }

    public static CaptureProviderStartResult FailedWithOwnedHandle(
        CaptureProviderSessionHandle handle,
        CaptureProviderFailureCode failureCode,
        string detail)
    {
        return new CaptureProviderStartResult(
            isStarted: false,
            handle ?? throw new ArgumentNullException(nameof(handle)),
            writerResolved: false,
            ProviderContractValidation.RequireFailure(failureCode, nameof(failureCode)),
            ProviderContractValidation.RequireText(detail, nameof(detail)));
    }
}

public sealed class CaptureProviderReadinessResult
{
    private CaptureProviderReadinessResult(
        CaptureProviderReadinessStatus status,
        CaptureProviderFailureCode failureCode,
        string detail)
    {
        Status = status;
        FailureCode = failureCode;
        Detail = detail;
    }

    public CaptureProviderReadinessStatus Status { get; }

    public CaptureProviderFailureCode FailureCode { get; }

    public string Detail { get; }

    public static CaptureProviderReadinessResult Ready(string evidence)
    {
        return new CaptureProviderReadinessResult(
            CaptureProviderReadinessStatus.Ready,
            CaptureProviderFailureCode.None,
            ProviderContractValidation.RequireText(evidence, nameof(evidence)));
    }

    public static CaptureProviderReadinessResult Unverified(string detail)
    {
        return new CaptureProviderReadinessResult(
            CaptureProviderReadinessStatus.Unverified,
            CaptureProviderFailureCode.ReadinessUnverified,
            ProviderContractValidation.RequireText(detail, nameof(detail)));
    }

    public static CaptureProviderReadinessResult ExitedEarly(string detail)
    {
        return new CaptureProviderReadinessResult(
            CaptureProviderReadinessStatus.ExitedEarly,
            CaptureProviderFailureCode.ExitedEarly,
            ProviderContractValidation.RequireText(detail, nameof(detail)));
    }

    public static CaptureProviderReadinessResult Failed(
        CaptureProviderFailureCode failureCode,
        string detail)
    {
        return new CaptureProviderReadinessResult(
            CaptureProviderReadinessStatus.Failed,
            ProviderContractValidation.RequireFailure(failureCode, nameof(failureCode)),
            ProviderContractValidation.RequireText(detail, nameof(detail)));
    }
}

public sealed class CaptureProviderStopResult
{
    private CaptureProviderStopResult(
        CaptureProviderStopStatus status,
        bool writerResolved,
        CaptureProviderFailureCode failureCode,
        string detail)
    {
        Status = status;
        WriterResolved = writerResolved;
        FailureCode = failureCode;
        Detail = detail;
    }

    public CaptureProviderStopStatus Status { get; }

    public bool WriterResolved { get; }

    public CaptureProviderFailureCode FailureCode { get; }

    public string Detail { get; }

    public static CaptureProviderStopResult Stopped(string evidence)
    {
        return new CaptureProviderStopResult(
            CaptureProviderStopStatus.Stopped,
            writerResolved: true,
            CaptureProviderFailureCode.None,
            ProviderContractValidation.RequireText(evidence, nameof(evidence)));
    }

    public static CaptureProviderStopResult AlreadyStopped(string evidence)
    {
        return new CaptureProviderStopResult(
            CaptureProviderStopStatus.AlreadyStopped,
            writerResolved: true,
            CaptureProviderFailureCode.None,
            ProviderContractValidation.RequireText(evidence, nameof(evidence)));
    }

    public static CaptureProviderStopResult Forced(
        bool writerResolved,
        string detail)
    {
        return new CaptureProviderStopResult(
            CaptureProviderStopStatus.Forced,
            writerResolved,
            CaptureProviderFailureCode.ForcedStop,
            ProviderContractValidation.RequireText(detail, nameof(detail)));
    }

    public static CaptureProviderStopResult Failed(
        bool writerResolved,
        CaptureProviderFailureCode failureCode,
        string detail)
    {
        return new CaptureProviderStopResult(
            CaptureProviderStopStatus.Failed,
            writerResolved,
            ProviderContractValidation.RequireFailure(failureCode, nameof(failureCode)),
            ProviderContractValidation.RequireText(detail, nameof(detail)));
    }
}

public sealed class CaptureProviderHealthResult
{
    private CaptureProviderHealthResult(
        CaptureProviderHealthStatus status,
        CaptureProviderFailureCode failureCode,
        string detail)
    {
        Status = status;
        FailureCode = failureCode;
        Detail = detail;
    }

    public CaptureProviderHealthStatus Status { get; }

    public CaptureProviderFailureCode FailureCode { get; }

    public string Detail { get; }

    public static CaptureProviderHealthResult Disabled()
    {
        return new CaptureProviderHealthResult(
            CaptureProviderHealthStatus.Disabled,
            CaptureProviderFailureCode.None,
            "Capture health is disabled.");
    }

    public static CaptureProviderHealthResult Healthy(string evidence)
    {
        return new CaptureProviderHealthResult(
            CaptureProviderHealthStatus.Healthy,
            CaptureProviderFailureCode.None,
            ProviderContractValidation.RequireText(evidence, nameof(evidence)));
    }

    public static CaptureProviderHealthResult ExitedEarly(string detail)
    {
        return new CaptureProviderHealthResult(
            CaptureProviderHealthStatus.ExitedEarly,
            CaptureProviderFailureCode.ExitedEarly,
            ProviderContractValidation.RequireText(detail, nameof(detail)));
    }

    public static CaptureProviderHealthResult Failed(
        CaptureProviderFailureCode failureCode,
        string detail)
    {
        return new CaptureProviderHealthResult(
            CaptureProviderHealthStatus.Failed,
            ProviderContractValidation.RequireFailure(failureCode, nameof(failureCode)),
            ProviderContractValidation.RequireText(detail, nameof(detail)));
    }

    public static CaptureProviderHealthResult TimedOut(string detail)
    {
        return new CaptureProviderHealthResult(
            CaptureProviderHealthStatus.TimedOut,
            CaptureProviderFailureCode.HealthTimeout,
            ProviderContractValidation.RequireText(detail, nameof(detail)));
    }

    public static CaptureProviderHealthResult Cancelled(string detail)
    {
        return new CaptureProviderHealthResult(
            CaptureProviderHealthStatus.Cancelled,
            CaptureProviderFailureCode.Cancelled,
            ProviderContractValidation.RequireText(detail, nameof(detail)));
    }
}

public sealed class CaptureProviderFinalizationResult
{
    private CaptureProviderFinalizationResult(
        CaptureProviderFinalizationStatus status,
        CaptureProviderFailureCode failureCode,
        string detail,
        IEnumerable<ArtifactRecord> artifacts)
    {
        Status = status;
        FailureCode = failureCode;
        Detail = detail;
        ArgumentNullException.ThrowIfNull(artifacts);
        ArtifactRecord[] snapshot = artifacts.ToArray();
        if (snapshot.Any(artifact => artifact is null))
        {
            throw new ArgumentException(
                "Finalization artifacts cannot contain null entries.",
                nameof(artifacts));
        }

        if (status == CaptureProviderFinalizationStatus.Finalized &&
            snapshot.Any(
                artifact =>
                    artifact.FinalizationState != ArtifactFinalizationState.Finalized))
        {
            throw new ArgumentException(
                "A successful provider finalization result can return only finalized artifacts.",
                nameof(artifacts));
        }

        Artifacts = Array.AsReadOnly(snapshot);
    }

    public CaptureProviderFinalizationStatus Status { get; }

    public CaptureProviderFailureCode FailureCode { get; }

    public string Detail { get; }

    public IReadOnlyList<ArtifactRecord> Artifacts { get; }

    public static CaptureProviderFinalizationResult Finalized(string evidence)
    {
        return Finalized(evidence, Array.Empty<ArtifactRecord>());
    }

    public static CaptureProviderFinalizationResult Finalized(
        string evidence,
        IEnumerable<ArtifactRecord> artifacts)
    {
        return new CaptureProviderFinalizationResult(
            CaptureProviderFinalizationStatus.Finalized,
            CaptureProviderFailureCode.None,
            ProviderContractValidation.RequireText(evidence, nameof(evidence)),
            artifacts);
    }

    public static CaptureProviderFinalizationResult Failed(
        CaptureProviderFailureCode failureCode,
        string detail)
    {
        return Failed(
            failureCode,
            detail,
            Array.Empty<ArtifactRecord>());
    }

    public static CaptureProviderFinalizationResult Failed(
        CaptureProviderFailureCode failureCode,
        string detail,
        IEnumerable<ArtifactRecord> artifacts)
    {
        return new CaptureProviderFinalizationResult(
            CaptureProviderFinalizationStatus.Failed,
            ProviderContractValidation.RequireFailure(failureCode, nameof(failureCode)),
            ProviderContractValidation.RequireText(detail, nameof(detail)),
            artifacts);
    }
}

public interface ICaptureProvider
{
    string ProviderId { get; }

    Task<CaptureProviderProbeResult> ProbeAsync(
        CaptureProviderStartRequest request,
        CancellationToken cancellationToken);

    Task<CaptureProviderStartResult> StartAsync(
        CaptureProviderStartRequest request,
        CancellationToken cancellationToken);

    Task<CaptureProviderReadinessResult> WaitForReadinessAsync(
        CaptureProviderSessionHandle handle,
        CancellationToken cancellationToken);

    Task<CaptureProviderHealthResult> ObserveHealthAsync(
        CaptureProviderSessionHandle handle,
        CancellationToken cancellationToken);

    Task<CaptureProviderStopResult> RequestStopAsync(
        CaptureProviderSessionHandle handle,
        CancellationToken cancellationToken);

    Task<CaptureProviderFinalizationResult> WaitForFinalizationAsync(
        CaptureProviderSessionHandle handle,
        CancellationToken cancellationToken);
}

internal static class ProviderContractValidation
{
    private static readonly TimeSpan MaximumTimeout =
        TimeSpan.FromMilliseconds(uint.MaxValue - 1);

    public static string RequireText(string value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("A non-empty value is required.", parameterName);
        }

        return value;
    }

    public static IReadOnlyList<string> RequireTextValues(
        IEnumerable<string> values,
        string parameterName,
        bool allowEmpty = false)
    {
        ArgumentNullException.ThrowIfNull(values, parameterName);
        string[] snapshot = values.ToArray();
        if ((!allowEmpty && snapshot.Length == 0) ||
            snapshot.Any(string.IsNullOrWhiteSpace))
        {
            throw new ArgumentException(
                allowEmpty
                    ? "Every value must be non-empty."
                    : "At least one non-empty value is required.",
                parameterName);
        }

        return Array.AsReadOnly(snapshot);
    }

    public static CaptureProviderFailureCode RequireFailure(
        CaptureProviderFailureCode failureCode,
        string parameterName)
    {
        if (!Enum.IsDefined(failureCode) ||
            failureCode == CaptureProviderFailureCode.None)
        {
            throw new ArgumentException(
                "A provider failure requires a non-success failure code.",
                parameterName);
        }

        return failureCode;
    }

    public static TimeSpan ValidateTimeout(TimeSpan value, string parameterName)
    {
        if (value < TimeSpan.Zero || value > MaximumTimeout)
        {
            throw new ArgumentOutOfRangeException(
                parameterName,
                "A provider timeout must be between zero and the maximum supported timer interval.");
        }

        return value;
    }

    public static TimeSpan ValidatePositiveTimeout(
        TimeSpan value,
        string parameterName)
    {
        ValidateTimeout(value, parameterName);
        if (value == TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                parameterName,
                "A positive provider timeout is required.");
        }

        return value;
    }
}
