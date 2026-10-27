// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Microsoft.Protocols.TestSuites.Diagnostics.Configuration;
using Microsoft.Protocols.TestSuites.Diagnostics.Errors;
using Microsoft.Protocols.TestSuites.Diagnostics.Evidence;
using Microsoft.Protocols.TestSuites.Diagnostics.Identity;
using Microsoft.Protocols.TestSuites.Diagnostics.Logging;
using Microsoft.Protocols.TestSuites.Diagnostics.Manifest;
using Microsoft.Protocols.TestSuites.Diagnostics.Providers;
using Microsoft.Protocols.TestSuites.Diagnostics.Runner;
using Microsoft.Protocols.TestSuites.Diagnostics.Storage;

namespace Microsoft.Protocols.TestSuites.Diagnostics.Lifecycle;

public sealed class DiagnosticsInvocationRuntime
{
    public DiagnosticsInvocationRuntime(
        InvocationIdentity identity,
        ArtifactInvocation artifactInvocation,
        InvocationLogRouter router,
        ICaptureProvider provider,
        IEnumerable<string>? sensitiveValues = null)
    {
        Identity = identity ?? throw new ArgumentNullException(nameof(identity));
        ArtifactInvocation = artifactInvocation ??
            throw new ArgumentNullException(nameof(artifactInvocation));
        Router = router ?? throw new ArgumentNullException(nameof(router));
        Provider = provider ?? throw new ArgumentNullException(nameof(provider));
        SensitiveValues = sensitiveValues?.ToArray() ?? Array.Empty<string>();
    }

    public InvocationIdentity Identity { get; }

    public ArtifactInvocation ArtifactInvocation { get; }

    public InvocationLogRouter Router { get; }

    public ICaptureProvider Provider { get; }

    public IReadOnlyList<string> SensitiveValues { get; }
}

public sealed class DiagnosticsInvocationLifecycle : IDisposable
{
    private readonly DiagnosticErrorLedger errors;
    private readonly DiagnosticsConfiguration? configuration;
    private readonly DiagnosticsInvocationRuntime? runtime;
    private readonly BoundedInvocationLogCollector? logs;
    private readonly IDisposable? route;
    private readonly CaptureProviderSession? providerSession;
    private readonly CaptureProviderTimeouts? providerTimeouts;
    private int cleanupStatus;
    private int disposed;

    private DiagnosticsInvocationLifecycle(DiagnosticErrorLedger errors)
    {
        this.errors = errors;
    }

    private DiagnosticsInvocationLifecycle(
        DiagnosticErrorLedger errors,
        DiagnosticsConfiguration configuration,
        DiagnosticsInvocationRuntime runtime,
        BoundedInvocationLogCollector logs,
        IDisposable route,
        CaptureProviderSession providerSession,
        CaptureProviderTimeouts providerTimeouts)
    {
        this.errors = errors;
        this.configuration = configuration;
        this.runtime = runtime;
        this.logs = logs;
        this.route = route;
        this.providerSession = providerSession;
        this.providerTimeouts = providerTimeouts;
    }

    public bool IsEnabled => runtime is not null;

    // Lets suite-specific collectors (for example SUT logs) add files next to the standard artifacts.
    public string? ArtifactDirectoryPath => runtime?.ArtifactInvocation.DirectoryPath;

    public LifecycleStatus CleanupStatus =>
        (LifecycleStatus)Volatile.Read(ref cleanupStatus);

    public DiagnosticErrorLedger Errors => errors;

    public static DiagnosticsInvocationLifecycle Start(
        IEffectiveConfigurationSource source,
        string scopeKey,
        string displayName,
        Func<DiagnosticsConfiguration, InvocationIdentity, DiagnosticsInvocationRuntime>
            runtimeFactory)
    {
        return Start(
            source,
            scopeKey,
            displayName,
            runtimeFactory,
            DiagnosticsConfigurationPropertyMap.Canonical);
    }

    public static DiagnosticsInvocationLifecycle Start(
        IEffectiveConfigurationSource source,
        string scopeKey,
        string displayName,
        Func<DiagnosticsConfiguration, InvocationIdentity, DiagnosticsInvocationRuntime>
            runtimeFactory,
        DiagnosticsConfigurationPropertyMap propertyMap)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(scopeKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(displayName);

        return Start(
            source,
            () => scopeKey,
            () => displayName,
            runtimeFactory,
            propertyMap);
    }

    public static DiagnosticsInvocationLifecycle Start(
        IEffectiveConfigurationSource source,
        Func<string> scopeKeyFactory,
        Func<string> displayNameFactory,
        Func<DiagnosticsConfiguration, InvocationIdentity, DiagnosticsInvocationRuntime>
            runtimeFactory)
    {
        return Start(
            source,
            scopeKeyFactory,
            displayNameFactory,
            runtimeFactory,
            DiagnosticsConfigurationPropertyMap.Canonical);
    }

    public static DiagnosticsInvocationLifecycle Start(
        IEffectiveConfigurationSource source,
        Func<string> scopeKeyFactory,
        Func<string> displayNameFactory,
        Func<DiagnosticsConfiguration, InvocationIdentity, DiagnosticsInvocationRuntime>
            runtimeFactory,
        DiagnosticsConfigurationPropertyMap propertyMap)
    {
        return Start(
            source,
            scopeKeyFactory,
            displayNameFactory,
            displayName => InvocationIdentity.Create(
                runId: "ptf",
                testIdentity: displayName,
                attemptIdentity: "initial",
                dataRowIdentity: string.Empty),
            runtimeFactory,
            propertyMap);
    }

    public static DiagnosticsInvocationLifecycle Start(
        IEffectiveConfigurationSource source,
        Func<string> scopeKeyFactory,
        Func<string> displayNameFactory,
        Func<string, InvocationIdentity> identityFactory,
        Func<DiagnosticsConfiguration, InvocationIdentity, DiagnosticsInvocationRuntime>
            runtimeFactory)
    {
        return Start(
            source,
            scopeKeyFactory,
            displayNameFactory,
            identityFactory,
            runtimeFactory,
            DiagnosticsConfigurationPropertyMap.Canonical);
    }

    public static DiagnosticsInvocationLifecycle Start(
        IEffectiveConfigurationSource source,
        Func<string> scopeKeyFactory,
        Func<string> displayNameFactory,
        Func<string, InvocationIdentity> identityFactory,
        Func<DiagnosticsConfiguration, InvocationIdentity, DiagnosticsInvocationRuntime>
            runtimeFactory,
        DiagnosticsConfigurationPropertyMap propertyMap,
        DiagnosticsConfigurationPolicy? policy = null)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(scopeKeyFactory);
        ArgumentNullException.ThrowIfNull(displayNameFactory);
        ArgumentNullException.ThrowIfNull(identityFactory);
        ArgumentNullException.ThrowIfNull(runtimeFactory);
        ArgumentNullException.ThrowIfNull(propertyMap);

        var errors = new DiagnosticErrorLedger();
        DiagnosticsConfiguration configuration =
            DiagnosticsConfigurationReader.Read(
                source,
                errors,
                DateTimeOffset.UtcNow,
                propertyMap,
                policy);
        if (configuration.State != DiagnosticsConfigurationState.Enabled)
        {
            return new DiagnosticsInvocationLifecycle(errors);
        }

        try
        {
            string scopeKey = scopeKeyFactory();
            string displayName = displayNameFactory();
            ArgumentException.ThrowIfNullOrWhiteSpace(scopeKey);
            ArgumentException.ThrowIfNullOrWhiteSpace(displayName);

            InvocationIdentity identity = identityFactory(displayName) ??
                throw new InvalidOperationException(
                    "The diagnostics invocation identity factory returned null.");
            DiagnosticsInvocationRuntime runtime =
                runtimeFactory(configuration, identity) ??
                throw new InvalidOperationException(
                    "The diagnostics invocation runtime factory returned null.");
            var logs = new BoundedInvocationLogCollector(
                capacity: 4096,
                maxMessageLength: 16384,
                runtime.SensitiveValues);
            IDisposable route = runtime.Router.Register(scopeKey, logs);

            DiagnosticsCaptureConfiguration capture = configuration.Capture!;
            var timeouts = new CaptureProviderTimeouts(
                capture.StartTimeout.Value,
                capture.StopTimeout.Value,
                capture.StopTimeout.Value);
            CaptureProviderSession? session = null;
            try
            {
                session = CaptureProviderOrchestrator
                    .CreateEnabled(errors)
                    .StartAsync(
                        () => new CaptureProviderStartRequest(
                            runtime.Identity,
                            runtime.ArtifactInvocation,
                            capture.Targets.Select(target => target.Value),
                            capture.Format.Value.ToString(),
                            capture.MaxDuration.Value,
                            capture.MaxBytes.Value),
                        () => runtime.Provider,
                        timeouts,
                        CancellationToken.None)
                    .GetAwaiter()
                    .GetResult();
            }
            finally
            {
                if (session is null)
                {
                    route.Dispose();
                }
            }

            return new DiagnosticsInvocationLifecycle(
                errors,
                configuration,
                runtime,
                logs,
                route,
                session,
                timeouts);
        }
        catch (ArtifactStorageException)
        {
            return StartupFailed(errors, DiagnosticErrorCategory.Storage);
        }
        catch (IOException)
        {
            return StartupFailed(errors, DiagnosticErrorCategory.Storage);
        }
        catch (UnauthorizedAccessException)
        {
            return StartupFailed(errors, DiagnosticErrorCategory.Storage);
        }
        catch (InvalidOperationException)
        {
            return StartupFailed(errors, DiagnosticErrorCategory.Capture);
        }
        catch (ArgumentException)
        {
            return StartupFailed(errors, DiagnosticErrorCategory.Capture);
        }
    }

    public void MarkCleanupCompleted()
    {
        Interlocked.CompareExchange(
            ref cleanupStatus,
            (int)LifecycleStatus.Complete,
            (int)LifecycleStatus.Pending);
    }

    public void MarkCleanupFailed()
    {
        Interlocked.CompareExchange(
            ref cleanupStatus,
            (int)LifecycleStatus.Failed,
            (int)LifecycleStatus.Pending);
        errors.Record(
            DiagnosticErrorCategory.Cleanup,
            "Diagnostics.CleanupFailed",
            "Protocol cleanup did not complete successfully.",
            DateTimeOffset.UtcNow);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0 || runtime is null)
        {
            return;
        }

        CaptureProviderCompletionResult completion;
        try
        {
            completion = providerSession!
                .CompleteAsync(providerTimeouts!, CancellationToken.None)
                .GetAwaiter()
                .GetResult();
        }
        finally
        {
            route!.Dispose();
        }

        try
        {
            WriteArtifacts(completion);
        }
        catch (ArtifactStorageException)
        {
            RecordArtifactFinalizationFailure();
        }
        catch (IOException)
        {
            RecordArtifactFinalizationFailure();
        }
        catch (UnauthorizedAccessException)
        {
            RecordArtifactFinalizationFailure();
        }
        catch (InvalidOperationException)
        {
            RecordArtifactFinalizationFailure();
        }
    }

    private void RecordArtifactFinalizationFailure()
    {
        errors.Record(
            DiagnosticErrorCategory.Storage,
            "Diagnostics.ArtifactWriteFailed",
            "Diagnostics artifacts could not be persisted.",
            DateTimeOffset.UtcNow);
    }

    private static DiagnosticsInvocationLifecycle StartupFailed(
        DiagnosticErrorLedger errors,
        DiagnosticErrorCategory category)
    {
        errors.Record(
            category,
            "Diagnostics.StartFailed",
            "Diagnostics could not start for this invocation.",
            DateTimeOffset.UtcNow);
        return new DiagnosticsInvocationLifecycle(errors);
    }

    private void WriteArtifacts(CaptureProviderCompletionResult completion)
    {
        string logContent = logs!.SerializeNdjson();
        using (ArtifactCheckpoint logCheckpoint =
            runtime!.ArtifactInvocation.CreateCheckpoint("ptf-log.ndjson"))
        {
            logCheckpoint.WriteText(logContent);
            logCheckpoint.Commit();
        }

        byte[] logBytes = Encoding.UTF8.GetBytes(logContent);
        var manifest = new ManifestDocument(ManifestSchema.SupportedVersion)
        {
            Collection = CreateCollectionEvidence(completion),
            CleanupStatus = CleanupStatus,
            FinalizationStatus = LifecycleStatus.Complete,
            CompletionState = CompletionState.Provisional,
        };
        manifest.Artifacts.AddRange(completion.Artifacts);
        manifest.Artifacts.Add(
            ArtifactRecord.CreateFinalized(
                "ptf-log.ndjson",
                "ptf-log-router",
                logBytes.LongLength,
                Convert.ToHexString(SHA256.HashData(logBytes)),
                ArtifactConfidentiality.Internal,
                ArtifactRelation.Original,
                "application/x-ndjson"));

        if (completion.Artifacts.Count == 0)
        {
            bool unsupported =
                completion.FailureCode == CaptureProviderFailureCode.ProviderUnsupported;
            manifest.ArtifactAbsences.Add(
                unsupported
                    ? ArtifactAbsence.Unsupported(
                        ArtifactKind.Capture,
                        EvidenceReasonCode.ProviderUnsupported)
                    : ArtifactAbsence.Missing(
                        ArtifactKind.Capture,
                        EvidenceReasonCode.UnexpectedEmptyEvidence));
        }

        if (!completion.WriterResolved)
        {
            manifest.UnresolvedWriters.Add(runtime.Provider.ProviderId);
        }

        foreach (DiagnosticError error in errors.Chronology)
        {
            manifest.Errors.Restore(
                error.Sequence,
                error.Category,
                error.Code,
                error.Message,
                error.OccurredAt);
        }

        foreach (ManifestMetadataEntry entry in
            SanitizedConfigurationProjection.Create(configuration!))
        {
            manifest.Metadata.Add(entry);
        }
        manifest.Metadata.Add(
            new ManifestMetadataEntry(
                RunnerCorrelationMetadata.InvocationId,
                runtime.Identity.OpaqueInvocationId,
                MetadataSensitivity.NonSensitive));
        if (runtime.Identity.ManagedTestIdentitySha256 is not null &&
            runtime.Identity.TestDisplayNameSha256 is not null)
        {
            manifest.Metadata.Add(
                new ManifestMetadataEntry(
                    RunnerCorrelationMetadata.RunId,
                    runtime.Identity.RunId,
                    MetadataSensitivity.NonSensitive));
            manifest.Metadata.Add(
                new ManifestMetadataEntry(
                    RunnerCorrelationMetadata.ManagedTestIdentitySha256,
                    runtime.Identity.ManagedTestIdentitySha256,
                    MetadataSensitivity.NonSensitive));
            manifest.Metadata.Add(
                new ManifestMetadataEntry(
                    RunnerCorrelationMetadata.TestDisplayNameSha256,
                    runtime.Identity.TestDisplayNameSha256,
                    MetadataSensitivity.NonSensitive));
            manifest.Metadata.Add(
                new ManifestMetadataEntry(
                    RunnerCorrelationMetadata.AttemptIdentity,
                    runtime.Identity.AttemptIdentity,
                    MetadataSensitivity.NonSensitive));
        }

        manifest.Metadata.Add(
            new ManifestMetadataEntry(
                RunnerCorrelationMetadata.OutcomeAuthority,
                "provisional-not-authoritative",
                MetadataSensitivity.NonSensitive));

        using ArtifactCheckpoint manifestCheckpoint =
            runtime.ArtifactInvocation.CreateCheckpoint("manifest.json");
        manifestCheckpoint.WriteText(ManifestSerializer.Serialize(manifest));
        manifestCheckpoint.Commit();
    }

    private static CollectionEvidence CreateCollectionEvidence(
        CaptureProviderCompletionResult completion)
    {
        int usableArtifactCount = completion.Artifacts.Count;
        bool unsupported =
            completion.FailureCode == CaptureProviderFailureCode.ProviderUnsupported;
        bool finalized =
            completion.FinalizationStatus == CaptureProviderFinalizationStatus.Finalized;
        CollectionStatus status = unsupported || usableArtifactCount == 0
            ? CollectionStatus.Unavailable
            : finalized && completion.CollectionComplete
                ? CollectionStatus.Complete
                : CollectionStatus.Partial;
        EvidenceReasonCode reasonCode = unsupported
            ? EvidenceReasonCode.ProviderUnsupported
            : usableArtifactCount == 0
                ? EvidenceReasonCode.UnexpectedEmptyEvidence
                : !completion.CollectionComplete
                    ? EvidenceReasonCode.CollectionGap
                : finalized
                    ? EvidenceReasonCode.None
                    : EvidenceReasonCode.CleanupFailed;

        return new CollectionEvidence(
            status,
            plannedArtifactCount: Math.Max(1, usableArtifactCount),
            usableArtifactCount,
            noTrafficExpected: false,
            reasonCode);
    }
}
