// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Protocols.TestSuites.Diagnostics.Configuration;
using Microsoft.Protocols.TestSuites.Diagnostics.Evidence;
using Microsoft.Protocols.TestSuites.Diagnostics.Identity;
using Microsoft.Protocols.TestSuites.Diagnostics.Lifecycle;
using Microsoft.Protocols.TestSuites.Diagnostics.Logging;
using Microsoft.Protocols.TestSuites.Diagnostics.Manifest;
using Microsoft.Protocols.TestSuites.Diagnostics.Providers;
using Microsoft.Protocols.TestSuites.Diagnostics.Storage;
using Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.Configuration;
using Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.Providers;
using Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.TestSupport;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.Lifecycle;

[TestClass]
public sealed class DiagnosticsLifecycleIntegrationTests
{
    [TestMethod]
    public void Start_MissingOrDisabledEnabledProperty_HasNoRuntimeSideEffects()
    {
        foreach (string? enabledValue in new string?[] { null, "false" })
        {
            var source = new TestEffectiveConfigurationSource(
                enabledValue is null
                    ? new Dictionary<string, string?>()
                    : new Dictionary<string, string?>
                    {
                        [DiagnosticsConfigurationPropertyNames.Enabled] = enabledValue,
                    });
            int runtimeFactoryCalls = 0;

            using DiagnosticsInvocationLifecycle lifecycle =
                DiagnosticsInvocationLifecycle.Start(
                    source,
                    "scope",
                    "test",
                    (_, _) =>
                    {
                        runtimeFactoryCalls++;
                        throw new InvalidOperationException("must not be called");
                    });

            lifecycle.MarkCleanupCompleted();
            lifecycle.Dispose();

            Assert.IsFalse(lifecycle.IsEnabled);
            Assert.AreEqual(0, runtimeFactoryCalls);
            CollectionAssert.AreEqual(
                new[] { DiagnosticsConfigurationPropertyNames.Enabled },
                source.RequestedProperties.ToArray());
        }
    }

    [TestMethod]
    public void Start_Disabled_DoesNotEvaluateInvocationIdentityFactories()
    {
        var source = new TestEffectiveConfigurationSource(
            new Dictionary<string, string?>
            {
                [DiagnosticsConfigurationPropertyNames.Enabled] = "false",
            });
        int scopeCalls = 0;
        int displayNameCalls = 0;

        using DiagnosticsInvocationLifecycle lifecycle =
            DiagnosticsInvocationLifecycle.Start(
                source,
                () =>
                {
                    scopeCalls++;
                    return "scope";
                },
                () =>
                {
                    displayNameCalls++;
                    return "test";
                },
                (_, _) => throw new InvalidOperationException("must not be called"));

        Assert.IsFalse(lifecycle.IsEnabled);
        Assert.AreEqual(0, scopeCalls);
        Assert.AreEqual(0, displayNameCalls);
        CollectionAssert.AreEqual(
            new[] { DiagnosticsConfigurationPropertyNames.Enabled },
            source.RequestedProperties.ToArray());
    }

    [TestMethod]
    public void Dispose_EnabledInvocation_FinalizesOnceAfterCleanupAndStaysProvisional()
    {
        using LifecycleFixture fixture = LifecycleFixture.Create();
        using DiagnosticsInvocationLifecycle lifecycle = fixture.Start();

        fixture.Router.Route(
            fixture.ScopeKey,
            DateTimeOffset.UtcNow,
            "Comment",
            "during protocol");
        Assert.IsFalse(File.Exists(fixture.ManifestPath));

        lifecycle.MarkCleanupCompleted();
        Parallel.For(0, 8, _ => lifecycle.Dispose());

        CollectionAssert.AreEqual(
            new[] { "Probe", "Start", "Readiness", "Stop", "Finalization" },
            fixture.Provider.Calls.ToArray());
        Assert.IsTrue(File.Exists(fixture.ManifestPath));

        using JsonDocument manifest =
            JsonDocument.Parse(File.ReadAllText(fixture.ManifestPath));
        JsonElement root = manifest.RootElement;
        Assert.AreEqual("Pending", root.GetProperty("protocolResult").GetString());
        Assert.AreEqual("Complete", root.GetProperty("cleanupStatus").GetString());
        Assert.AreEqual("Complete", root.GetProperty("finalizationStatus").GetString());
        Assert.AreEqual("Pending", root.GetProperty("runnerResult").GetString());
        Assert.AreEqual("Provisional", root.GetProperty("completionState").GetString());
    }

    [TestMethod]
    public void Dispose_ProviderCompletionPtfLog_IsRetainedAndManifested()
    {
        const string CompletionMessage = "provider completion log";
        using LifecycleFixture fixture = LifecycleFixture.Create();
        bool routedDuringCompletion = false;
        fixture.Provider.WaitForFinalizationAsyncHandler = (_, _) =>
        {
            routedDuringCompletion = fixture.Router.Route(
                fixture.ScopeKey,
                DateTimeOffset.UtcNow,
                "Comment",
                CompletionMessage);
            return Task.FromResult(
                CaptureProviderFinalizationResult.Finalized(
                    "Deterministic finalization evidence."));
        };
        using DiagnosticsInvocationLifecycle lifecycle = fixture.Start();

        lifecycle.MarkCleanupCompleted();
        lifecycle.Dispose();

        Assert.IsTrue(routedDuringCompletion);
        Assert.IsFalse(
            fixture.Router.Route(
                fixture.ScopeKey,
                DateTimeOffset.UtcNow,
                "Comment",
                "after provider completion"));
        byte[] logBytes = File.ReadAllBytes(fixture.LogPath);
        Assert.IsTrue(
            Encoding.UTF8.GetString(logBytes)
                .Contains(CompletionMessage, StringComparison.Ordinal));

        using JsonDocument manifest =
            JsonDocument.Parse(File.ReadAllText(fixture.ManifestPath));
        JsonElement logArtifact =
            FindArtifact(manifest.RootElement, "ptf-log.ndjson");
        Assert.AreEqual(
            logBytes.LongLength,
            logArtifact.GetProperty("byteCount").GetInt64());
        Assert.AreEqual(
            Convert.ToHexString(SHA256.HashData(logBytes)),
            logArtifact.GetProperty("sha256").GetString());
        Assert.AreEqual(
            "ptf-log-router",
            logArtifact.GetProperty("producer").GetString());
        Assert.AreEqual(
            "Finalized",
            logArtifact.GetProperty("finalizationState").GetString());
    }

    [TestMethod]
    public void Dispose_UnsupportedProvider_RecordsFinalizedLogAndExplicitCaptureAbsence()
    {
        using LifecycleFixture fixture = LifecycleFixture.Create();
        fixture.Provider.ProbeAsyncHandler =
            static (_, _) => Task.FromResult(
                CaptureProviderProbeResult.Unavailable(
                    CaptureProviderFailureCode.ProviderUnsupported,
                    "unsupported"));
        using DiagnosticsInvocationLifecycle lifecycle = fixture.Start();

        fixture.Router.Route(
            fixture.ScopeKey,
            DateTimeOffset.UtcNow,
            "Comment",
            "persisted record");
        lifecycle.MarkCleanupCompleted();
        lifecycle.Dispose();

        byte[] logBytes = File.ReadAllBytes(fixture.LogPath);
        using JsonDocument manifest =
            JsonDocument.Parse(File.ReadAllText(fixture.ManifestPath));
        JsonElement root = manifest.RootElement;
        JsonElement logArtifact = root.GetProperty("artifacts")
            .EnumerateArray()
            .Single(
                artifact =>
                    artifact.GetProperty("relativePath").GetString() ==
                        "ptf-log.ndjson");
        JsonElement absence = root.GetProperty("artifactAbsences")
            .EnumerateArray()
            .Single();

        Assert.AreEqual(
            logBytes.LongLength,
            logArtifact.GetProperty("byteCount").GetInt64());
        Assert.AreEqual(
            Convert.ToHexString(SHA256.HashData(logBytes)),
            logArtifact.GetProperty("sha256").GetString());
        Assert.AreEqual(
            "Unavailable",
            root.GetProperty("collectionStatus").GetString());
        Assert.AreEqual(
            "ProviderUnsupported",
            root.GetProperty("evidenceReasonCode").GetString());
        Assert.AreEqual("Capture", absence.GetProperty("kind").GetString());
        Assert.AreEqual(
            "ProviderUnsupported",
            absence.GetProperty("reasonCode").GetString());
        Assert.IsTrue(
            root.GetProperty("metadata")
                .EnumerateArray()
                .Any(
                    entry =>
                        entry.GetProperty("key").GetString() == "outcomeAuthority" &&
                        entry.GetProperty("value").GetString() ==
                            "provisional-not-authoritative"));
    }

    [TestMethod]
    public void Dispose_ProviderProducedFiles_AreRetainedAndRegisteredInSingleInvocation()
    {
        const string CaptureRelativePath =
            "captures/deterministic__target-1__0001.pcap";
        const string ProviderLogRelativePath =
            "logs/capture-session-1.stdout.log";
        var providerArtifacts = new List<ArtifactRecord>();
        using LifecycleFixture fixture = LifecycleFixture.Create();
        fixture.Provider.StartAsyncHandler = (request, _) =>
        {
            providerArtifacts.Add(
                WriteProviderArtifact(
                    request.ArtifactInvocation,
                    CaptureRelativePath,
                    "provider-capture",
                    "application/vnd.tcpdump.pcap"));
            providerArtifacts.Add(
                WriteProviderArtifact(
                    request.ArtifactInvocation,
                    ProviderLogRelativePath,
                    "provider-stdout",
                    "text/plain"));
            return Task.FromResult(
                CaptureProviderStartResult.Started(
                    CaptureProviderSessionHandle.Create(
                        "deterministic",
                        request.Identity.InvocationId,
                        "session-1")));
        };
        fixture.Provider.WaitForFinalizationAsyncHandler =
            (_, _) => Task.FromResult(
                CaptureProviderFinalizationResult.Finalized(
                    "Provider artifacts finalized.",
                    providerArtifacts));
        using DiagnosticsInvocationLifecycle lifecycle = fixture.Start();

        lifecycle.MarkCleanupCompleted();
        lifecycle.Dispose();

        string invocationDirectory = fixture.ArtifactInvocation!.DirectoryPath;
        string capturePath = Path.Combine(
            invocationDirectory,
            "captures",
            "deterministic__target-1__0001.pcap");
        string providerLogPath = Path.Combine(
            invocationDirectory,
            "logs",
            "capture-session-1.stdout.log");
        foreach (string artifactPath in new[]
        {
            capturePath,
            providerLogPath,
            fixture.LogPath,
            fixture.ManifestPath,
        })
        {
            Assert.IsTrue(File.Exists(artifactPath), artifactPath);
            Assert.IsFalse(
                Path.GetRelativePath(invocationDirectory, artifactPath)
                    .StartsWith("..", StringComparison.Ordinal));
        }

        using JsonDocument manifest =
            JsonDocument.Parse(File.ReadAllText(fixture.ManifestPath));
        JsonElement root = manifest.RootElement;
        JsonElement captureArtifact = FindArtifact(root, CaptureRelativePath);
        JsonElement providerLogArtifact =
            FindArtifact(root, ProviderLogRelativePath);

        Assert.AreEqual(
            Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(capturePath))),
            captureArtifact.GetProperty("sha256").GetString());
        Assert.AreEqual(
            Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(providerLogPath))),
            providerLogArtifact.GetProperty("sha256").GetString());
        Assert.AreEqual(
            new FileInfo(capturePath).Length,
            captureArtifact.GetProperty("byteCount").GetInt64());
        Assert.AreEqual(
            new FileInfo(providerLogPath).Length,
            providerLogArtifact.GetProperty("byteCount").GetInt64());
        Assert.AreEqual(
            "deterministic",
            captureArtifact.GetProperty("producer").GetString());
        Assert.AreEqual(
            "deterministic",
            providerLogArtifact.GetProperty("producer").GetString());
        Assert.AreEqual(
            "Finalized",
            captureArtifact.GetProperty("finalizationState").GetString());
        Assert.AreEqual(
            "Finalized",
            providerLogArtifact.GetProperty("finalizationState").GetString());
        Assert.AreEqual(
            "Complete",
            root.GetProperty("collectionStatus").GetString());
        Assert.AreEqual(2, root.GetProperty("plannedArtifactCount").GetInt32());
        Assert.AreEqual(2, root.GetProperty("usableArtifactCount").GetInt32());
    }

    [TestMethod]
    public void Router_RegistersSharedInstanceOnce_RoutesOnlyScopedLogs_AndOutlivesRoutes()
    {
        var registry = new SharedInvocationLogRouterRegistry();
        object suiteOwner = new();
        int creations = 0;
        InvocationLogRouter first = registry.GetOrCreate(
            suiteOwner,
            () =>
            {
                creations++;
                return new InvocationLogRouter();
            });
        InvocationLogRouter second = registry.GetOrCreate(
            suiteOwner,
            () =>
            {
                creations++;
                return new InvocationLogRouter();
            });
        var firstTarget = new BoundedInvocationLogCollector(16, 256);
        var secondTarget = new BoundedInvocationLogCollector(16, 256);

        using (first.Register("scope-a", firstTarget))
        using (second.Register("scope-b", secondTarget))
        {
            first.Route("scope-a", DateTimeOffset.UtcNow, "Comment", "one");
            first.Route("scope-b", DateTimeOffset.UtcNow, "Comment", "two");
            first.Route("scope-c", DateTimeOffset.UtcNow, "Comment", "ignored");
        }

        Assert.AreSame(first, second);
        Assert.AreEqual(1, creations);
        Assert.AreEqual("one", firstTarget.Records.Single().Message);
        Assert.AreEqual("two", secondTarget.Records.Single().Message);
        Assert.IsFalse(first.Route(
            "scope-a",
            DateTimeOffset.UtcNow,
            "Comment",
            "after route disposal"));
        Assert.AreSame(first, registry.GetOrCreate(suiteOwner, static () => new()));
    }

    [TestMethod]
    public void Router_DuplicateActiveScope_IsRejectedWithoutReplacingOriginalRoute()
    {
        var router = new InvocationLogRouter();
        var original = new BoundedInvocationLogCollector(16, 256);
        var replacement = new BoundedInvocationLogCollector(16, 256);
        using IDisposable route = router.Register("scope", original);

        Assert.ThrowsException<InvalidOperationException>(
            () => router.Register("scope", replacement));
        Assert.IsTrue(
            router.Route(
                "scope",
                DateTimeOffset.UtcNow,
                "Comment",
                "original"));
        Assert.AreEqual("original", original.Records.Single().Message);
        Assert.AreEqual(0, replacement.Records.Count);
    }

    [TestMethod]
    public void Dispose_ProtocolCleanupFailureRemainsIndependentFromDiagnosticsFailure()
    {
        using LifecycleFixture fixture = LifecycleFixture.Create();
        fixture.Provider.RequestStopAsyncHandler =
            static (_, _) => throw new IOException("hostile secret=abc");
        using DiagnosticsInvocationLifecycle lifecycle = fixture.Start();

        lifecycle.MarkCleanupFailed();
        lifecycle.Dispose();

        Assert.AreEqual(LifecycleStatus.Failed, lifecycle.CleanupStatus);
        Assert.IsTrue(
            lifecycle.Errors.Chronology.Any(
                error => error.Code == CaptureProviderFailureCode.StopFailed.ToString()));
        Assert.IsFalse(
            lifecycle.Errors.Chronology.Any(
                error => error.Message.Contains("secret=abc", StringComparison.Ordinal)));
    }

    [TestMethod]
    public void Dispose_ProviderStartAndFinalizationFailures_DoNotPersistHostileDetails()
    {
        const string Secret = "provider-secret";
        using LifecycleFixture fixture = LifecycleFixture.Create(Secret);
        fixture.Provider.WaitForFinalizationAsyncHandler =
            static (_, _) => throw new IOException("provider-secret");
        using DiagnosticsInvocationLifecycle lifecycle = fixture.Start();

        lifecycle.MarkCleanupCompleted();
        lifecycle.Dispose();

        string manifest = File.ReadAllText(fixture.ManifestPath);
        Assert.IsFalse(manifest.Contains(Secret, StringComparison.Ordinal));
        Assert.IsTrue(
            lifecycle.Errors.Chronology.Any(
                error =>
                    error.Code ==
                    CaptureProviderFailureCode.FinalizationFailed.ToString()));
    }

    [TestMethod]
    public void Dispose_ArtifactWriteFailure_IsRecordedAndDoesNotEscape()
    {
        using LifecycleFixture fixture = LifecycleFixture.Create();
        using DiagnosticsInvocationLifecycle lifecycle = fixture.Start();
        lifecycle.MarkCleanupCompleted();
        string invocationPath = fixture.ArtifactInvocation!.DirectoryPath;
        Directory.Delete(invocationPath, recursive: true);
        File.WriteAllText(invocationPath, "blocks directory recreation");

        lifecycle.Dispose();

        Assert.IsTrue(
            lifecycle.Errors.Chronology.Any(
                error => error.Code == "Diagnostics.ArtifactWriteFailed"));
    }

    [TestMethod]
    public async Task UnsupportedProvider_ProbeIsHonestAndHardwareIndependent()
    {
        var provider = new UnsupportedCaptureProvider();
        using TemporaryDirectory directory = TemporaryDirectory.Create();
        string sourceRoot = directory.CreateSubdirectory("source");
        string buildRoot = directory.CreateSubdirectory("build");
        string artifactRoot = directory.CreateSubdirectory("artifacts");
        using ArtifactStore store =
            ArtifactStore.Open(artifactRoot, sourceRoot, buildRoot);
        InvocationIdentity identity = InvocationIdentity.Create(
            "run",
            "test",
            "attempt",
            string.Empty);
        using ArtifactInvocation invocation = store.CreateInvocation(identity);
        var request = new CaptureProviderStartRequest(
            identity,
            invocation,
            new[] { "opaque-target" },
            "Native",
            TimeSpan.FromMinutes(1),
            1024 * 1024);

        CaptureProviderProbeResult result =
            await provider.ProbeAsync(request, default);

        Assert.IsFalse(result.IsAvailable);
        Assert.AreEqual(
            CaptureProviderFailureCode.ProviderUnsupported,
            result.FailureCode);
        Assert.IsFalse(
            Directory.EnumerateFileSystemEntries(invocation.DirectoryPath).Any());
    }

    [TestMethod]
    public void Router_RedactsSensitiveAndHostileValuesBeforePersistence()
    {
        using LifecycleFixture fixture = LifecycleFixture.Create(
            sensitiveValue: "top-secret");
        using DiagnosticsInvocationLifecycle lifecycle = fixture.Start();

        fixture.Router.Route(
            fixture.ScopeKey,
            DateTimeOffset.UtcNow,
            "Comment\r\nInjected",
            "value=top-secret\r\nforged");
        lifecycle.MarkCleanupCompleted();
        lifecycle.Dispose();

        string persisted = File.ReadAllText(fixture.LogPath);
        Assert.IsFalse(persisted.Contains("top-secret", StringComparison.Ordinal));
        Assert.IsFalse(persisted.Contains("\r", StringComparison.Ordinal));
        Assert.IsTrue(persisted.Contains("[REDACTED]", StringComparison.Ordinal));
    }

    private static ArtifactRecord WriteProviderArtifact(
        ArtifactInvocation invocation,
        string relativePath,
        string content,
        string mediaType)
    {
        using ArtifactCheckpoint checkpoint =
            invocation.CreateCheckpoint(relativePath.Split('/'));
        checkpoint.WriteText(content);
        checkpoint.Commit();

        byte[] bytes = Encoding.UTF8.GetBytes(content);
        return ArtifactRecord.CreateFinalized(
            relativePath,
            "deterministic",
            bytes.LongLength,
            Convert.ToHexString(SHA256.HashData(bytes)),
            ArtifactConfidentiality.Restricted,
            ArtifactRelation.Original,
            mediaType);
    }

    private static JsonElement FindArtifact(
        JsonElement manifest,
        string relativePath)
    {
        return manifest.GetProperty("artifacts")
            .EnumerateArray()
            .Single(
                artifact =>
                    artifact.GetProperty("relativePath").GetString() ==
                    relativePath);
    }

    private sealed class LifecycleFixture : IDisposable
    {
        private readonly TemporaryDirectory temporaryDirectory;
        private readonly ArtifactStore artifactStore;
        private readonly TestEffectiveConfigurationSource source;
        private readonly string sensitiveValue;

        private LifecycleFixture(
            TemporaryDirectory temporaryDirectory,
            ArtifactStore artifactStore,
            TestEffectiveConfigurationSource source,
            string sensitiveValue)
        {
            this.temporaryDirectory = temporaryDirectory;
            this.artifactStore = artifactStore;
            this.source = source;
            this.sensitiveValue = sensitiveValue;
        }

        public string ScopeKey => "Lifecycle.Test";

        public ArtifactInvocation? ArtifactInvocation { get; private set; }

        public DeterministicCaptureProvider Provider { get; } = new();

        public InvocationLogRouter Router { get; } = new();

        public string ManifestPath =>
            Path.Combine(ArtifactInvocation!.DirectoryPath, "manifest.json");

        public string LogPath =>
            Path.Combine(ArtifactInvocation!.DirectoryPath, "ptf-log.ndjson");

        public static LifecycleFixture Create(string sensitiveValue = "top-secret")
        {
            TemporaryDirectory temporaryDirectory = TemporaryDirectory.Create();
            string sourceRoot = temporaryDirectory.CreateSubdirectory("source");
            string buildRoot = temporaryDirectory.CreateSubdirectory("build");
            string artifactRoot = temporaryDirectory.CreateSubdirectory("artifacts");
            ArtifactStore artifactStore = ArtifactStore.Open(
                artifactRoot,
                sourceRoot,
                buildRoot);
            return new LifecycleFixture(
                temporaryDirectory,
                artifactStore,
                new TestEffectiveConfigurationSource(CreateEnabledValues(artifactRoot)),
                sensitiveValue);
        }

        public DiagnosticsInvocationLifecycle Start()
        {
            DiagnosticsInvocationLifecycle lifecycle =
                DiagnosticsInvocationLifecycle.Start(
                source,
                ScopeKey,
                "Lifecycle.Test",
                (_, identity) =>
                {
                    ArtifactInvocation = artifactStore.CreateInvocation(identity);
                    return new DiagnosticsInvocationRuntime(
                        identity,
                        ArtifactInvocation,
                        Router,
                        Provider,
                        new[] { sensitiveValue });
                });
            Assert.IsTrue(
                lifecycle.IsEnabled,
                string.Join(
                    Environment.NewLine,
                    lifecycle.Errors.Chronology.Select(
                        error => $"{error.Code}: {error.Message}")));
            return lifecycle;
        }

        public void Dispose()
        {
            ArtifactInvocation?.Dispose();
            artifactStore.Dispose();
            temporaryDirectory.Dispose();
        }

        private static IReadOnlyDictionary<string, string?> CreateEnabledValues(
            string artifactRoot)
        {
            return new Dictionary<string, string?>
            {
                [DiagnosticsConfigurationPropertyNames.Enabled] = "true",
                [DiagnosticsConfigurationPropertyNames.ArtifactRoot] = artifactRoot,
                [DiagnosticsConfigurationPropertyNames.Provider] = "Automatic",
                [DiagnosticsConfigurationPropertyNames.ToolPath] = string.Empty,
                [DiagnosticsConfigurationPropertyNames.Targets] = "Adapter-B",
                [DiagnosticsConfigurationPropertyNames.TrafficScope] = "RdmaFocused",
                [DiagnosticsConfigurationPropertyNames.StartTimeout] = "00:00:05",
                [DiagnosticsConfigurationPropertyNames.StopTimeout] = "00:00:05",
                [DiagnosticsConfigurationPropertyNames.MaxDuration] = "00:01:00",
                [DiagnosticsConfigurationPropertyNames.MaxBytes] = "1048576",
                [DiagnosticsConfigurationPropertyNames.Format] = "Native",
                [DiagnosticsConfigurationPropertyNames.NativeLogsEnabled] = "false",
                [DiagnosticsConfigurationPropertyNames.Retention] = "KeepAll",
            };
        }
    }
}
