// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using Microsoft.Protocols.TestSuites.Diagnostics.Configuration;
using Microsoft.Protocols.TestSuites.Diagnostics.Errors;
using Microsoft.Protocols.TestSuites.Diagnostics.Identity;
using Microsoft.Protocols.TestSuites.Diagnostics.Lifecycle;
using Microsoft.Protocols.TestSuites.Diagnostics.Logging;
using Microsoft.Protocols.TestSuites.Diagnostics.Providers;
using Microsoft.Protocols.TestSuites.Diagnostics.Storage;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Protocols.TestSuites.FileServer.Diagnostics.Portability.Tests;

[TestClass]
public sealed class SharedDiagnosticsPortabilityTests
{
    private static readonly DiagnosticsConfigurationPropertyMap PropertyMap =
        new(
            enabled: "FileServer.Diagnostics.Enabled",
            artifactRoot: "FileServer.Diagnostics.ArtifactRoot",
            provider: "FileServer.Diagnostics.Capture.Provider",
            toolPath: "FileServer.Diagnostics.Capture.ToolPath",
            targets: "FileServer.Diagnostics.Capture.Targets",
            trafficScope: "FileServer.Diagnostics.Capture.TrafficScope",
            startTimeout: "FileServer.Diagnostics.Capture.StartTimeout",
            stopTimeout: "FileServer.Diagnostics.Capture.StopTimeout",
            maxDuration: "FileServer.Diagnostics.Capture.MaxDuration",
            maxBytes: "FileServer.Diagnostics.Capture.MaxBytes",
            format: "FileServer.Diagnostics.Capture.Format",
            nativeLogsEnabled: "FileServer.Diagnostics.Logs.NativeEnabled",
            retention: "FileServer.Diagnostics.Retention",
            targetFallback: "FileServer.PrimaryTarget");

    [TestMethod]
    public void Read_AlternatePropertyNames_ProducesEnabledConfiguration()
    {
        string artifactRoot = Path.Combine(
            Path.GetTempPath(),
            "fileserver-diagnostics-portability");
        var source = new DictionaryConfigurationSource(
            CreateEnabledValues(artifactRoot));

        DiagnosticsConfiguration configuration =
            DiagnosticsConfigurationReader.Read(
                source,
                new DiagnosticErrorLedger(),
                DateTimeOffset.UtcNow,
                PropertyMap);

        Assert.AreEqual(
            DiagnosticsConfigurationState.Enabled,
            configuration.State);
        Assert.AreEqual(artifactRoot, configuration.ArtifactRoot!.Value);
        Assert.AreEqual(
            "192.0.2.20",
            configuration.Capture!.Targets.Single().Value);
        Assert.AreEqual(
            ConfigurationProvenance.Inferred,
            configuration.Capture.Targets.Single().Provenance);
    }

    [TestMethod]
    public void Start_DisabledAlternateConfiguration_HasZeroSideEffects()
    {
        var source = new DictionaryConfigurationSource(
            new Dictionary<string, string?>
            {
                [PropertyMap.Enabled] = "false",
            },
            failOnUnexpectedRead: true);
        int scopeCalls = 0;
        int displayNameCalls = 0;
        int runtimeFactoryCalls = 0;

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
                (_, _) =>
                {
                    runtimeFactoryCalls++;
                    throw new InvalidOperationException("must not be called");
                },
                PropertyMap);

        Assert.IsFalse(lifecycle.IsEnabled);
        Assert.AreEqual(0, scopeCalls);
        Assert.AreEqual(0, displayNameCalls);
        Assert.AreEqual(0, runtimeFactoryCalls);
        CollectionAssert.AreEqual(
            new[] { PropertyMap.Enabled },
            source.RequestedProperties.ToArray());
    }

    [TestMethod]
    public void Start_RuntimeFailure_IsRecordedWithoutEscaping()
    {
        string artifactRoot = Path.Combine(
            Path.GetTempPath(),
            "fileserver-diagnostics-portability");
        var source = new DictionaryConfigurationSource(
            CreateEnabledValues(artifactRoot, explicitTarget: "Adapter-01"));

        using DiagnosticsInvocationLifecycle lifecycle =
            DiagnosticsInvocationLifecycle.Start(
                source,
                "FileServer.Scope",
                "FileServer.Portability",
                (_, _) => throw new InvalidOperationException("startup failed"),
                PropertyMap);

        Assert.IsFalse(lifecycle.IsEnabled);
        Assert.IsTrue(
            lifecycle.Errors.Chronology.Any(
                error => error.Code == "Diagnostics.StartFailed"));
    }

    [TestMethod]
    public void Dispose_UnsupportedProvider_FinalizesExplicitNoEvidenceManifest()
    {
        using var temporaryDirectory = new TemporaryDirectory();
        string sourceRoot = temporaryDirectory.CreateSubdirectory("source");
        string buildRoot = temporaryDirectory.CreateSubdirectory("build");
        string artifactRoot = temporaryDirectory.CreateSubdirectory("artifacts");
        var source = new DictionaryConfigurationSource(
            CreateEnabledValues(artifactRoot, explicitTarget: "Adapter-01"));
        using ArtifactStore artifactStore =
            ArtifactStore.Open(artifactRoot, sourceRoot, buildRoot);
        ArtifactInvocation? invocation = null;

        using (DiagnosticsInvocationLifecycle lifecycle =
               DiagnosticsInvocationLifecycle.Start(
                   source,
                   "FileServer.Scope",
                   "FileServer.Portability",
                   (_, identity) =>
                   {
                       invocation = artifactStore.CreateInvocation(identity);
                       return new DiagnosticsInvocationRuntime(
                           identity,
                           invocation,
                           new InvocationLogRouter(),
                           new UnsupportedCaptureProvider());
                   },
                   PropertyMap))
        {
            Assert.IsTrue(lifecycle.IsEnabled);
            lifecycle.MarkCleanupCompleted();
        }

        Assert.IsNotNull(invocation);
        string manifestPath = Path.Combine(
            invocation.DirectoryPath,
            "manifest.json");
        using JsonDocument manifest =
            JsonDocument.Parse(File.ReadAllText(manifestPath));

        Assert.AreEqual(
            "Unavailable",
            manifest.RootElement.GetProperty("collectionStatus").GetString());
        Assert.AreEqual(
            "ProviderUnsupported",
            manifest.RootElement.GetProperty("evidenceReasonCode").GetString());
        Assert.AreEqual(
            "Capture",
            manifest.RootElement.GetProperty("artifactAbsences")
                .EnumerateArray()
                .Single()
                .GetProperty("kind")
                .GetString());

        invocation.Dispose();
    }

    private static IReadOnlyDictionary<string, string?> CreateEnabledValues(
        string artifactRoot,
        string? explicitTarget = null)
    {
        return new Dictionary<string, string?>
        {
            [PropertyMap.Enabled] = "true",
            [PropertyMap.ArtifactRoot] = artifactRoot,
            [PropertyMap.Provider] = "Automatic",
            [PropertyMap.ToolPath] = string.Empty,
            [PropertyMap.Targets] = explicitTarget ?? string.Empty,
            [PropertyMap.TargetFallback!] = "192.0.2.20",
            [PropertyMap.TrafficScope] = "RdmaFocused",
            [PropertyMap.StartTimeout] = "00:00:05",
            [PropertyMap.StopTimeout] = "00:00:05",
            [PropertyMap.MaxDuration] = "00:01:00",
            [PropertyMap.MaxBytes] = "1048576",
            [PropertyMap.Format] = "Native",
            [PropertyMap.NativeLogsEnabled] = "false",
            [PropertyMap.Retention] = "KeepAll",
        };
    }

    private sealed class DictionaryConfigurationSource :
        IEffectiveConfigurationSource
    {
        private readonly IReadOnlyDictionary<string, string?> values;
        private readonly bool failOnUnexpectedRead;

        public DictionaryConfigurationSource(
            IReadOnlyDictionary<string, string?> values,
            bool failOnUnexpectedRead = false)
        {
            this.values = values;
            this.failOnUnexpectedRead = failOnUnexpectedRead;
        }

        public List<string> RequestedProperties { get; } = new();

        public string? GetValue(string propertyName)
        {
            RequestedProperties.Add(propertyName);
            if (values.TryGetValue(propertyName, out string? value))
            {
                return value;
            }

            if (failOnUnexpectedRead)
            {
                throw new InvalidOperationException(
                    $"Unexpected property read: {propertyName}");
            }

            return null;
        }
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            Root = Path.Combine(
                Path.GetTempPath(),
                "wpts-fileserver-diagnostics-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Root);
        }

        public string Root { get; }

        public string CreateSubdirectory(string name)
        {
            string path = Path.Combine(Root, name);
            Directory.CreateDirectory(path);
            return path;
        }

        public void Dispose()
        {
            if (Directory.Exists(Root))
            {
                Directory.Delete(Root, recursive: true);
            }
        }
    }
}
