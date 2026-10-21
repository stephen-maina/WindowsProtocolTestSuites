// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Text.Json;
using Microsoft.Protocols.TestTools;
using Microsoft.Protocols.TestTools.Logging;
using Microsoft.Protocols.TestSuites.Diagnostics.Configuration;
using Microsoft.Protocols.TestSuites.Diagnostics.Errors;
using Microsoft.Protocols.TestSuites.Diagnostics.Lifecycle;
using Microsoft.Protocols.TestSuites.Diagnostics.Providers;
using Microsoft.Protocols.TestSuites.Diagnostics.Ptf;
using Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Ptf;
using Microsoft.Protocols.TestSuites.Diagnostics.Runner;
using Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Runner;
using Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.Configuration;
using Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.Providers;
using Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.TestSupport;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.Ptf;

[TestClass]
public sealed class PtfDiagnosticsLifecycleTests
{
    [DataTestMethod]
    [DataRow(null)]
    [DataRow("false")]
    public void Start_DisabledOrMissing_DoesNotRegisterOrWrite(string? enabled)
    {
        using TemporaryDirectory directory = TemporaryDirectory.Create();
        string buildRoot = directory.CreateSubdirectory("build");
        NameValueCollection properties =
            CreateMalformedDisabledProperties(enabled);
        var logger = new TestLogger();
        int identityFactoryCalls = 0;
        using DiagnosticsInvocationLifecycle lifecycle =
            PtfDiagnosticsLifecycle.Start(
                properties,
                new Dictionary<string, object>(),
                logger,
                buildRoot,
                SmbdDiagnosticsSuite.Definition,
                () =>
                {
                    identityFactoryCalls++;
                    throw new AssertFailedException(
                        "Disabled diagnostics must not evaluate runner identity.");
                },
                _ => throw new AssertFailedException(
                    "Disabled diagnostics must not create a capture provider."));

        Assert.IsFalse(lifecycle.IsEnabled);
        Assert.AreEqual(0, lifecycle.Errors.Chronology.Count);
        Assert.AreEqual(0, identityFactoryCalls);
        Assert.AreEqual(0, logger.LogProfileAccessCount);
        Assert.AreEqual(0, logger.SinkCount);
        Assert.AreEqual(
            0,
            Directory.EnumerateFileSystemEntries(buildRoot).Count());
    }

    [TestMethod]
    public void Start_LogRegistrationFails_RecordsCaptureErrorAndPreservesProtocolException()
    {
        const string Scope = "Lifecycle.RegistrationFailure";
        using TemporaryDirectory directory = TemporaryDirectory.Create();
        string sourceRoot = directory.CreateSubdirectory("source");
        string buildRoot = Path.Combine(
            sourceRoot,
            "bin",
            "Debug",
            "net8.0");
        Directory.CreateDirectory(buildRoot);
        string artifactRoot = directory.CreateSubdirectory("artifacts");
        NameValueCollection properties =
            CreateEnabledProperties(artifactRoot);
        var testProperties = new Dictionary<string, object>
        {
            ["CurrentTestCaseName"] = Scope,
        };
        var logger = new TestLogger(throwOnLogProfileGet: true);
        int identityFactoryCalls = 0;

        DiagnosticsInvocationLifecycle lifecycle =
            PtfDiagnosticsLifecycle.Start(
                properties,
                testProperties,
                logger,
                buildRoot,
                SmbdDiagnosticsSuite.Definition,
                () =>
                {
                    identityFactoryCalls++;
                    return new RunnerTestExecutionIdentity(
                        "Lifecycle",
                        "RegistrationFailure",
                        "Registration failure",
                        testRunCount: 1);
                });

        Assert.IsFalse(lifecycle.IsEnabled);
        Assert.AreEqual(1, identityFactoryCalls);
        Assert.AreEqual(1, logger.LogProfileAccessCount);
        Assert.AreEqual(0, logger.SinkCount);
        Assert.AreEqual(1, lifecycle.Errors.Chronology.Count);
        Assert.AreEqual(
            "Diagnostics.StartFailed",
            lifecycle.Errors.Chronology[0].Code);
        Assert.AreEqual(
            DiagnosticErrorCategory.Capture,
            lifecycle.Errors.Chronology[0].Category);

        IOException protocolFailure = new("Protocol failure.");
        IOException observed = Assert.ThrowsExactly<IOException>(() =>
        {
            using (lifecycle)
            {
                throw protocolFailure;
            }
        });

        Assert.AreSame(protocolFailure, observed);
        Assert.AreEqual(1, lifecycle.Errors.Chronology.Count);
    }

    [TestMethod]
    public void Start_Enabled_UsesOneSharedRouterAndRedactsEffectiveSecrets()
    {
        const string Scope = "Lifecycle.Composition";
        const string Secret = "composition-secret";
        using TemporaryDirectory directory = TemporaryDirectory.Create();
        string sourceRoot = directory.CreateSubdirectory("source");
        string buildRoot = Path.Combine(
            sourceRoot,
            "bin",
            "Debug",
            "net8.0");
        Directory.CreateDirectory(buildRoot);
        string artifactRoot = directory.CreateSubdirectory("artifacts");
        NameValueCollection properties =
            CreateEnabledProperties(artifactRoot);
        properties["SutPassword"] = Secret;
        var testProperties = new Dictionary<string, object>
        {
            ["CurrentTestCaseName"] = Scope,
        };
        var logger = new TestLogger();

        using DiagnosticsInvocationLifecycle lifecycle =
            PtfDiagnosticsLifecycle.Start(
                properties,
                testProperties,
                logger,
                buildRoot,
                SmbdDiagnosticsSuite.Definition,
                () => new RunnerTestExecutionIdentity(
                    "Lifecycle",
                    "Composition",
                    "Composition (row-1)",
                    testRunCount: 1),
                _ => new UnsupportedCaptureProvider());
        PtfInvocationLogSink sink =
            (PtfInvocationLogSink)logger.LogProfile.AllSinks.Single(
                candidate =>
                    candidate.Name == PtfInvocationLogSink.SinkName);
        sink.WriteEntry(
            new Dictionary<string, object>
            {
                ["LogEntryKind"] = LogEntryKind.Comment,
                ["Message"] = $"credential={Secret}",
                ["CurrentTestCaseName"] = Scope,
                ["TimeStamp"] = DateTimeOffset.UtcNow,
            });
        lifecycle.MarkCleanupCompleted();
        lifecycle.Dispose();

        string invocationDirectory =
            Directory.GetDirectories(artifactRoot, "*", SearchOption.AllDirectories)
                .Single(path => File.Exists(Path.Combine(path, "manifest.json")));
        string manifest =
            File.ReadAllText(Path.Combine(invocationDirectory, "manifest.json"));
        string log =
            File.ReadAllText(Path.Combine(invocationDirectory, "ptf-log.ndjson"));
        using JsonDocument manifestDocument = JsonDocument.Parse(manifest);
        Assert.IsTrue(lifecycle.IsEnabled);
        Assert.AreEqual(1, logger.LogProfile.AllSinks.Count);
        Assert.IsTrue(
            manifestDocument.RootElement.GetProperty("metadata")
                .EnumerateArray()
                .Any(
                    entry =>
                        entry.GetProperty("key").GetString() ==
                            "outcomeAuthority" &&
                        entry.GetProperty("value").GetString() ==
                            "provisional-not-authoritative"));
        Assert.IsTrue(
            manifestDocument.RootElement.GetProperty("metadata")
                .EnumerateArray()
                .Any(entry =>
                    entry.GetProperty("key").GetString() ==
                        RunnerCorrelationMetadata.ManagedTestIdentitySha256 &&
                    entry.GetProperty("value").GetString()!.Length == 64));
        Assert.IsTrue(
            manifestDocument.RootElement.GetProperty("metadata")
                .EnumerateArray()
                .Any(entry =>
                    entry.GetProperty("key").GetString() ==
                        RunnerCorrelationMetadata.TestDisplayNameSha256 &&
                    entry.GetProperty("value").GetString()!.Length == 64));
        Assert.IsFalse(
            manifest.Contains("Composition (row-1)", StringComparison.Ordinal));
        Assert.IsFalse(log.Contains(Secret, StringComparison.Ordinal));
        Assert.IsTrue(log.Contains("[REDACTED]", StringComparison.Ordinal));
    }

    [TestMethod]
    [DoNotParallelize]
    public void Start_RunnerManagedInvocation_UsesRunScopedTestsRoot()
    {
        const string Scope = "Lifecycle.RunnerManaged";
        string runId = RunnerRunContext.CreateRunId();
        string? priorRunId = Environment.GetEnvironmentVariable(
            SmbdRunnerContext.RunIdEnvironmentVariable);
        using TemporaryDirectory directory = TemporaryDirectory.Create();
        string sourceRoot = directory.CreateSubdirectory("source");
        string buildRoot = Path.Combine(
            sourceRoot,
            "bin",
            "Debug",
            "net8.0");
        Directory.CreateDirectory(buildRoot);
        string artifactRoot = directory.CreateSubdirectory("artifacts");
        var testProperties = new Dictionary<string, object>
        {
            ["CurrentTestCaseName"] = Scope,
        };

        try
        {
            Environment.SetEnvironmentVariable(
                SmbdRunnerContext.RunIdEnvironmentVariable,
                runId);
            using DiagnosticsInvocationLifecycle lifecycle =
                PtfDiagnosticsLifecycle.Start(
                    CreateEnabledProperties(artifactRoot),
                    testProperties,
                    new TestLogger(),
                    buildRoot,
                    SmbdDiagnosticsSuite.Definition,
                    () => new RunnerTestExecutionIdentity(
                        "Lifecycle",
                        "RunnerManaged",
                        "RunnerManaged",
                        testRunCount: 1),
                    _ => new UnsupportedCaptureProvider());
            lifecycle.MarkCleanupCompleted();
            lifecycle.Dispose();
        }
        finally
        {
            Environment.SetEnvironmentVariable(
                SmbdRunnerContext.RunIdEnvironmentVariable,
                priorRunId);
        }

        string testsRoot = Path.Combine(
            artifactRoot,
            runId,
            "tests");
        string manifestPath = Directory
            .EnumerateFiles(
                testsRoot,
                "manifest.json",
                SearchOption.AllDirectories)
            .Single();
        using JsonDocument manifest = JsonDocument.Parse(
            File.ReadAllText(manifestPath));
        Assert.IsTrue(
            manifest.RootElement.GetProperty("metadata")
                .EnumerateArray()
                .Any(entry =>
                    entry.GetProperty("key").GetString() ==
                        RunnerCorrelationMetadata.RunId &&
                    entry.GetProperty("value").GetString() == runId));
    }

    [DataTestMethod]
    [DataRow(
        "WindowsServer2025",
        DiagnosticsConfigurationPolicy.AutomaticProvider)]
    [DataRow(
        "NonWindows",
        DiagnosticsConfigurationPolicy.AutomaticProvider)]
    [DataRow(
        "WindowsServer2025",
        NetshTraceCaptureProvider.ProviderIdentifier)]
    public void Start_WindowsDriver_IgnoresSutPlatformAndUsesWindowsProvider(
        string sutPlatform,
        string providerIdentifier)
    {
        using TemporaryDirectory directory = TemporaryDirectory.Create();
        string sourceRoot = directory.CreateSubdirectory("source");
        string buildRoot = Path.Combine(
            sourceRoot,
            "bin",
            "Debug",
            "net8.0");
        Directory.CreateDirectory(buildRoot);
        string artifactRoot = directory.CreateSubdirectory("artifacts");
        NameValueCollection properties = CreateEnabledProperties(artifactRoot);
        properties["Platform"] = sutPlatform;
        properties[DiagnosticsConfigurationPropertyNames.Provider] =
            providerIdentifier;
        properties[DiagnosticsConfigurationPropertyNames.Targets] = "192.0.2.10";
        var testProperties = new Dictionary<string, object>
        {
            ["CurrentTestCaseName"] = "Lifecycle.ProviderSelection",
        };
        DiagnosticsCaptureConfiguration? observedCapture = null;
        var provider = new DeterministicCaptureProvider();

        using DiagnosticsInvocationLifecycle lifecycle =
            PtfDiagnosticsLifecycle.Start(
                properties,
                testProperties,
                new TestLogger(),
                buildRoot,
                SmbdDiagnosticsSuite.Definition,
                () => new RunnerTestExecutionIdentity(
                    "Lifecycle",
                    "ProviderSelection",
                    "Provider selection",
                    testRunCount: 1),
                capture =>
                {
                    observedCapture = capture;
                    return provider;
                },
                runtimePlatformProbe: () =>
                    DiagnosticsRuntimePlatform.Windows);
        lifecycle.MarkCleanupCompleted();
        lifecycle.Dispose();

        Assert.IsTrue(lifecycle.IsEnabled);
        Assert.IsNotNull(observedCapture);
        Assert.AreEqual(providerIdentifier, observedCapture.Provider.Value);
        Assert.AreEqual(TimeSpan.FromMinutes(1), observedCapture.MaxDuration.Value);
        Assert.AreEqual(1048576L, observedCapture.MaxBytes.Value);
        CollectionAssert.AreEqual(
            new[] { "Probe", "Start", "Readiness", "Stop", "Finalization" },
            provider.Calls.ToArray());
    }

    [DataTestMethod]
    [DataRow("WindowsServer2025")]
    [DataRow("NonWindows")]
    public void Start_LinuxDriver_IgnoresSutPlatformAndReportsBackendUnavailable(
        string sutPlatform)
    {
        using TemporaryDirectory directory = TemporaryDirectory.Create();
        string sourceRoot = directory.CreateSubdirectory("source");
        string buildRoot = Path.Combine(
            sourceRoot,
            "bin",
            "Debug",
            "net8.0");
        Directory.CreateDirectory(buildRoot);
        string artifactRoot = directory.CreateSubdirectory("artifacts");
        NameValueCollection properties = CreateEnabledProperties(artifactRoot);
        properties["Platform"] = sutPlatform;
        properties["DriverPlatform"] = "NonWindows";
        int factoryCalls = 0;

        using DiagnosticsInvocationLifecycle lifecycle =
            PtfDiagnosticsLifecycle.Start(
                properties,
                new Dictionary<string, object>
                {
                    ["CurrentTestCaseName"] = "Lifecycle.PlatformSelection",
                },
                new TestLogger(),
                buildRoot,
                SmbdDiagnosticsSuite.Definition,
                () => new RunnerTestExecutionIdentity(
                    "Lifecycle",
                    "PlatformSelection",
                    "Platform selection",
                    testRunCount: 1),
                captureProviderFactory: _ =>
                {
                    factoryCalls++;
                    return new DeterministicCaptureProvider();
                },
                runtimePlatformProbe: () =>
                    DiagnosticsRuntimePlatform.Linux);
        lifecycle.MarkCleanupCompleted();
        lifecycle.Dispose();

        Assert.IsTrue(lifecycle.IsEnabled);
        Assert.AreEqual(0, factoryCalls);
        DiagnosticError error = lifecycle.Errors.Chronology.Single(
            candidate =>
                candidate.Code ==
                CaptureProviderFailureCode.ProviderUnsupported.ToString());
        StringAssert.Contains(
            error.Message,
            "Linux capture provider is not available");
    }

    [DataTestMethod]
    [DataRow(
        "WindowsServer2025",
        DiagnosticsRuntimePlatform.Linux)]
    [DataRow(
        "NonWindows",
        DiagnosticsRuntimePlatform.Windows)]
    public void Start_DriverPlatformDoesNotMatchRuntime_ReportsMismatch(
        string driverPlatform,
        DiagnosticsRuntimePlatform runtimePlatform)
    {
        using TemporaryDirectory directory = TemporaryDirectory.Create();
        string sourceRoot = directory.CreateSubdirectory("source");
        string buildRoot = Path.Combine(
            sourceRoot,
            "bin",
            "Debug",
            "net8.0");
        Directory.CreateDirectory(buildRoot);
        NameValueCollection properties = CreateEnabledProperties(
            directory.CreateSubdirectory("artifacts"));
        properties["DriverPlatform"] = driverPlatform;
        int factoryCalls = 0;

        using DiagnosticsInvocationLifecycle lifecycle =
            PtfDiagnosticsLifecycle.Start(
                properties,
                new Dictionary<string, object>(),
                new TestLogger(),
                buildRoot,
                SmbdDiagnosticsSuite.Definition,
                captureProviderFactory: _ =>
                {
                    factoryCalls++;
                    return new DeterministicCaptureProvider();
                },
                runtimePlatformProbe: () => runtimePlatform);
        lifecycle.MarkCleanupCompleted();
        lifecycle.Dispose();

        Assert.IsTrue(lifecycle.IsEnabled);
        Assert.AreEqual(0, factoryCalls);
        DiagnosticError error = lifecycle.Errors.Chronology.Single(
            candidate =>
                candidate.Code ==
                CaptureProviderFailureCode.ProviderUnsupported.ToString());
        StringAssert.Contains(error.Message, "does not match");
    }

    [TestMethod]
    public void Start_NetshTraceOnLinuxDriver_ReportsProviderIncompatibility()
    {
        using TemporaryDirectory directory = TemporaryDirectory.Create();
        string sourceRoot = directory.CreateSubdirectory("source");
        string buildRoot = Path.Combine(
            sourceRoot,
            "bin",
            "Debug",
            "net8.0");
        Directory.CreateDirectory(buildRoot);
        NameValueCollection properties = CreateEnabledProperties(
            directory.CreateSubdirectory("artifacts"));
        properties["DriverPlatform"] = "NonWindows";
        properties[DiagnosticsConfigurationPropertyNames.Provider] =
            NetshTraceCaptureProvider.ProviderIdentifier;
        int factoryCalls = 0;

        using DiagnosticsInvocationLifecycle lifecycle =
            PtfDiagnosticsLifecycle.Start(
                properties,
                new Dictionary<string, object>(),
                new TestLogger(),
                buildRoot,
                SmbdDiagnosticsSuite.Definition,
                captureProviderFactory: _ =>
                {
                    factoryCalls++;
                    return new DeterministicCaptureProvider();
                },
                runtimePlatformProbe: () =>
                    DiagnosticsRuntimePlatform.Linux);
        lifecycle.MarkCleanupCompleted();
        lifecycle.Dispose();

        Assert.IsTrue(lifecycle.IsEnabled);
        Assert.AreEqual(0, factoryCalls);
        DiagnosticError error = lifecycle.Errors.Chronology.Single(
            candidate =>
                candidate.Code ==
                CaptureProviderFailureCode.ProviderUnsupported.ToString());
        StringAssert.Contains(
            error.Message,
            "NetshTrace is not supported on Linux");
    }

    [DataTestMethod]
    [DataRow(null)]
    [DataRow("")]
    [DataRow("UnknownPlatform")]
    public void Start_InvalidDriverPlatform_ReportsInvalidConfiguration(
        string? driverPlatform)
    {
        using TemporaryDirectory directory = TemporaryDirectory.Create();
        string sourceRoot = directory.CreateSubdirectory("source");
        string buildRoot = Path.Combine(
            sourceRoot,
            "bin",
            "Debug",
            "net8.0");
        Directory.CreateDirectory(buildRoot);
        NameValueCollection properties = CreateEnabledProperties(
            directory.CreateSubdirectory("artifacts"));
        properties["DriverPlatform"] = driverPlatform;
        int factoryCalls = 0;

        using DiagnosticsInvocationLifecycle lifecycle =
            PtfDiagnosticsLifecycle.Start(
                properties,
                new Dictionary<string, object>(),
                new TestLogger(),
                buildRoot,
                SmbdDiagnosticsSuite.Definition,
                captureProviderFactory: _ =>
                {
                    factoryCalls++;
                    return new DeterministicCaptureProvider();
                },
                runtimePlatformProbe: () =>
                    DiagnosticsRuntimePlatform.Windows);
        lifecycle.MarkCleanupCompleted();
        lifecycle.Dispose();

        Assert.IsTrue(lifecycle.IsEnabled);
        Assert.AreEqual(0, factoryCalls);
        DiagnosticError error = lifecycle.Errors.Chronology.Single(
            candidate =>
                candidate.Code ==
                CaptureProviderFailureCode.ProviderUnsupported.ToString());
        StringAssert.Contains(error.Message, "DriverPlatform");
    }

    [TestMethod]
    public void Start_UnsupportedProviderSelectionDoesNotCreateConcreteProvider()
    {
        using TemporaryDirectory directory = TemporaryDirectory.Create();
        string sourceRoot = directory.CreateSubdirectory("source");
        string buildRoot = Path.Combine(
            sourceRoot,
            "bin",
            "Debug",
            "net8.0");
        Directory.CreateDirectory(buildRoot);
        string artifactRoot = directory.CreateSubdirectory("artifacts");
        NameValueCollection properties = CreateEnabledProperties(artifactRoot);
        properties[DiagnosticsConfigurationPropertyNames.Provider] =
            "UnqualifiedProvider";
        int factoryCalls = 0;

        using DiagnosticsInvocationLifecycle lifecycle =
            PtfDiagnosticsLifecycle.Start(
                properties,
                new Dictionary<string, object>(),
                new TestLogger(),
                buildRoot,
                SmbdDiagnosticsSuite.Definition,
                runnerIdentityFactory: null,
                captureProviderFactory: _ =>
                {
                    factoryCalls++;
                    return new UnsupportedCaptureProvider();
                });

        Assert.IsFalse(lifecycle.IsEnabled);
        Assert.AreEqual(0, factoryCalls);
        Assert.IsTrue(
            lifecycle.Errors.Chronology.Any(
                error =>
                    error.Code ==
                    DiagnosticsConfigurationErrorCodes.ProviderUnsupported));
    }

    [DataTestMethod]
    [DataRow(false, false)]
    [DataRow(false, true)]
    [DataRow(true, false)]
    [DataRow(true, true)]
    public void Start_SessionResolvesIntoExcludedRoot_DoesNotMutateMarker(
        bool sessionIsBuildRoot,
        bool markerExists)
    {
        using TemporaryDirectory directory = TemporaryDirectory.Create();
        string sessionName = sessionIsBuildRoot ? "build" : "source";
        string sessionRoot = directory.CreateSubdirectory(sessionName);
        string buildRoot = sessionIsBuildRoot
            ? sessionRoot
            : Path.Combine(sessionRoot, "bin", "Release", "net8.0");
        Directory.CreateDirectory(buildRoot);
        string marker = Path.Combine(sessionRoot, PtfSessionLayout.MarkerFileName);
        DateTime originalStamp = default;
        if (markerExists)
        {
            File.WriteAllText(marker, "existing-source-marker");
            File.SetLastWriteTimeUtc(marker, new DateTime(2000, 1, 1, 0, 0, 0, DateTimeKind.Utc));
            originalStamp = File.GetLastWriteTimeUtc(marker);
        }

        NameValueCollection properties = CreateEnabledProperties(directory.Path);
        properties[PtfSessionLayout.SessionNameProperty] = sessionName;
        int providerCalls = 0;
        using DiagnosticsInvocationLifecycle lifecycle =
            PtfDiagnosticsLifecycle.Start(
                properties,
                new Dictionary<string, object>(),
                new TestLogger(),
                buildRoot,
                SmbdDiagnosticsSuite.Definition,
                captureProviderFactory: _ =>
                {
                    providerCalls++;
                    return new DeterministicCaptureProvider();
                });

        Assert.IsFalse(lifecycle.IsEnabled);
        Assert.AreEqual(1, lifecycle.Errors.Chronology.Count);
        Assert.AreEqual(0, providerCalls);
        Assert.IsFalse(Directory.Exists(Path.Combine(sessionRoot, PtfSessionLayout.TestsDirectoryName)));
        if (markerExists)
        {
            Assert.AreEqual("existing-source-marker", File.ReadAllText(marker));
            Assert.AreEqual(originalStamp, File.GetLastWriteTimeUtc(marker));
        }
        else
        {
            Assert.IsFalse(File.Exists(marker), "Rejected session must not create a source/build marker.");
        }
    }

    [DataTestMethod]
    [DataRow(false, false)]
    [DataRow(true, false)]
    [DataRow(false, true)]
    [DataRow(true, true)]
    public void Start_AncestorArtifactRootWithSafeSession_PreservesSourceDuringRetention(
        bool sourceHasOldSessionMarker,
        bool markedDirectoryContainsSource)
    {
        using TemporaryDirectory directory = TemporaryDirectory.Create();
        string markedDirectory = directory.CreateSubdirectory("source");
        string sourceRoot = markedDirectoryContainsSource
            ? directory.CreateSubdirectory(Path.Combine("source", "project"))
            : markedDirectory;
        string buildRoot = Path.Combine(sourceRoot, "bin", "Release", "net8.0");
        Directory.CreateDirectory(buildRoot);
        string protectedFile = Path.Combine(sourceRoot, "source.cs");
        File.WriteAllText(protectedFile, "protected source");
        string marker = Path.Combine(markedDirectory, PtfSessionLayout.MarkerFileName);
        if (sourceHasOldSessionMarker)
        {
            File.WriteAllText(marker, "old-session-marker");
            File.SetLastWriteTimeUtc(marker, new DateTime(2000, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        }

        NameValueCollection properties = CreateEnabledProperties(directory.Path);
        properties[PtfSessionLayout.SessionNameProperty] = "safe-current";
        properties[PtfSessionLayout.MaxSessionsProperty] = "1";
        using DiagnosticsInvocationLifecycle lifecycle =
            PtfDiagnosticsLifecycle.Start(
                properties,
                new Dictionary<string, object>(),
                new TestLogger(),
                buildRoot,
                SmbdDiagnosticsSuite.Definition,
                captureProviderFactory: _ => new DeterministicCaptureProvider(),
                runtimePlatformProbe: () => DiagnosticsRuntimePlatform.Windows);
        lifecycle.MarkCleanupCompleted();
        lifecycle.Dispose();

        Assert.IsTrue(lifecycle.IsEnabled);
        Assert.AreEqual("protected source", File.ReadAllText(protectedFile));
        Assert.IsTrue(Directory.Exists(buildRoot));
        Assert.AreEqual(sourceHasOldSessionMarker, File.Exists(marker));
        Assert.IsTrue(Directory.Exists(Path.Combine(directory.Path, "safe-current", "tests")));
    }

    private static NameValueCollection CreateEnabledProperties(
        string artifactRoot)
    {
        return new NameValueCollection
        {
            ["Platform"] = "WindowsServer2025",
            ["DriverPlatform"] = "WindowsServer2025",
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

    private static NameValueCollection CreateMalformedDisabledProperties(
        string? enabled)
    {
        var properties = new NameValueCollection();
        foreach (KeyValuePair<string, string?> property in
            DiagnosticsConfigurationReaderTests.CreateMalformedDisabledValues(
                enabled))
        {
            properties[property.Key] = property.Value;
        }

        return properties;
    }

    private sealed class TestLogger : ILogger
    {
        private readonly HashSet<LogEntryKind> activeKinds =
            Enum.GetValues<LogEntryKind>().ToHashSet();
        private readonly LogProfile logProfile;
        private readonly bool throwOnLogProfileGet;

        internal TestLogger(bool throwOnLogProfileGet = false)
        {
            this.throwOnLogProfileGet = throwOnLogProfileGet;
            logProfile = new LogProfile();
            logProfile.ProfilesMap.Add(
                ActiveLoggingProfile,
                new Dictionary<string, List<LogEntryKind>>(
                    StringComparer.Ordinal));
        }

        public ITestSite Site => null!;

        public string ActiveLoggingProfile { get; set; } = "Default";

        public LogProfile LogProfile
        {
            get
            {
                LogProfileAccessCount++;
                if (throwOnLogProfileGet)
                {
                    throw new InvalidOperationException(
                        "Log profile registration failed.");
                }

                return logProfile;
            }
        }

        internal int LogProfileAccessCount { get; private set; }

        internal int SinkCount => logProfile.AllSinks.Count;

        public void Add(LogEntryKind kind, string format, params object[] args)
        {
        }

        public void AddTestStatistic()
        {
        }

        public void Dispose()
        {
        }

        public bool IsActive(LogEntryKind kind)
        {
            return activeKinds.Contains(kind);
        }
    }
}
