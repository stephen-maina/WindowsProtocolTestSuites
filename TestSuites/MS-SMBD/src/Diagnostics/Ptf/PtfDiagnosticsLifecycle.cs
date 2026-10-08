// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using Microsoft.Protocols.TestTools;
using Microsoft.Protocols.TestTools.Logging;
using Microsoft.Protocols.TestSuites.Diagnostics.Configuration;
using Microsoft.Protocols.TestSuites.Diagnostics.Identity;
using Microsoft.Protocols.TestSuites.Diagnostics.Lifecycle;
using Microsoft.Protocols.TestSuites.Diagnostics.Providers;
using Microsoft.Protocols.TestSuites.Diagnostics.Runner;
using Microsoft.Protocols.TestSuites.Diagnostics.Storage;
using Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Configuration;
using Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Runner;
using Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Storage;

namespace Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Ptf;

public static class PtfDiagnosticsLifecycle
{
    private const string CurrentTestCaseName = "CurrentTestCaseName";
    private const string DriverPlatformPropertyName = "DriverPlatform";
    private const string UnknownInvocation = "MS-SMBD.UnknownInvocation";
    private const string RdmaSnifferEnabledProperty = "Diagnostics.Capture.RdmaSniffer.Enabled";
    private const string RdmaSnifferToolPathProperty = "Diagnostics.Capture.RdmaSniffer.ToolPath";

    private static readonly DiagnosticsConfigurationPolicy ConfigurationPolicy =
        new(new[] { NetshTraceCaptureProvider.ProviderIdentifier });

    private static readonly string[] SensitivePropertyNameFragments =
    {
        "credential",
        "key",
        "password",
        "secret",
        "token",
    };

    public static DiagnosticsInvocationLifecycle Start(
        NameValueCollection effectiveProperties,
        IReadOnlyDictionary<string, object> testProperties,
        ILogger logger,
        string buildOutputRoot,
        Func<RunnerTestExecutionIdentity>? runnerIdentityFactory = null,
        Func<DiagnosticsCaptureConfiguration, ICaptureProvider>?
            captureProviderFactory = null,
        Func<DiagnosticsRuntimePlatform>? runtimePlatformProbe = null)
    {
        ArgumentNullException.ThrowIfNull(effectiveProperties);
        ArgumentNullException.ThrowIfNull(testProperties);
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentException.ThrowIfNullOrWhiteSpace(buildOutputRoot);

        var source = new PtfEffectiveConfigurationSource(effectiveProperties);
        return DiagnosticsInvocationLifecycle.Start(
            source,
            () => ReadInvocationName(testProperties),
            () => ReadInvocationName(testProperties),
            displayName => runnerIdentityFactory is null
                ? InvocationIdentity.Create(
                    runId: "ptf",
                    testIdentity: displayName,
                    attemptIdentity: "initial",
                    dataRowIdentity: string.Empty)
                : runnerIdentityFactory().CreateInvocationIdentity(
                    SmbdRunnerContext.ReadRunId()),
            (configuration, identity) =>
            {
                string normalizedBuildOutputRoot =
                    Path.GetFullPath(buildOutputRoot);
                string sourceRoot =
                    ArtifactStorageBoundaries.FindSourceRoot(
                        normalizedBuildOutputRoot);
                string artifactRoot = configuration.ArtifactRoot!.Value;
                if (RunnerRunContext.IsRunnerManaged(identity.RunId))
                {
                    artifactRoot = ArtifactPath.CombineUnderRoot(
                        artifactRoot,
                        identity.RunId,
                        "tests");
                }
                else
                {
                    // Validate the configured root before creating session folders in it.
                    using (ArtifactStore.Open(
                        artifactRoot,
                        sourceRoot,
                        normalizedBuildOutputRoot))
                    {
                    }

                    artifactRoot = PtfSessionLayout.PrepareTestsRoot(
                        artifactRoot,
                        effectiveProperties,
                        DateTimeOffset.Now);
                }

                using ArtifactStore artifactStore = ArtifactStore.Open(
                    artifactRoot,
                    sourceRoot,
                    normalizedBuildOutputRoot);
                ArtifactInvocation invocation =
                    artifactStore.CreateInvocation(identity);
                PtfInvocationLogBridge bridge =
                    PtfInvocationLogBridge.GetOrCreate(logger);
                DiagnosticsCaptureConfiguration capture =
                    configuration.Capture!;
                DiagnosticsRuntimePlatform runtimePlatform =
                    (runtimePlatformProbe ??
                        DiagnosticsRuntimePlatformDetector.Detect)();
                ICaptureProvider provider = SelectCaptureProvider(
                    effectiveProperties[DriverPlatformPropertyName],
                    effectiveProperties,
                    runtimePlatform,
                    capture,
                    captureProviderFactory);

                return new DiagnosticsInvocationRuntime(
                    identity,
                    invocation,
                    bridge.Router,
                    provider,
                    ReadSensitiveValues(effectiveProperties));
            },
            SmbdDiagnosticsConfigurationProperties.PropertyMap,
            ConfigurationPolicy);
    }

    private static ICaptureProvider SelectCaptureProvider(
        string? configuredDriverPlatform,
        NameValueCollection effectiveProperties,
        DiagnosticsRuntimePlatform runtimePlatform,
        DiagnosticsCaptureConfiguration capture,
        Func<DiagnosticsCaptureConfiguration, ICaptureProvider>?
            captureProviderFactory)
    {
        DriverPlatformKind configuredPlatform =
            ReadDriverPlatform(configuredDriverPlatform);
        if (configuredPlatform == DriverPlatformKind.Invalid)
        {
            string reason = string.IsNullOrWhiteSpace(configuredDriverPlatform)
                ? "DriverPlatform is required for diagnostics provider selection."
                : $"DriverPlatform '{configuredDriverPlatform}' is not recognized for diagnostics provider selection.";
            return new UnsupportedCaptureProvider(reason);
        }

        if (runtimePlatform == DiagnosticsRuntimePlatform.Unsupported)
        {
            return new UnsupportedCaptureProvider(
                "Diagnostics capture is not supported on the current test-driver operating system.");
        }

        bool runtimeMatchesConfiguration =
            configuredPlatform == DriverPlatformKind.Windows &&
                runtimePlatform == DiagnosticsRuntimePlatform.Windows ||
            configuredPlatform == DriverPlatformKind.Linux &&
                runtimePlatform == DiagnosticsRuntimePlatform.Linux;
        if (!runtimeMatchesConfiguration)
        {
            return new UnsupportedCaptureProvider(
                $"Configured DriverPlatform '{configuredDriverPlatform}' does not match the {runtimePlatform} process runtime.");
        }

        if (runtimePlatform == DiagnosticsRuntimePlatform.Linux)
        {
            string reason = string.Equals(
                    capture.Provider.Value,
                    NetshTraceCaptureProvider.ProviderIdentifier,
                    StringComparison.Ordinal)
                ? "NetshTrace is not supported on Linux test drivers."
                : "Linux capture provider is not available in this build.";
            return new UnsupportedCaptureProvider(reason);
        }

        return captureProviderFactory is null
            ? CreateCaptureProvider(capture, effectiveProperties)
            : captureProviderFactory(capture);
    }

    private static DriverPlatformKind ReadDriverPlatform(
        string? configuredDriverPlatform)
    {
        return configuredDriverPlatform?.Trim() switch
        {
            "WindowsServer2012" or
            "WindowsServer2012R2" or
            "WindowsServer2016" or
            "WindowsServerV1709" or
            "WindowsServerV1803" or
            "WindowsServer2019" or
            "WindowsServerV1903" or
            "WindowsServerV1909" or
            "WindowsServerV2004" or
            "WindowsServerV20H2" or
            "Windows10V21H1" or
            "WindowsServer2022" or
            "WindowsServerV22H2" or
            "WindowsServer2025" or
            "Windows11" or
            "Windows11V21H2" or
            "Windows11V22H2" or
            "Windows11V23H2" or
            "Windows11V24H2" => DriverPlatformKind.Windows,
            "NonWindows" => DriverPlatformKind.Linux,
            _ => DriverPlatformKind.Invalid,
        };
    }

    private static ICaptureProvider CreateCaptureProvider(
        DiagnosticsCaptureConfiguration capture,
        NameValueCollection effectiveProperties)
    {
        if (string.Equals(
                capture.Provider.Value,
                DiagnosticsConfigurationPolicy.AutomaticProvider,
                StringComparison.Ordinal) ||
            string.Equals(
                capture.Provider.Value,
                NetshTraceCaptureProvider.ProviderIdentifier,
                StringComparison.Ordinal))
        {
            var netsh = new NetshTraceCaptureProvider(
                capture.ToolPath.Value ??
                    NetshTraceCaptureProvider.DefaultExecutablePath,
                capture.StartTimeout.Value,
                capture.StopTimeout.Value);
            if (!bool.TryParse(
                    effectiveProperties[RdmaSnifferEnabledProperty],
                    out bool snifferEnabled) ||
                !snifferEnabled)
            {
                return netsh;
            }

            string? snifferPath = effectiveProperties[RdmaSnifferToolPathProperty];
            return new AuxiliaryCaptureProvider(
                netsh,
                new Mlx5SnifferCaptureProvider(
                    string.IsNullOrWhiteSpace(snifferPath)
                        ? Mlx5SnifferCaptureProvider.DefaultExecutablePath
                        : snifferPath.Trim(),
                    capture.StartTimeout.Value));
        }

        return new UnsupportedCaptureProvider();
    }

    private static string ReadInvocationName(
        IReadOnlyDictionary<string, object> testProperties)
    {
        if (testProperties.TryGetValue(
                CurrentTestCaseName,
                out object? value) &&
            value is string testCaseName &&
            !string.IsNullOrWhiteSpace(testCaseName))
        {
            return testCaseName;
        }

        return UnknownInvocation;
    }

    private static IReadOnlyList<string> ReadSensitiveValues(
        NameValueCollection effectiveProperties)
    {
        return effectiveProperties.AllKeys
            .Where(key => key is not null && IsSensitivePropertyName(key))
            .Select(key => effectiveProperties[key!])
            .Where(value => !string.IsNullOrEmpty(value))
            .Select(value => value!)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
    }

    private static bool IsSensitivePropertyName(string propertyName)
    {
        return SensitivePropertyNameFragments.Any(
            fragment => propertyName.Contains(
                fragment,
                StringComparison.OrdinalIgnoreCase));
    }

    private enum DriverPlatformKind
    {
        Invalid,
        Windows,
        Linux,
    }
}
