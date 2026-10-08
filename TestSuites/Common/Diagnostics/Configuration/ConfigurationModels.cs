// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;

namespace Microsoft.Protocols.TestSuites.Diagnostics.Configuration;

public enum ConfigurationProvenance
{
    Configured,
    Observed,
    Inferred,
}

public enum DiagnosticsConfigurationState
{
    Disabled,
    Invalid,
    Enabled,
}

public enum CaptureTrafficScope
{
    RdmaFocused,
    Broader,
}

public enum CaptureFileFormat
{
    Native,
}

public enum DiagnosticsRetentionPolicy
{
    KeepAll,
}

public sealed class ProvenancedValue<T>
{
    public ProvenancedValue(T value, ConfigurationProvenance provenance)
    {
        Value = value;
        Provenance = provenance;
    }

    public T Value { get; }

    public ConfigurationProvenance Provenance { get; }
}

internal sealed class CaptureTargetSelector
{
    internal CaptureTargetSelector(
        string exactToken,
        string? canonicalAddress,
        ConfigurationProvenance provenance)
    {
        ExactToken = exactToken;
        CanonicalAddress = canonicalAddress;
        EffectiveValue = new ProvenancedValue<string>(
            canonicalAddress ?? exactToken,
            provenance);
    }

    internal string ExactToken { get; }

    internal string? CanonicalAddress { get; }

    internal ProvenancedValue<string> EffectiveValue { get; }
}

public sealed class DiagnosticsCaptureConfiguration
{
    private readonly ReadOnlyCollection<CaptureTargetSelector> targetSelectors;

    internal DiagnosticsCaptureConfiguration(
        ProvenancedValue<string> provider,
        ProvenancedValue<string?> toolPath,
        IReadOnlyList<CaptureTargetSelector> targets,
        ProvenancedValue<CaptureTrafficScope> trafficScope,
        ProvenancedValue<TimeSpan> startTimeout,
        ProvenancedValue<TimeSpan> stopTimeout,
        ProvenancedValue<TimeSpan> maxDuration,
        ProvenancedValue<long> maxBytes,
        ProvenancedValue<CaptureFileFormat> format)
    {
        Provider = provider;
        ToolPath = toolPath;
        targetSelectors = new ReadOnlyCollection<CaptureTargetSelector>(
            new List<CaptureTargetSelector>(targets));
        Targets = new ReadOnlyCollection<ProvenancedValue<string>>(
            new List<ProvenancedValue<string>>(
                targetSelectors.Select(target => target.EffectiveValue)));
        TrafficScope = trafficScope;
        StartTimeout = startTimeout;
        StopTimeout = stopTimeout;
        MaxDuration = maxDuration;
        MaxBytes = maxBytes;
        Format = format;
    }

    public ProvenancedValue<string> Provider { get; }

    public ProvenancedValue<string?> ToolPath { get; }

    public IReadOnlyList<ProvenancedValue<string>> Targets { get; }

    internal IReadOnlyList<CaptureTargetSelector> TargetSelectors =>
        targetSelectors;

    public ProvenancedValue<CaptureTrafficScope> TrafficScope { get; }

    public ProvenancedValue<TimeSpan> StartTimeout { get; }

    public ProvenancedValue<TimeSpan> StopTimeout { get; }

    public ProvenancedValue<TimeSpan> MaxDuration { get; }

    public ProvenancedValue<long> MaxBytes { get; }

    public ProvenancedValue<CaptureFileFormat> Format { get; }
}

public sealed class DiagnosticsConfiguration
{
    private DiagnosticsConfiguration(
        DiagnosticsConfigurationState state,
        ProvenancedValue<bool> enabledSetting,
        ProvenancedValue<string>? artifactRoot,
        DiagnosticsCaptureConfiguration? capture,
        ProvenancedValue<bool>? nativeLogsEnabled,
        ProvenancedValue<DiagnosticsRetentionPolicy>? retention)
    {
        State = state;
        EnabledSetting = enabledSetting;
        ArtifactRoot = artifactRoot;
        Capture = capture;
        NativeLogsEnabled = nativeLogsEnabled;
        Retention = retention;
    }

    public DiagnosticsConfigurationState State { get; }

    public bool Enabled => EnabledSetting.Value;

    public ProvenancedValue<bool> EnabledSetting { get; }

    public ProvenancedValue<string>? ArtifactRoot { get; }

    public DiagnosticsCaptureConfiguration? Capture { get; }

    public ProvenancedValue<bool>? NativeLogsEnabled { get; }

    public ProvenancedValue<DiagnosticsRetentionPolicy>? Retention { get; }

    internal static DiagnosticsConfiguration Disabled(
        ConfigurationProvenance provenance)
    {
        return new DiagnosticsConfiguration(
            DiagnosticsConfigurationState.Disabled,
            new ProvenancedValue<bool>(false, provenance),
            artifactRoot: null,
            capture: null,
            nativeLogsEnabled: null,
            retention: null);
    }

    internal static DiagnosticsConfiguration Invalid(
        ProvenancedValue<bool> enabledSetting)
    {
        return new DiagnosticsConfiguration(
            DiagnosticsConfigurationState.Invalid,
            enabledSetting,
            artifactRoot: null,
            capture: null,
            nativeLogsEnabled: null,
            retention: null);
    }

    internal static DiagnosticsConfiguration CreateEnabled(
        ProvenancedValue<string> artifactRoot,
        DiagnosticsCaptureConfiguration capture,
        ProvenancedValue<bool> nativeLogsEnabled,
        ProvenancedValue<DiagnosticsRetentionPolicy> retention)
    {
        return new DiagnosticsConfiguration(
            DiagnosticsConfigurationState.Enabled,
            new ProvenancedValue<bool>(
                true,
                ConfigurationProvenance.Configured),
            artifactRoot,
            capture,
            nativeLogsEnabled,
            retention);
    }
}

public static class DiagnosticsConfigurationPropertyNames
{
    public const string Enabled = "Diagnostics.Enabled";
    public const string ArtifactRoot = "Diagnostics.ArtifactRoot";
    public const string Provider = "Diagnostics.Capture.Provider";
    public const string ToolPath = "Diagnostics.Capture.ToolPath";
    public const string Targets = "Diagnostics.Capture.Targets";
    public const string TrafficScope = "Diagnostics.Capture.TrafficScope";
    public const string StartTimeout = "Diagnostics.Capture.StartTimeout";
    public const string StopTimeout = "Diagnostics.Capture.StopTimeout";
    public const string MaxDuration = "Diagnostics.Capture.MaxDuration";
    public const string MaxBytes = "Diagnostics.Capture.MaxBytes";
    public const string Format = "Diagnostics.Capture.Format";
    public const string NativeLogsEnabled = "Diagnostics.Logs.NativeEnabled";
    public const string Retention = "Diagnostics.Retention";
}

public sealed class DiagnosticsConfigurationPropertyMap
{
    public DiagnosticsConfigurationPropertyMap(
        string enabled,
        string artifactRoot,
        string provider,
        string toolPath,
        string targets,
        string trafficScope,
        string startTimeout,
        string stopTimeout,
        string maxDuration,
        string maxBytes,
        string format,
        string nativeLogsEnabled,
        string retention,
        string? targetFallback = null)
    {
        Enabled = RequirePropertyName(enabled, nameof(enabled));
        ArtifactRoot = RequirePropertyName(artifactRoot, nameof(artifactRoot));
        Provider = RequirePropertyName(provider, nameof(provider));
        ToolPath = RequirePropertyName(toolPath, nameof(toolPath));
        Targets = RequirePropertyName(targets, nameof(targets));
        TrafficScope = RequirePropertyName(trafficScope, nameof(trafficScope));
        StartTimeout = RequirePropertyName(startTimeout, nameof(startTimeout));
        StopTimeout = RequirePropertyName(stopTimeout, nameof(stopTimeout));
        MaxDuration = RequirePropertyName(maxDuration, nameof(maxDuration));
        MaxBytes = RequirePropertyName(maxBytes, nameof(maxBytes));
        Format = RequirePropertyName(format, nameof(format));
        NativeLogsEnabled = RequirePropertyName(
            nativeLogsEnabled,
            nameof(nativeLogsEnabled));
        Retention = RequirePropertyName(retention, nameof(retention));
        TargetFallback = string.IsNullOrWhiteSpace(targetFallback)
            ? null
            : targetFallback;
    }

    public static DiagnosticsConfigurationPropertyMap Canonical { get; } =
        new(
            DiagnosticsConfigurationPropertyNames.Enabled,
            DiagnosticsConfigurationPropertyNames.ArtifactRoot,
            DiagnosticsConfigurationPropertyNames.Provider,
            DiagnosticsConfigurationPropertyNames.ToolPath,
            DiagnosticsConfigurationPropertyNames.Targets,
            DiagnosticsConfigurationPropertyNames.TrafficScope,
            DiagnosticsConfigurationPropertyNames.StartTimeout,
            DiagnosticsConfigurationPropertyNames.StopTimeout,
            DiagnosticsConfigurationPropertyNames.MaxDuration,
            DiagnosticsConfigurationPropertyNames.MaxBytes,
            DiagnosticsConfigurationPropertyNames.Format,
            DiagnosticsConfigurationPropertyNames.NativeLogsEnabled,
            DiagnosticsConfigurationPropertyNames.Retention);

    public string Enabled { get; }

    public string ArtifactRoot { get; }

    public string Provider { get; }

    public string ToolPath { get; }

    public string Targets { get; }

    public string TrafficScope { get; }

    public string StartTimeout { get; }

    public string StopTimeout { get; }

    public string MaxDuration { get; }

    public string MaxBytes { get; }

    public string Format { get; }

    public string NativeLogsEnabled { get; }

    public string Retention { get; }

    public string? TargetFallback { get; }

    private static string RequirePropertyName(
        string propertyName,
        string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            propertyName,
            parameterName);
        return propertyName;
    }
}

public static class DiagnosticsConfigurationErrorCodes
{
    public const string MissingValue = "ConfigurationValueMissing";
    public const string InvalidValue = "ConfigurationValueInvalid";
    public const string UnsupportedValue = "ConfigurationValueUnsupported";
    public const string ProviderUnsupported = "ProviderUnsupported";
    public const string TargetNotFound = "TargetNotFound";
    public const string TargetAmbiguous = "TargetAmbiguous";
    public const string TargetDisconnected = "TargetDisconnected";
    public const string DuplicateTargetIdentity = "DuplicateTargetIdentity";
    public const string AdapterInventoryUnavailable = "AdapterInventoryUnavailable";
}

public interface IEffectiveConfigurationSource
{
    string? GetValue(string propertyName);
}

public sealed class DiagnosticsConfigurationPolicy
{
    public const string AutomaticProvider = "Automatic";

    private readonly IReadOnlyDictionary<string, string> providers;

    public DiagnosticsConfigurationPolicy(
        IEnumerable<string>? supportedProviderIdentifiers = null)
    {
        var canonicalProviders = new Dictionary<string, string>(
            StringComparer.OrdinalIgnoreCase)
        {
            [AutomaticProvider] = AutomaticProvider,
        };

        if (supportedProviderIdentifiers is not null)
        {
            foreach (string identifier in supportedProviderIdentifiers)
            {
                if (string.IsNullOrWhiteSpace(identifier))
                {
                    throw new ArgumentException(
                        "Supported provider identifiers must be non-empty.",
                        nameof(supportedProviderIdentifiers));
                }

                string canonical = identifier.Trim();
                if (!canonicalProviders.TryAdd(canonical, canonical))
                {
                    throw new ArgumentException(
                        "Supported provider identifiers must be unique.",
                        nameof(supportedProviderIdentifiers));
                }
            }
        }

        providers = new ReadOnlyDictionary<string, string>(canonicalProviders);
    }

    public static DiagnosticsConfigurationPolicy Default { get; } = new();

    internal bool TryGetProvider(
        string identifier,
        out string canonicalIdentifier)
    {
        return providers.TryGetValue(identifier, out canonicalIdentifier!);
    }
}
