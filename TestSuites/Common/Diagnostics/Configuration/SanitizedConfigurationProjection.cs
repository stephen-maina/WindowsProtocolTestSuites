// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Microsoft.Protocols.TestSuites.Diagnostics.Manifest;

namespace Microsoft.Protocols.TestSuites.Diagnostics.Configuration;

public static class SanitizedConfigurationProjection
{
    public const string ProvenanceSuffix = ".provenance";

    public static IReadOnlyList<ManifestMetadataEntry> Create(
        DiagnosticsConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var metadata = new List<ManifestMetadataEntry>();
        Add(
            metadata,
            DiagnosticsConfigurationPropertyNames.Enabled,
            configuration.EnabledSetting,
            value => value ? "true" : "false",
            MetadataSensitivity.NonSensitive);

        if (configuration.State != DiagnosticsConfigurationState.Enabled ||
            configuration.ArtifactRoot is null ||
            configuration.Capture is null ||
            configuration.NativeLogsEnabled is null ||
            configuration.Retention is null)
        {
            return metadata.AsReadOnly();
        }

        Add(
            metadata,
            DiagnosticsConfigurationPropertyNames.ArtifactRoot,
            configuration.ArtifactRoot,
            value => value,
            MetadataSensitivity.Sensitive);
        Add(
            metadata,
            DiagnosticsConfigurationPropertyNames.Provider,
            configuration.Capture.Provider,
            value => value,
            MetadataSensitivity.NonSensitive);
        if (configuration.Capture.ToolPath.Value is not null)
        {
            Add(
                metadata,
                DiagnosticsConfigurationPropertyNames.ToolPath,
                configuration.Capture.ToolPath,
                value => value ?? string.Empty,
                MetadataSensitivity.Sensitive);
        }

        ProvenancedValue<string> targets = new(
            string.Join(
                ";",
                configuration.Capture.Targets.Select(target => target.Value)),
            configuration.Capture.Targets.All(
                target =>
                    target.Provenance ==
                    configuration.Capture.Targets[0].Provenance)
                ? configuration.Capture.Targets[0].Provenance
                : ConfigurationProvenance.Configured);
        Add(
            metadata,
            DiagnosticsConfigurationPropertyNames.Targets,
            targets,
            value => value,
            MetadataSensitivity.Sensitive);
        Add(
            metadata,
            DiagnosticsConfigurationPropertyNames.TrafficScope,
            configuration.Capture.TrafficScope,
            value => value.ToString(),
            MetadataSensitivity.NonSensitive);
        Add(
            metadata,
            DiagnosticsConfigurationPropertyNames.StartTimeout,
            configuration.Capture.StartTimeout,
            value => value.ToString("c", CultureInfo.InvariantCulture),
            MetadataSensitivity.NonSensitive);
        Add(
            metadata,
            DiagnosticsConfigurationPropertyNames.StopTimeout,
            configuration.Capture.StopTimeout,
            value => value.ToString("c", CultureInfo.InvariantCulture),
            MetadataSensitivity.NonSensitive);
        Add(
            metadata,
            DiagnosticsConfigurationPropertyNames.MaxDuration,
            configuration.Capture.MaxDuration,
            value => value.ToString("c", CultureInfo.InvariantCulture),
            MetadataSensitivity.NonSensitive);
        Add(
            metadata,
            DiagnosticsConfigurationPropertyNames.MaxBytes,
            configuration.Capture.MaxBytes,
            value => value.ToString(CultureInfo.InvariantCulture),
            MetadataSensitivity.NonSensitive);
        Add(
            metadata,
            DiagnosticsConfigurationPropertyNames.Format,
            configuration.Capture.Format,
            value => value.ToString(),
            MetadataSensitivity.NonSensitive);
        Add(
            metadata,
            DiagnosticsConfigurationPropertyNames.NativeLogsEnabled,
            configuration.NativeLogsEnabled,
            value => value ? "true" : "false",
            MetadataSensitivity.NonSensitive);
        Add(
            metadata,
            DiagnosticsConfigurationPropertyNames.Retention,
            configuration.Retention,
            value => value.ToString(),
            MetadataSensitivity.NonSensitive);

        return metadata.AsReadOnly();
    }

    private static void Add<T>(
        ICollection<ManifestMetadataEntry> metadata,
        string key,
        ProvenancedValue<T> value,
        Func<T, string> formatter,
        MetadataSensitivity sensitivity)
    {
        metadata.Add(
            new ManifestMetadataEntry(
                key,
                formatter(value.Value),
                sensitivity));
        metadata.Add(
            new ManifestMetadataEntry(
                key + ProvenanceSuffix,
                value.Provenance.ToString(),
                MetadataSensitivity.NonSensitive));
    }
}
