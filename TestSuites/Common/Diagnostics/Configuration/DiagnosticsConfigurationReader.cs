// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.Linq;
using Microsoft.Protocols.TestSuites.Diagnostics.Errors;
using Microsoft.Protocols.TestSuites.Diagnostics.Providers;
using Microsoft.Protocols.TestSuites.Diagnostics.Storage;

namespace Microsoft.Protocols.TestSuites.Diagnostics.Configuration;

public static class DiagnosticsConfigurationReader
{
    private const int MaximumLocalPathLength = 32766;

    public static DiagnosticsConfiguration Read(
        IEffectiveConfigurationSource source,
        DiagnosticErrorLedger errors,
        DateTimeOffset occurredAt,
        DiagnosticsConfigurationPolicy? policy = null)
    {
        return Read(
            source,
            errors,
            occurredAt,
            DiagnosticsConfigurationPropertyMap.Canonical,
            policy,
            DiagnosticsRuntimePlatformDetector.Detect());
    }

    public static DiagnosticsConfiguration Read(
        IEffectiveConfigurationSource source,
        DiagnosticErrorLedger errors,
        DateTimeOffset occurredAt,
        DiagnosticsConfigurationPropertyMap propertyMap,
        DiagnosticsConfigurationPolicy? policy = null)
    {
        return Read(
            source,
            errors,
            occurredAt,
            propertyMap,
            policy,
            DiagnosticsRuntimePlatformDetector.Detect());
    }

    public static DiagnosticsConfiguration Read(
        IEffectiveConfigurationSource source,
        DiagnosticErrorLedger errors,
        DateTimeOffset occurredAt,
        DiagnosticsConfigurationPropertyMap propertyMap,
        DiagnosticsConfigurationPolicy? policy,
        DiagnosticsRuntimePlatform runtimePlatform)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(errors);
        ArgumentNullException.ThrowIfNull(propertyMap);
        policy ??= DiagnosticsConfigurationPolicy.Default;
        var configurationErrors = new ConfigurationReadErrors(errors);

        ClassifiedRawValue rawEnabled = ReadRawValue(
            source,
            propertyMap.Enabled);
        if (rawEnabled.IsAbsentOrEmpty)
        {
            return DiagnosticsConfiguration.Disabled(
                ConfigurationProvenance.Inferred);
        }

        if (rawEnabled.IsMalformed ||
            !bool.TryParse(rawEnabled.TrimmedValue, out bool enabled))
        {
            Record(
                configurationErrors,
                DiagnosticsConfigurationErrorCodes.InvalidValue,
                propertyMap.Enabled,
                occurredAt);
            return DiagnosticsConfiguration.Invalid(
                new ProvenancedValue<bool>(
                    false,
                    ConfigurationProvenance.Inferred));
        }

        if (!enabled)
        {
            return DiagnosticsConfiguration.Disabled(
                ConfigurationProvenance.Configured);
        }

        return ReadEnabled(
            source,
            configurationErrors,
            occurredAt,
            propertyMap,
            policy,
            runtimePlatform);
    }

    private static DiagnosticsConfiguration ReadEnabled(
        IEffectiveConfigurationSource source,
        ConfigurationReadErrors errors,
        DateTimeOffset occurredAt,
        DiagnosticsConfigurationPropertyMap propertyMap,
        DiagnosticsConfigurationPolicy policy,
        DiagnosticsRuntimePlatform runtimePlatform)
    {
        ProvenancedValue<string>? artifactRoot =
            ReadArtifactRoot(
                source,
                propertyMap,
                errors,
                occurredAt,
                runtimePlatform);
        ProvenancedValue<string> provider =
            ReadProvider(source, propertyMap, policy, errors, occurredAt);
        ProvenancedValue<string?>? toolPath =
            ReadToolPath(
                source,
                propertyMap,
                errors,
                occurredAt,
                runtimePlatform);
        IReadOnlyList<CaptureTargetSelector> targets =
            ReadTargets(source, propertyMap, errors, occurredAt);
        ProvenancedValue<CaptureTrafficScope> trafficScope =
            ReadTrafficScope(source, propertyMap, errors, occurredAt);
        ProvenancedValue<TimeSpan>? startTimeout =
            ReadRequiredDuration(
                source,
                propertyMap.StartTimeout,
                errors,
                occurredAt);
        ProvenancedValue<TimeSpan>? stopTimeout =
            ReadRequiredDuration(
                source,
                propertyMap.StopTimeout,
                errors,
                occurredAt);
        ProvenancedValue<TimeSpan>? maxDuration =
            ReadRequiredDuration(
                source,
                propertyMap.MaxDuration,
                errors,
                occurredAt);
        ProvenancedValue<long>? maxBytes =
            ReadRequiredPositiveInteger(
                source,
                propertyMap.MaxBytes,
                errors,
                occurredAt);
        ProvenancedValue<CaptureFileFormat> format =
            ReadFormat(source, propertyMap, errors, occurredAt);
        ProvenancedValue<bool> nativeLogs =
            ReadNativeLogsEnabled(source, propertyMap, errors, occurredAt);
        ProvenancedValue<DiagnosticsRetentionPolicy> retention =
            ReadRetention(source, propertyMap, errors, occurredAt);

        if (errors.HasErrors ||
            artifactRoot is null ||
            toolPath is null ||
            targets.Count == 0 ||
            startTimeout is null ||
            stopTimeout is null ||
            maxDuration is null ||
            maxBytes is null)
        {
            return DiagnosticsConfiguration.Invalid(
                new ProvenancedValue<bool>(
                    true,
                    ConfigurationProvenance.Configured));
        }

        var capture = new DiagnosticsCaptureConfiguration(
            provider,
            toolPath,
            targets,
            trafficScope,
            startTimeout,
            stopTimeout,
            maxDuration,
            maxBytes,
            format);
        return DiagnosticsConfiguration.CreateEnabled(
            artifactRoot,
            capture,
            nativeLogs,
            retention);
    }

    private static ProvenancedValue<string>? ReadArtifactRoot(
        IEffectiveConfigurationSource source,
        DiagnosticsConfigurationPropertyMap propertyMap,
        ConfigurationReadErrors errors,
        DateTimeOffset occurredAt,
        DiagnosticsRuntimePlatform runtimePlatform)
    {
        string property = propertyMap.ArtifactRoot;
        ClassifiedRawValue raw = ReadRawValue(source, property);
        if (raw.IsAbsentOrEmpty)
        {
            RecordMissing(errors, property, occurredAt);
            return null;
        }

        if (raw.IsMalformed ||
            !TryNormalizeConcreteLocalPath(
                raw.Value!,
                allowDriveRoot: true,
                allowTrailingSeparator: true,
                runtimePlatform,
                out string? value))
        {
            RecordInvalid(errors, property, occurredAt);
            return null;
        }

        return new ProvenancedValue<string>(
            value,
            ConfigurationProvenance.Configured);
    }

    private static ProvenancedValue<string> ReadProvider(
        IEffectiveConfigurationSource source,
        DiagnosticsConfigurationPropertyMap propertyMap,
        DiagnosticsConfigurationPolicy policy,
        ConfigurationReadErrors errors,
        DateTimeOffset occurredAt)
    {
        string property = propertyMap.Provider;
        ClassifiedRawValue raw = ReadRawValue(source, property);
        if (raw.IsAbsentOrEmpty)
        {
            return new ProvenancedValue<string>(
                DiagnosticsConfigurationPolicy.AutomaticProvider,
                ConfigurationProvenance.Inferred);
        }

        if (raw.IsMalformed)
        {
            RecordInvalid(errors, property, occurredAt);
            return new ProvenancedValue<string>(
                DiagnosticsConfigurationPolicy.AutomaticProvider,
                ConfigurationProvenance.Configured);
        }

        string value = raw.TrimmedValue;
        if (!policy.TryGetProvider(value, out string canonical))
        {
            Record(
                errors,
                DiagnosticsConfigurationErrorCodes.ProviderUnsupported,
                property,
                occurredAt);
            return new ProvenancedValue<string>(
                DiagnosticsConfigurationPolicy.AutomaticProvider,
                ConfigurationProvenance.Configured);
        }

        return new ProvenancedValue<string>(
            canonical,
            ConfigurationProvenance.Configured);
    }

    private static ProvenancedValue<string?>? ReadToolPath(
        IEffectiveConfigurationSource source,
        DiagnosticsConfigurationPropertyMap propertyMap,
        ConfigurationReadErrors errors,
        DateTimeOffset occurredAt,
        DiagnosticsRuntimePlatform runtimePlatform)
    {
        string property = propertyMap.ToolPath;
        ClassifiedRawValue raw = ReadRawValue(source, property);
        if (raw.IsAbsentOrEmpty)
        {
            return new ProvenancedValue<string?>(
                value: null,
                ConfigurationProvenance.Inferred);
        }

        if (raw.IsMalformed ||
            !TryNormalizeConcreteLocalPath(
                raw.Value!,
                allowDriveRoot: false,
                allowTrailingSeparator: false,
                runtimePlatform,
                out string? value) ||
            (runtimePlatform == DiagnosticsRuntimePlatform.Windows &&
             !string.Equals(
                 Path.GetExtension(value),
                 ".exe",
                 StringComparison.OrdinalIgnoreCase)))
        {
            RecordInvalid(errors, property, occurredAt);
            return null;
        }

        return new ProvenancedValue<string?>(
            value,
            ConfigurationProvenance.Configured);
    }

    private static IReadOnlyList<CaptureTargetSelector> ReadTargets(
        IEffectiveConfigurationSource source,
        DiagnosticsConfigurationPropertyMap propertyMap,
        ConfigurationReadErrors errors,
        DateTimeOffset occurredAt)
    {
        string property = propertyMap.Targets;
        ClassifiedRawValue raw = ReadRawValue(source, property);
        if (!raw.IsAbsentOrEmpty)
        {
            if (raw.IsMalformed)
            {
                RecordInvalid(errors, property, occurredAt);
                return Array.Empty<CaptureTargetSelector>();
            }

            string[] fragments = raw.Value!.Split(';');
            var targets = new List<CaptureTargetSelector>(fragments.Length);
            foreach (string fragment in fragments)
            {
                if (!CaptureTargetResolver.TryCreateSelector(
                        fragment,
                        ConfigurationProvenance.Configured,
                        out CaptureTargetSelector target))
                {
                    RecordInvalid(errors, property, occurredAt);
                    return Array.Empty<CaptureTargetSelector>();
                }

                targets.Add(target);
            }

            if (targets.Count == 0 ||
                targets
                    .Select(target => target.EffectiveValue.Value)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Count() !=
                targets.Count)
            {
                RecordInvalid(errors, property, occurredAt);
                return Array.Empty<CaptureTargetSelector>();
            }

            return targets;
        }

        string fallbackProperty =
            propertyMap.TargetFallback ?? propertyMap.Targets;
        if (propertyMap.TargetFallback is null)
        {
            RecordMissing(errors, fallbackProperty, occurredAt);
            return Array.Empty<CaptureTargetSelector>();
        }

        ClassifiedRawValue clientRNicIp =
            ReadRawValue(source, fallbackProperty);
        if (clientRNicIp.IsAbsentOrEmpty)
        {
            RecordMissing(errors, fallbackProperty, occurredAt);
            return Array.Empty<CaptureTargetSelector>();
        }

        if (clientRNicIp.IsMalformed ||
            !CaptureTargetResolver.TryCreateSelector(
                clientRNicIp.Value!,
                ConfigurationProvenance.Inferred,
                out CaptureTargetSelector fallbackTarget))
        {
            RecordInvalid(errors, fallbackProperty, occurredAt);
            return Array.Empty<CaptureTargetSelector>();
        }

        return new[] { fallbackTarget };
    }

    private static ProvenancedValue<CaptureTrafficScope> ReadTrafficScope(
        IEffectiveConfigurationSource source,
        DiagnosticsConfigurationPropertyMap propertyMap,
        ConfigurationReadErrors errors,
        DateTimeOffset occurredAt)
    {
        string property = propertyMap.TrafficScope;
        ClassifiedRawValue raw = ReadRawValue(source, property);
        if (raw.IsAbsentOrEmpty)
        {
            return new ProvenancedValue<CaptureTrafficScope>(
                CaptureTrafficScope.RdmaFocused,
                ConfigurationProvenance.Inferred);
        }

        if (raw.IsMalformed)
        {
            RecordInvalid(errors, property, occurredAt);
            return new ProvenancedValue<CaptureTrafficScope>(
                CaptureTrafficScope.RdmaFocused,
                ConfigurationProvenance.Configured);
        }

        string value = raw.TrimmedValue;
        if (value.Equals("RdmaFocused", StringComparison.OrdinalIgnoreCase))
        {
            return new ProvenancedValue<CaptureTrafficScope>(
                CaptureTrafficScope.RdmaFocused,
                ConfigurationProvenance.Configured);
        }

        if (value.Equals("Broader", StringComparison.OrdinalIgnoreCase))
        {
            return new ProvenancedValue<CaptureTrafficScope>(
                CaptureTrafficScope.Broader,
                ConfigurationProvenance.Configured);
        }

        RecordUnsupported(errors, property, occurredAt);
        return new ProvenancedValue<CaptureTrafficScope>(
            CaptureTrafficScope.RdmaFocused,
            ConfigurationProvenance.Configured);
    }

    private static ProvenancedValue<TimeSpan>? ReadRequiredDuration(
        IEffectiveConfigurationSource source,
        string propertyName,
        ConfigurationReadErrors errors,
        DateTimeOffset occurredAt)
    {
        ClassifiedRawValue raw = ReadRawValue(source, propertyName);
        if (raw.IsAbsentOrEmpty)
        {
            RecordMissing(errors, propertyName, occurredAt);
            return null;
        }

        if (raw.IsMalformed)
        {
            RecordInvalid(errors, propertyName, occurredAt);
            return null;
        }

        string valueText = raw.TrimmedValue;
        if (!valueText.Contains(':', StringComparison.Ordinal) ||
            !TimeSpan.TryParseExact(
                valueText,
                "c",
                CultureInfo.InvariantCulture,
                TimeSpanStyles.None,
                out TimeSpan value) ||
            value <= TimeSpan.Zero)
        {
            RecordInvalid(errors, propertyName, occurredAt);
            return null;
        }

        return new ProvenancedValue<TimeSpan>(
            value,
            ConfigurationProvenance.Configured);
    }

    private static ProvenancedValue<long>? ReadRequiredPositiveInteger(
        IEffectiveConfigurationSource source,
        string propertyName,
        ConfigurationReadErrors errors,
        DateTimeOffset occurredAt)
    {
        ClassifiedRawValue raw = ReadRawValue(source, propertyName);
        if (raw.IsAbsentOrEmpty)
        {
            RecordMissing(errors, propertyName, occurredAt);
            return null;
        }

        if (raw.IsMalformed ||
            !long.TryParse(
                raw.TrimmedValue,
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out long value) ||
            value <= 0)
        {
            RecordInvalid(errors, propertyName, occurredAt);
            return null;
        }

        return new ProvenancedValue<long>(
            value,
            ConfigurationProvenance.Configured);
    }

    private static ProvenancedValue<CaptureFileFormat> ReadFormat(
        IEffectiveConfigurationSource source,
        DiagnosticsConfigurationPropertyMap propertyMap,
        ConfigurationReadErrors errors,
        DateTimeOffset occurredAt)
    {
        string property = propertyMap.Format;
        ClassifiedRawValue raw = ReadRawValue(source, property);
        if (raw.IsAbsentOrEmpty)
        {
            return new ProvenancedValue<CaptureFileFormat>(
                CaptureFileFormat.Native,
                ConfigurationProvenance.Inferred);
        }

        if (raw.IsMalformed)
        {
            RecordInvalid(errors, property, occurredAt);
            return new ProvenancedValue<CaptureFileFormat>(
                CaptureFileFormat.Native,
                ConfigurationProvenance.Configured);
        }

        if (raw.TrimmedValue.Equals(
                "Native",
                StringComparison.OrdinalIgnoreCase))
        {
            return new ProvenancedValue<CaptureFileFormat>(
                CaptureFileFormat.Native,
                ConfigurationProvenance.Configured);
        }

        RecordUnsupported(errors, property, occurredAt);
        return new ProvenancedValue<CaptureFileFormat>(
            CaptureFileFormat.Native,
            ConfigurationProvenance.Configured);
    }

    private static ProvenancedValue<bool> ReadNativeLogsEnabled(
        IEffectiveConfigurationSource source,
        DiagnosticsConfigurationPropertyMap propertyMap,
        ConfigurationReadErrors errors,
        DateTimeOffset occurredAt)
    {
        string property = propertyMap.NativeLogsEnabled;
        ClassifiedRawValue raw = ReadRawValue(source, property);
        if (raw.IsAbsentOrEmpty)
        {
            return new ProvenancedValue<bool>(
                false,
                ConfigurationProvenance.Inferred);
        }

        if (raw.IsMalformed ||
            !bool.TryParse(raw.TrimmedValue, out bool value))
        {
            RecordInvalid(errors, property, occurredAt);
            return new ProvenancedValue<bool>(
                false,
                ConfigurationProvenance.Configured);
        }

        return new ProvenancedValue<bool>(
            value,
            ConfigurationProvenance.Configured);
    }

    private static ProvenancedValue<DiagnosticsRetentionPolicy> ReadRetention(
        IEffectiveConfigurationSource source,
        DiagnosticsConfigurationPropertyMap propertyMap,
        ConfigurationReadErrors errors,
        DateTimeOffset occurredAt)
    {
        string property = propertyMap.Retention;
        ClassifiedRawValue raw = ReadRawValue(source, property);
        if (raw.IsAbsentOrEmpty)
        {
            return new ProvenancedValue<DiagnosticsRetentionPolicy>(
                DiagnosticsRetentionPolicy.KeepAll,
                ConfigurationProvenance.Inferred);
        }

        if (raw.IsMalformed)
        {
            RecordInvalid(errors, property, occurredAt);
            return new ProvenancedValue<DiagnosticsRetentionPolicy>(
                DiagnosticsRetentionPolicy.KeepAll,
                ConfigurationProvenance.Configured);
        }

        if (raw.TrimmedValue.Equals(
                "KeepAll",
                StringComparison.OrdinalIgnoreCase))
        {
            return new ProvenancedValue<DiagnosticsRetentionPolicy>(
                DiagnosticsRetentionPolicy.KeepAll,
                ConfigurationProvenance.Configured);
        }

        RecordUnsupported(errors, property, occurredAt);
        return new ProvenancedValue<DiagnosticsRetentionPolicy>(
            DiagnosticsRetentionPolicy.KeepAll,
            ConfigurationProvenance.Configured);
    }

    internal static bool TryNormalizeConcreteLocalDrivePath(
        string path,
        bool allowDriveRoot,
        bool allowTrailingSeparator,
        [NotNullWhen(true)] out string? normalizedPath)
    {
        normalizedPath = null;

        if (path.Length == 0 ||
            path.Any(char.IsControl) ||
            !string.Equals(path, path.Trim(), StringComparison.Ordinal))
        {
            return false;
        }

        try
        {
            string separatorNormalized = path.Replace('/', '\\');
            if (separatorNormalized.Length < 3 ||
                !char.IsAsciiLetter(separatorNormalized[0]) ||
                separatorNormalized[1] != ':' ||
                separatorNormalized[2] != '\\')
            {
                return false;
            }

            bool hasTrailingSeparator =
                separatorNormalized.Length > 3 &&
                separatorNormalized.EndsWith(
                    "\\",
                    StringComparison.Ordinal);
            if (hasTrailingSeparator && !allowTrailingSeparator)
            {
                return false;
            }

            string pathForSegmentValidation = hasTrailingSeparator
                ? separatorNormalized[..^1]
                : separatorNormalized;
            if (pathForSegmentValidation.Length > 3 &&
                pathForSegmentValidation.EndsWith(
                    "\\",
                    StringComparison.Ordinal))
            {
                return false;
            }

            if (!AreValidPathSegments(
                    pathForSegmentValidation[3..],
                    allowDotSegments: true))
            {
                return false;
            }

            string fullPath = Path.GetFullPath(separatorNormalized);
            string? root = Path.GetPathRoot(fullPath);
            if (fullPath.Length > MaximumLocalPathLength ||
                root is null ||
                root.Length != 3 ||
                !char.IsAsciiLetter(root[0]) ||
                root[1] != Path.VolumeSeparatorChar ||
                root[2] != Path.DirectorySeparatorChar)
            {
                return false;
            }

            string canonicalPath = string.Equals(
                fullPath,
                root,
                StringComparison.OrdinalIgnoreCase)
                ? fullPath
                : Path.TrimEndingDirectorySeparator(fullPath);
            if (!allowDriveRoot &&
                string.Equals(
                    canonicalPath,
                    root,
                    StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (!AreValidPathSegments(
                    canonicalPath[3..],
                    allowDotSegments: false))
            {
                return false;
            }

            normalizedPath = canonicalPath;
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (NotSupportedException)
        {
            return false;
        }
        catch (PathTooLongException)
        {
            return false;
        }
    }

    internal static bool TryNormalizeConcreteLocalPath(
        string path,
        bool allowDriveRoot,
        bool allowTrailingSeparator,
        DiagnosticsRuntimePlatform runtimePlatform,
        [NotNullWhen(true)] out string? normalizedPath)
    {
        return runtimePlatform switch
        {
            DiagnosticsRuntimePlatform.Windows =>
                TryNormalizeConcreteLocalDrivePath(
                    path,
                    allowDriveRoot,
                    allowTrailingSeparator,
                    out normalizedPath),
            DiagnosticsRuntimePlatform.Linux =>
                TryNormalizeConcreteLinuxPath(
                    path,
                    allowDriveRoot,
                    allowTrailingSeparator,
                    out normalizedPath),
            _ => SetInvalidPath(out normalizedPath),
        };
    }

    private static bool TryNormalizeConcreteLinuxPath(
        string path,
        bool allowRoot,
        bool allowTrailingSeparator,
        [NotNullWhen(true)] out string? normalizedPath)
    {
        normalizedPath = null;
        if (path.Length == 0 ||
            path.Length > MaximumLocalPathLength ||
            path.Any(char.IsControl) ||
            path.Contains('\\', StringComparison.Ordinal) ||
            !string.Equals(path, path.Trim(), StringComparison.Ordinal) ||
            path[0] != '/' ||
            path.StartsWith("//", StringComparison.Ordinal))
        {
            return false;
        }

        bool hasTrailingSeparator =
            path.Length > 1 &&
            path.EndsWith("/", StringComparison.Ordinal);
        if (hasTrailingSeparator && !allowTrailingSeparator)
        {
            return false;
        }

        string pathForSegmentValidation = hasTrailingSeparator
            ? path[..^1]
            : path;
        var canonicalComponents = new List<string>();
        foreach (string component in pathForSegmentValidation[1..].Split('/'))
        {
            if (component.Length == 0)
            {
                if (pathForSegmentValidation.Length == 1)
                {
                    continue;
                }

                return false;
            }

            if (component == ".")
            {
                continue;
            }

            if (component == "..")
            {
                if (canonicalComponents.Count == 0)
                {
                    return false;
                }

                canonicalComponents.RemoveAt(canonicalComponents.Count - 1);
                continue;
            }

            if (!LinuxPathComponent.IsValid(component))
            {
                return false;
            }

            canonicalComponents.Add(component);
        }

        string canonicalPath = canonicalComponents.Count == 0
            ? "/"
            : "/" + string.Join("/", canonicalComponents);
        if (!allowRoot && canonicalPath == "/")
        {
            return false;
        }

        normalizedPath = canonicalPath;
        return true;
    }

    private static bool SetInvalidPath(
        [NotNullWhen(true)] out string? normalizedPath)
    {
        normalizedPath = null;
        return false;
    }

    private static bool AreValidPathSegments(
        string relativePath,
        bool allowDotSegments)
    {
        if (relativePath.Length == 0)
        {
            return true;
        }

        int depth = 0;
        foreach (string component in relativePath.Split('\\'))
        {
            if (component.Length == 0)
            {
                return false;
            }

            if (allowDotSegments && component is "." or "..")
            {
                if (component == "..")
                {
                    if (depth == 0)
                    {
                        return false;
                    }

                    depth--;
                }

                continue;
            }

            if (!WindowsPathComponent.IsValid(component))
            {
                return false;
            }

            depth++;
        }

        return true;
    }

    private static ClassifiedRawValue ReadRawValue(
        IEffectiveConfigurationSource source,
        string propertyName)
    {
        return ClassifiedRawValue.Classify(source.GetValue(propertyName));
    }

    private static void RecordMissing(
        ConfigurationReadErrors errors,
        string propertyName,
        DateTimeOffset occurredAt)
    {
        Record(
            errors,
            DiagnosticsConfigurationErrorCodes.MissingValue,
            propertyName,
            occurredAt);
    }

    private static void RecordInvalid(
        ConfigurationReadErrors errors,
        string propertyName,
        DateTimeOffset occurredAt)
    {
        Record(
            errors,
            DiagnosticsConfigurationErrorCodes.InvalidValue,
            propertyName,
            occurredAt);
    }

    private static void RecordUnsupported(
        ConfigurationReadErrors errors,
        string propertyName,
        DateTimeOffset occurredAt)
    {
        Record(
            errors,
            DiagnosticsConfigurationErrorCodes.UnsupportedValue,
            propertyName,
            occurredAt);
    }

    private static void Record(
        ConfigurationReadErrors errors,
        string code,
        string propertyName,
        DateTimeOffset occurredAt)
    {
        errors.Record(
            DiagnosticErrorCategory.Capture,
            code,
            $"Diagnostics property '{propertyName}' is missing, invalid, or unsupported.",
            occurredAt);
    }

    private sealed class ConfigurationReadErrors
    {
        private readonly DiagnosticErrorLedger ledger;

        internal ConfigurationReadErrors(DiagnosticErrorLedger ledger)
        {
            this.ledger = ledger;
        }

        internal bool HasErrors { get; private set; }

        internal void Record(
            DiagnosticErrorCategory category,
            string code,
            string message,
            DateTimeOffset occurredAt)
        {
            ledger.Record(category, code, message, occurredAt);
            HasErrors = true;
        }
    }

    private enum RawValueKind
    {
        Absent,
        Empty,
        WhitespaceOnly,
        ControlContaining,
        Present,
    }

    private readonly struct ClassifiedRawValue
    {
        private ClassifiedRawValue(string? value, RawValueKind kind)
        {
            Value = value;
            Kind = kind;
        }

        internal string? Value { get; }

        internal RawValueKind Kind { get; }

        internal bool IsAbsentOrEmpty =>
            Kind is RawValueKind.Absent or RawValueKind.Empty;

        internal bool IsMalformed =>
            Kind is RawValueKind.WhitespaceOnly
                or RawValueKind.ControlContaining;

        internal string TrimmedValue => Value!.Trim();

        internal static ClassifiedRawValue Classify(string? value)
        {
            if (value is null)
            {
                return new ClassifiedRawValue(
                    value,
                    RawValueKind.Absent);
            }

            if (value.Length == 0)
            {
                return new ClassifiedRawValue(
                    value,
                    RawValueKind.Empty);
            }

            if (value.Any(char.IsControl))
            {
                return new ClassifiedRawValue(
                    value,
                    RawValueKind.ControlContaining);
            }

            if (value.All(char.IsWhiteSpace))
            {
                return new ClassifiedRawValue(
                    value,
                    RawValueKind.WhitespaceOnly);
            }

            return new ClassifiedRawValue(
                value,
                RawValueKind.Present);
        }
    }
}
