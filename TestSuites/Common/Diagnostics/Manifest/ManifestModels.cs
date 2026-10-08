// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using Microsoft.Protocols.TestSuites.Diagnostics.Errors;
using Microsoft.Protocols.TestSuites.Diagnostics.Evidence;

namespace Microsoft.Protocols.TestSuites.Diagnostics.Manifest;

public static class ManifestSchema
{
    public const int SupportedMajorVersion = 1;
    public const int SupportedMinorVersion = 0;
    public const string SupportedVersion = "1.0";

    public static void Validate(string schemaVersion)
    {
        if (string.IsNullOrWhiteSpace(schemaVersion))
        {
            throw new ManifestSerializationException(
                "The manifest schemaVersion must be a non-empty major.minor version.");
        }

        string[] components = schemaVersion.Split('.');
        if (components.Length != 2 ||
            !int.TryParse(
                components[0],
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out int major) ||
            !int.TryParse(
                components[1],
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out int minor) ||
            major < 0 ||
            minor < 0)
        {
            throw new ManifestSerializationException(
                $"Manifest schema version '{schemaVersion}' is not a valid major.minor version.");
        }

        if (major != SupportedMajorVersion)
        {
            throw new UnsupportedSchemaVersionException(
                schemaVersion,
                SupportedMajorVersion);
        }
    }
}

public enum ProtocolResultState
{
    Pending,
    Unknown,
    Passed,
    Failed,
    Skipped,
    Inconclusive,
    Aborted,
    TimedOut,
}

public enum CoverageQualification
{
    Qualified,
    Unverified,
    Unsupported,
}

public enum LifecycleStatus
{
    Pending,
    Complete,
    Failed,
    Unavailable,
}

public enum RunnerResultState
{
    Pending,
    Passed,
    Failed,
    Skipped,
    Inconclusive,
    Aborted,
    TimedOut,
    Unknown,
}

public enum CompletionState
{
    Provisional,
    Final,
    Interrupted,
}

public enum ManifestSealState
{
    InProgress,
    Sealed,
}

public enum MetadataSensitivity
{
    NonSensitive,
    Sensitive,
    Secret,
}

public sealed class ManifestMetadataEntry
{
    public const string DefaultRedactionMarker = "[REDACTED]";

    public ManifestMetadataEntry(
        string key,
        string? value,
        MetadataSensitivity sensitivity,
        string redactionMarker = DefaultRedactionMarker)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            throw new ArgumentException(
                "A metadata key is required.",
                nameof(key));
        }

        if (sensitivity == MetadataSensitivity.NonSensitive && value is null)
        {
            throw new ArgumentNullException(
                nameof(value),
                "Non-sensitive metadata requires a value.");
        }

        if (sensitivity != MetadataSensitivity.NonSensitive &&
            !string.Equals(
                redactionMarker,
                DefaultRedactionMarker,
                StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "Sensitive metadata must use the trusted redaction marker.",
                nameof(redactionMarker));
        }

        Key = key;
        Value = value;
        Sensitivity = sensitivity;
        RedactionMarker = redactionMarker;
    }

    public string Key { get; }

    public string? Value { get; }

    public MetadataSensitivity Sensitivity { get; }

    public string RedactionMarker { get; }
}

public sealed class ManifestDocument
{
    public ManifestDocument(string schemaVersion)
    {
        ManifestSchema.Validate(schemaVersion);
        SchemaVersion = schemaVersion;
    }

    public string SchemaVersion { get; }

    public ProtocolResultState ProtocolResult { get; set; } =
        ProtocolResultState.Pending;

    public CollectionEvidence Collection { get; set; } =
        new(
            CollectionStatus.Pending,
            plannedArtifactCount: 0,
            usableArtifactCount: 0,
            noTrafficExpected: false,
            EvidenceReasonCode.None);

    public CoverageQualification CoverageQualification { get; set; } =
        CoverageQualification.Unverified;

    public LifecycleStatus CleanupStatus { get; set; } =
        LifecycleStatus.Pending;

    public LifecycleStatus FinalizationStatus { get; set; } =
        LifecycleStatus.Pending;

    public RunnerResultState RunnerResult { get; set; } =
        RunnerResultState.Pending;

    public CompletionState CompletionState { get; set; } =
        CompletionState.Provisional;

    public List<ManifestMetadataEntry> Metadata { get; } = new();

    public List<ArtifactRecord> Artifacts { get; } = new();

    public List<ArtifactAbsence> ArtifactAbsences { get; } = new();

    public List<string> UnresolvedWriters { get; } = new();

    public DiagnosticErrorLedger Errors { get; } = new();

    public ManifestSealState EvaluateSeal()
    {
        ManifestValidation.ValidateOutcomeStates(this);

        if (Collection is null)
        {
            return ManifestSealState.InProgress;
        }

        CollectionValidationResult collectionValidation =
            CollectionEvidenceValidator.ValidateForFinalization(Collection);
        bool hasUnresolvedCollection =
            !collectionValidation.CanFinalize ||
            !ManifestValidation.CollectionEquals(
                Collection,
                collectionValidation.NormalizedEvidence);
        bool hasActiveOrInvalidArtifact = Artifacts.Any(
            artifact =>
                artifact is null ||
                artifact.FinalizationState != ArtifactFinalizationState.Finalized);
        bool hasUnresolvedWriter = UnresolvedWriters.Count != 0;
        bool hasPendingOutcome =
            ProtocolResult == ProtocolResultState.Pending ||
            CleanupStatus == LifecycleStatus.Pending ||
            RunnerResult == RunnerResultState.Pending ||
            FinalizationStatus == LifecycleStatus.Pending ||
            CompletionState == CompletionState.Provisional;

        return hasUnresolvedCollection ||
               hasActiveOrInvalidArtifact ||
               hasUnresolvedWriter ||
               hasPendingOutcome
            ? ManifestSealState.InProgress
            : ManifestSealState.Sealed;
    }
}

internal static class ManifestValidation
{
    public static bool CollectionEquals(
        CollectionEvidence first,
        CollectionEvidence second)
    {
        return first.Status == second.Status
            && first.PlannedArtifactCount == second.PlannedArtifactCount
            && first.UsableArtifactCount == second.UsableArtifactCount
            && first.NoTrafficExpected == second.NoTrafficExpected
            && first.ReasonCode == second.ReasonCode;
    }

    public static void ValidateUnresolvedWriters(IEnumerable<string> writerIds)
    {
        if (writerIds.Any(string.IsNullOrWhiteSpace))
        {
            throw new ManifestSerializationException(
                "Unresolved writer IDs must be non-empty.");
        }
    }

    public static void ValidateOutcomeStates(ManifestDocument manifest)
    {
        ValidateDefined(manifest.ProtocolResult, "protocolResult");
        ValidateDefined(
            manifest.CoverageQualification,
            "coverageQualification");
        ValidateDefined(manifest.CleanupStatus, "cleanupStatus");
        ValidateDefined(manifest.FinalizationStatus, "finalizationStatus");
        ValidateDefined(manifest.RunnerResult, "runnerResult");
        ValidateDefined(manifest.CompletionState, "completionState");
    }

    private static void ValidateDefined<TEnum>(
        TEnum value,
        string propertyName)
        where TEnum : struct, Enum
    {
        if (!Enum.IsDefined(value))
        {
            throw new ManifestSerializationException(
                $"Manifest property '{propertyName}' has unsupported value '{value}'.");
        }
    }
}

public static class ManifestSealer
{
    public static ManifestDocument Seal(ManifestDocument manifest)
    {
        ArgumentNullException.ThrowIfNull(manifest);

        ManifestValidation.ValidateOutcomeStates(manifest);
        ManifestValidation.ValidateUnresolvedWriters(manifest.UnresolvedWriters);
        string[] unresolvedWriters = manifest.UnresolvedWriters.ToArray();
        if (unresolvedWriters.Length != 0)
        {
            throw new UnresolvedWritersException(unresolvedWriters);
        }

        string[] activeArtifacts = manifest.Artifacts
            .Where(artifact =>
                artifact is null ||
                artifact.FinalizationState != ArtifactFinalizationState.Finalized)
            .Select(artifact => artifact?.RelativePath ?? "<null>")
            .ToArray();
        if (activeArtifacts.Length != 0)
        {
            throw new UnfinalizedArtifactException(activeArtifacts);
        }

        CollectionValidationResult collectionValidation =
            CollectionEvidenceValidator.ValidateForFinalization(
                manifest.Collection);
        if (!collectionValidation.CanFinalize)
        {
            throw new ManifestNotFinalizableException(
                $"Collection status '{manifest.Collection.Status}' is not finalizable.");
        }

        if (manifest.ProtocolResult == ProtocolResultState.Pending ||
            manifest.CleanupStatus == LifecycleStatus.Pending ||
            manifest.RunnerResult == RunnerResultState.Pending)
        {
            throw new ManifestNotFinalizableException(
                "Protocol, cleanup, and runner outcomes must be terminal before sealing.");
        }

        manifest.Collection = collectionValidation.NormalizedEvidence;
        if (manifest.FinalizationStatus == LifecycleStatus.Pending)
        {
            manifest.FinalizationStatus = LifecycleStatus.Complete;
        }

        if (manifest.CompletionState == CompletionState.Provisional)
        {
            manifest.CompletionState =
                manifest.FinalizationStatus == LifecycleStatus.Failed
                    ? CompletionState.Interrupted
                    : CompletionState.Final;
        }

        return manifest;
    }
}

public static class ManifestSerializer
{
    public static string Serialize(ManifestDocument manifest)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ManifestSchema.Validate(manifest.SchemaVersion);
        ValidateInventory(manifest);

        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(
            stream,
            new JsonWriterOptions { Indented = true }))
        {
            writer.WriteStartObject();
            writer.WriteString("schemaVersion", manifest.SchemaVersion);
            writer.WriteString("protocolResult", manifest.ProtocolResult.ToString());
            writer.WriteString("collectionStatus", manifest.Collection.Status.ToString());
            writer.WriteNumber(
                "plannedArtifactCount",
                manifest.Collection.PlannedArtifactCount);
            writer.WriteNumber(
                "usableArtifactCount",
                manifest.Collection.UsableArtifactCount);
            writer.WriteBoolean(
                "noTrafficExpected",
                manifest.Collection.NoTrafficExpected);
            writer.WriteString(
                "evidenceReasonCode",
                manifest.Collection.ReasonCode.ToString());
            writer.WriteString(
                "coverageQualification",
                manifest.CoverageQualification.ToString());
            writer.WriteString("cleanupStatus", manifest.CleanupStatus.ToString());
            writer.WriteString(
                "finalizationStatus",
                manifest.FinalizationStatus.ToString());
            writer.WriteString("runnerResult", manifest.RunnerResult.ToString());
            writer.WriteString(
                "completionState",
                manifest.CompletionState.ToString());

            WriteMetadata(writer, manifest.Metadata);
            WriteArtifacts(writer, manifest.Artifacts);
            WriteArtifactAbsences(writer, manifest.ArtifactAbsences);
            WriteUnresolvedWriters(writer, manifest.UnresolvedWriters);
            WriteErrors(writer, manifest.Errors);

            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(stream.ToArray());
    }

    public static ManifestDocument Deserialize(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            throw new ManifestSerializationException(
                "Manifest JSON must be non-empty.");
        }

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(json);
        }
        catch (JsonException exception)
        {
            throw new ManifestSerializationException(
                "Manifest JSON is malformed.",
                exception);
        }

        using (document)
        {
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                throw new ManifestSerializationException(
                    "The manifest root must be a JSON object.");
            }

            string schemaVersion = ReadRequiredString(root, "schemaVersion");
            ManifestSchema.Validate(schemaVersion);

            var manifest = new ManifestDocument(schemaVersion)
            {
                ProtocolResult = ReadEnum(
                    root,
                    "protocolResult",
                    ProtocolResultState.Pending),
                Collection = ReadCollection(root),
                CoverageQualification = ReadEnum(
                    root,
                    "coverageQualification",
                    CoverageQualification.Unverified),
                CleanupStatus = ReadEnum(
                    root,
                    "cleanupStatus",
                    LifecycleStatus.Pending),
                FinalizationStatus = ReadEnum(
                    root,
                    "finalizationStatus",
                    LifecycleStatus.Pending),
                RunnerResult = ReadEnum(
                    root,
                    "runnerResult",
                    RunnerResultState.Pending),
                CompletionState = ReadEnum(
                    root,
                    "completionState",
                    CompletionState.Provisional),
            };

            ReadMetadata(root, manifest);
            ReadArtifacts(root, manifest);
            ReadArtifactAbsences(root, manifest);
            ReadUnresolvedWriters(root, manifest);
            ReadErrors(root, manifest);
            ValidateInventory(manifest);
            return manifest;
        }
    }

    private static void ValidateInventory(ManifestDocument manifest)
    {
        ManifestValidation.ValidateOutcomeStates(manifest);

        if (manifest.Collection is null)
        {
            throw new ManifestSerializationException(
                "The collection evidence cannot be null.");
        }

        if (manifest.Artifacts.Any(artifact => artifact is null))
        {
            throw new ManifestSerializationException(
                "The artifact inventory cannot contain null placeholders.");
        }

        if (manifest.ArtifactAbsences.Any(absence => absence is null))
        {
            throw new ManifestSerializationException(
                "The artifact absence inventory cannot contain null placeholders.");
        }

        if (manifest.Metadata.Any(entry => entry is null))
        {
            throw new ManifestSerializationException(
                "The metadata inventory cannot contain null placeholders.");
        }

        ManifestValidation.ValidateUnresolvedWriters(manifest.UnresolvedWriters);
        if (manifest.CompletionState == CompletionState.Final)
        {
            CollectionValidationResult collectionValidation =
                CollectionEvidenceValidator.ValidateForFinalization(
                    manifest.Collection);
            if (!collectionValidation.CanFinalize ||
                !ManifestValidation.CollectionEquals(
                    manifest.Collection,
                    collectionValidation.NormalizedEvidence))
            {
                throw new ManifestSerializationException(
                    "A final manifest must contain normalized, finalizable collection evidence.");
            }

            if (manifest.Artifacts.Any(
                    artifact =>
                        artifact.FinalizationState !=
                        ArtifactFinalizationState.Finalized) ||
                manifest.UnresolvedWriters.Count != 0)
            {
                throw new ManifestSerializationException(
                    "A final manifest cannot contain active artifacts or unresolved writers.");
            }

            if (manifest.EvaluateSeal() != ManifestSealState.Sealed)
            {
                throw new ManifestSerializationException(
                    "A final manifest must have terminal protocol, cleanup, finalization, and runner outcomes.");
            }
        }
    }

    private static void WriteMetadata(
        Utf8JsonWriter writer,
        IEnumerable<ManifestMetadataEntry> entries)
    {
        writer.WriteStartArray("metadata");
        foreach (ManifestMetadataEntry entry in entries)
        {
            writer.WriteStartObject();
            writer.WriteString("key", entry.Key);
            writer.WriteString("sensitivity", entry.Sensitivity.ToString());
            if (entry.Sensitivity == MetadataSensitivity.NonSensitive)
            {
                writer.WriteString("value", entry.Value);
            }
            else if (entry.Sensitivity == MetadataSensitivity.Sensitive)
            {
                writer.WriteString("value", entry.RedactionMarker);
            }

            writer.WriteEndObject();
        }

        writer.WriteEndArray();
    }

    private static void WriteArtifacts(
        Utf8JsonWriter writer,
        IEnumerable<ArtifactRecord> artifacts)
    {
        writer.WriteStartArray("artifacts");
        foreach (ArtifactRecord artifact in artifacts)
        {
            writer.WriteStartObject();
            writer.WriteString("relativePath", artifact.RelativePath);
            writer.WriteString("producer", artifact.Producer);
            if (artifact.ByteCount.HasValue)
            {
                writer.WriteNumber("byteCount", artifact.ByteCount.Value);
            }
            else
            {
                writer.WriteNull("byteCount");
            }

            if (artifact.Sha256 is not null)
            {
                writer.WriteString("sha256", artifact.Sha256);
            }
            else
            {
                writer.WriteNull("sha256");
            }

            writer.WriteString(
                "finalizationState",
                artifact.FinalizationState.ToString());
            writer.WriteString(
                "confidentiality",
                artifact.Confidentiality.ToString());
            writer.WriteString("mediaType", artifact.MediaType);
            writer.WriteStartObject("relation");
            writer.WriteString("kind", artifact.Relation.Kind.ToString());
            if (artifact.Relation.SourceRelativePath is not null)
            {
                writer.WriteString(
                    "sourceRelativePath",
                    artifact.Relation.SourceRelativePath);
            }
            else
            {
                writer.WriteNull("sourceRelativePath");
            }

            writer.WriteEndObject();
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
    }

    private static void WriteArtifactAbsences(
        Utf8JsonWriter writer,
        IEnumerable<ArtifactAbsence> absences)
    {
        writer.WriteStartArray("artifactAbsences");
        foreach (ArtifactAbsence absence in absences)
        {
            writer.WriteStartObject();
            writer.WriteString("kind", absence.Kind.ToString());
            writer.WriteString(
                "availability",
                absence.Availability.ToString());
            writer.WriteString("reasonCode", absence.ReasonCode.ToString());
            if (absence.Reason.Detail is not null)
            {
                writer.WriteString("detail", absence.Reason.Detail);
            }

            writer.WriteEndObject();
        }

        writer.WriteEndArray();
    }

    private static void WriteUnresolvedWriters(
        Utf8JsonWriter writer,
        IEnumerable<string> writerIds)
    {
        writer.WriteStartArray("unresolvedWriters");
        foreach (string writerId in writerIds)
        {
            writer.WriteStringValue(writerId);
        }

        writer.WriteEndArray();
    }

    private static void WriteErrors(
        Utf8JsonWriter writer,
        DiagnosticErrorLedger ledger)
    {
        writer.WriteStartArray("errors");
        foreach (DiagnosticError error in ledger.Chronology)
        {
            writer.WriteStartObject();
            writer.WriteNumber("sequence", error.Sequence);
            writer.WriteString("category", error.Category.ToString());
            writer.WriteString("code", error.Code);
            writer.WriteString("message", error.Message);
            writer.WriteString("occurredAt", error.OccurredAt);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
    }

    private static CollectionEvidence ReadCollection(JsonElement root)
    {
        CollectionStatus status = ReadEnum(
            root,
            "collectionStatus",
            CollectionStatus.Pending);
        int planned = ReadOptionalInt32(root, "plannedArtifactCount", 0);
        int usable = ReadOptionalInt32(root, "usableArtifactCount", 0);
        bool noTrafficExpected = ReadOptionalBoolean(
            root,
            "noTrafficExpected",
            defaultValue: false);
        EvidenceReasonCode reasonCode = ReadEnum(
            root,
            "evidenceReasonCode",
            EvidenceReasonCode.None);

        try
        {
            return new CollectionEvidence(
                status,
                planned,
                usable,
                noTrafficExpected,
                reasonCode);
        }
        catch (ArgumentException exception)
        {
            throw new ManifestSerializationException(
                "The manifest collection evidence is invalid.",
                exception);
        }
    }

    private static void ReadMetadata(
        JsonElement root,
        ManifestDocument manifest)
    {
        foreach (JsonElement element in ReadOptionalArray(root, "metadata"))
        {
            RequireObject(element, "metadata entry");
            string key = ReadRequiredString(element, "key");
            MetadataSensitivity sensitivity = ReadRequiredEnum<MetadataSensitivity>(
                element,
                "sensitivity");
            string? value = element.TryGetProperty("value", out JsonElement valueElement) &&
                            valueElement.ValueKind != JsonValueKind.Null
                ? RequireString(valueElement, "metadata value")
                : null;

            manifest.Metadata.Add(new ManifestMetadataEntry(
                key,
                sensitivity == MetadataSensitivity.NonSensitive ? value : null,
                sensitivity));
        }
    }

    private static void ReadArtifacts(
        JsonElement root,
        ManifestDocument manifest)
    {
        foreach (JsonElement element in ReadOptionalArray(root, "artifacts"))
        {
            if (element.ValueKind == JsonValueKind.Null)
            {
                throw new ManifestSerializationException(
                    "The artifact inventory cannot contain null placeholders.");
            }

            RequireObject(element, "artifact");
            string relativePath = ReadRequiredString(element, "relativePath");
            string producer = ReadRequiredString(element, "producer");
            ArtifactFinalizationState finalizationState = ReadEnum(
                element,
                "finalizationState",
                ArtifactFinalizationState.Active);
            ArtifactConfidentiality confidentiality = ReadEnum(
                element,
                "confidentiality",
                ArtifactConfidentiality.Internal);
            long? byteCount = ReadOptionalInt64(element, "byteCount");
            string? sha256 = ReadOptionalString(element, "sha256");
            string? mediaType = ReadOptionalString(element, "mediaType");
            ArtifactRelation relation = ReadRelation(element);

            try
            {
                manifest.Artifacts.Add(ArtifactRecord.Restore(
                    relativePath,
                    producer,
                    byteCount,
                    sha256,
                    finalizationState,
                    confidentiality,
                    relation,
                    mediaType));
            }
            catch (ArgumentException exception)
            {
                throw new ManifestSerializationException(
                    $"Artifact '{relativePath}' is invalid.",
                    exception);
            }
        }
    }

    private static ArtifactRelation ReadRelation(JsonElement artifact)
    {
        if (!artifact.TryGetProperty("relation", out JsonElement relationElement))
        {
            return ArtifactRelation.Original;
        }

        RequireObject(relationElement, "artifact relation");
        ArtifactRelationKind kind = ReadEnum(
            relationElement,
            "kind",
            ArtifactRelationKind.Original);
        return kind switch
        {
            ArtifactRelationKind.Original => ArtifactRelation.Original,
            ArtifactRelationKind.Derived => ArtifactRelation.DerivedFrom(
                ReadRequiredString(
                    relationElement,
                    "sourceRelativePath")),
            _ => throw new ManifestSerializationException(
                $"Unknown artifact relation kind '{kind}'."),
        };
    }

    private static void ReadArtifactAbsences(
        JsonElement root,
        ManifestDocument manifest)
    {
        foreach (JsonElement element in ReadOptionalArray(
                     root,
                     "artifactAbsences"))
        {
            RequireObject(element, "artifact absence");
            ArtifactKind kind = ReadEnum(
                element,
                "kind",
                ArtifactKind.Other);
            ArtifactAvailability availability = ReadEnum(
                element,
                "availability",
                ArtifactAvailability.Missing);
            EvidenceReasonCode reasonCode = ReadEnum(
                element,
                "reasonCode",
                EvidenceReasonCode.ArtifactMissing);
            string? detail = ReadOptionalString(element, "detail");
            ArtifactAbsence absence = availability switch
            {
                ArtifactAvailability.Unsupported =>
                    ArtifactAbsence.Unsupported(kind, reasonCode, detail),
                ArtifactAvailability.Missing =>
                    ArtifactAbsence.Missing(kind, reasonCode, detail),
                _ => throw new ManifestSerializationException(
                    $"Unknown artifact availability '{availability}'."),
            };
            manifest.ArtifactAbsences.Add(absence);
        }
    }

    private static void ReadUnresolvedWriters(
        JsonElement root,
        ManifestDocument manifest)
    {
        foreach (JsonElement element in ReadOptionalArray(
                     root,
                     "unresolvedWriters"))
        {
            string writerId = RequireString(element, "unresolved writer ID");
            if (string.IsNullOrWhiteSpace(writerId))
            {
                throw new ManifestSerializationException(
                    "Unresolved writer IDs must be non-empty.");
            }

            manifest.UnresolvedWriters.Add(writerId);
        }
    }

    private static void ReadErrors(
        JsonElement root,
        ManifestDocument manifest)
    {
        foreach (JsonElement element in ReadOptionalArray(root, "errors"))
        {
            RequireObject(element, "diagnostic error");
            long sequence = ReadRequiredInt64(element, "sequence");
            DiagnosticErrorCategory category = ReadEnum(
                element,
                "category",
                DiagnosticErrorCategory.Capture);
            string code = ReadRequiredString(element, "code");
            string message = ReadRequiredString(element, "message");
            DateTimeOffset occurredAt = ReadRequiredDateTimeOffset(
                element,
                "occurredAt");

            try
            {
                manifest.Errors.Restore(
                    sequence,
                    category,
                    code,
                    message,
                    occurredAt);
            }
            catch (ArgumentException exception)
            {
                throw new ManifestSerializationException(
                    "The manifest diagnostic error chronology is invalid.",
                    exception);
            }
            catch (InvalidOperationException exception)
            {
                throw new ManifestSerializationException(
                    "The manifest diagnostic error chronology is invalid.",
                    exception);
            }
        }
    }

    private static IEnumerable<JsonElement> ReadOptionalArray(
        JsonElement parent,
        string propertyName)
    {
        if (!parent.TryGetProperty(propertyName, out JsonElement element))
        {
            return Array.Empty<JsonElement>();
        }

        if (element.ValueKind != JsonValueKind.Array)
        {
            throw new ManifestSerializationException(
                $"Manifest property '{propertyName}' must be an array.");
        }

        return element.EnumerateArray().ToArray();
    }

    private static string ReadRequiredString(
        JsonElement parent,
        string propertyName)
    {
        if (!parent.TryGetProperty(propertyName, out JsonElement element))
        {
            throw new ManifestSerializationException(
                $"Manifest property '{propertyName}' is required.");
        }

        string value = RequireString(element, propertyName);
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ManifestSerializationException(
                $"Manifest property '{propertyName}' must be non-empty.");
        }

        return value;
    }

    private static string RequireString(
        JsonElement element,
        string description)
    {
        if (element.ValueKind != JsonValueKind.String)
        {
            throw new ManifestSerializationException(
                $"The {description} must be a JSON string.");
        }

        return element.GetString()!;
    }

    private static string? ReadOptionalString(
        JsonElement parent,
        string propertyName)
    {
        if (!parent.TryGetProperty(propertyName, out JsonElement element) ||
            element.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        return RequireString(element, propertyName);
    }

    private static int ReadOptionalInt32(
        JsonElement parent,
        string propertyName,
        int defaultValue)
    {
        if (!parent.TryGetProperty(propertyName, out JsonElement element))
        {
            return defaultValue;
        }

        if (!element.TryGetInt32(out int value))
        {
            throw new ManifestSerializationException(
                $"Manifest property '{propertyName}' must be a 32-bit integer.");
        }

        return value;
    }

    private static long? ReadOptionalInt64(
        JsonElement parent,
        string propertyName)
    {
        if (!parent.TryGetProperty(propertyName, out JsonElement element) ||
            element.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        if (!element.TryGetInt64(out long value))
        {
            throw new ManifestSerializationException(
                $"Manifest property '{propertyName}' must be a 64-bit integer.");
        }

        return value;
    }

    private static long ReadRequiredInt64(
        JsonElement parent,
        string propertyName)
    {
        if (!parent.TryGetProperty(propertyName, out JsonElement element))
        {
            throw new ManifestSerializationException(
                $"Manifest property '{propertyName}' is required.");
        }

        if (!element.TryGetInt64(out long value))
        {
            throw new ManifestSerializationException(
                $"Manifest property '{propertyName}' must be a 64-bit integer.");
        }

        return value;
    }

    private static bool ReadOptionalBoolean(
        JsonElement parent,
        string propertyName,
        bool defaultValue)
    {
        if (!parent.TryGetProperty(propertyName, out JsonElement element))
        {
            return defaultValue;
        }

        if (element.ValueKind is not (
                JsonValueKind.True or
                JsonValueKind.False))
        {
            throw new ManifestSerializationException(
                $"Manifest property '{propertyName}' must be a Boolean.");
        }

        return element.GetBoolean();
    }

    private static TEnum ReadEnum<TEnum>(
        JsonElement parent,
        string propertyName,
        TEnum defaultValue)
        where TEnum : struct, Enum
    {
        if (!parent.TryGetProperty(propertyName, out JsonElement element))
        {
            return defaultValue;
        }

        string text = RequireString(element, propertyName);
        if (!Enum.TryParse(text, ignoreCase: false, out TEnum value) ||
            !Enum.IsDefined(value))
        {
            throw new ManifestSerializationException(
                $"Manifest property '{propertyName}' has unsupported value '{text}'.");
        }

        return value;
    }

    private static TEnum ReadRequiredEnum<TEnum>(
        JsonElement parent,
        string propertyName)
        where TEnum : struct, Enum
    {
        if (!parent.TryGetProperty(propertyName, out _))
        {
            throw new ManifestSerializationException(
                $"Manifest property '{propertyName}' is required.");
        }

        return ReadEnum(parent, propertyName, default(TEnum));
    }

    private static DateTimeOffset ReadRequiredDateTimeOffset(
        JsonElement parent,
        string propertyName)
    {
        string text = ReadRequiredString(parent, propertyName);
        if (!DateTimeOffset.TryParse(
                text,
                CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind,
                out DateTimeOffset value))
        {
            throw new ManifestSerializationException(
                $"Manifest property '{propertyName}' is not a valid timestamp.");
        }

        return value;
    }

    private static void RequireObject(
        JsonElement element,
        string description)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            throw new ManifestSerializationException(
                $"The {description} must be a JSON object.");
        }
    }
}

public class ManifestSerializationException : Exception
{
    public ManifestSerializationException(string message)
        : base(message)
    {
    }

    public ManifestSerializationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

public class ManifestVersionNotSupportedException :
    ManifestSerializationException
{
    public ManifestVersionNotSupportedException(
        string receivedVersion,
        int supportedMajorVersion)
        : base(
            $"Manifest schema version '{receivedVersion}' is not supported. " +
            $"Supported major version: {supportedMajorVersion}.")
    {
        ReceivedVersion = receivedVersion;
        SupportedMajorVersion = supportedMajorVersion;
    }

    public string ReceivedVersion { get; }

    public int SupportedMajorVersion { get; }
}

public sealed class UnsupportedSchemaVersionException :
    ManifestVersionNotSupportedException
{
    public UnsupportedSchemaVersionException(
        string receivedVersion,
        int supportedMajorVersion)
        : base(receivedVersion, supportedMajorVersion)
    {
    }
}

public sealed class UnresolvedWritersException : InvalidOperationException
{
    public UnresolvedWritersException(IEnumerable<string> writerIds)
        : base(
            "The manifest cannot be sealed while artifact writers remain unresolved: " +
            string.Join(", ", writerIds))
    {
        WriterIds = writerIds.ToArray();
    }

    public IReadOnlyList<string> WriterIds { get; }
}

public sealed class UnfinalizedArtifactException : InvalidOperationException
{
    public UnfinalizedArtifactException(IEnumerable<string> relativePaths)
        : base(
            "The manifest cannot be sealed while artifacts remain active: " +
            string.Join(", ", relativePaths))
    {
        RelativePaths = relativePaths.ToArray();
    }

    public IReadOnlyList<string> RelativePaths { get; }
}

public sealed class ManifestNotFinalizableException : InvalidOperationException
{
    public ManifestNotFinalizableException(string message)
        : base(message)
    {
    }
}
