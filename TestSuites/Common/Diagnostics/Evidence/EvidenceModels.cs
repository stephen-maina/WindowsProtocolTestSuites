// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using StorageArtifactPath = Microsoft.Protocols.TestSuites.Diagnostics.Storage.ArtifactPath;
using ArtifactStorageException = Microsoft.Protocols.TestSuites.Diagnostics.Storage.ArtifactStorageException;

namespace Microsoft.Protocols.TestSuites.Diagnostics.Evidence;

public enum CollectionStatus
{
    Disabled,
    Unavailable,
    Partial,
    Complete,
    Pending,
}

public enum EvidenceReasonCode
{
    None,
    NoTrafficExpected,
    CollectionGap,
    StorageUnavailable,
    UnexpectedEmptyEvidence,
    ProviderUnsupported,
    ArtifactMissing,
    StartupUnavailable,
    CleanupFailed,
}

public sealed class CollectionEvidence
{
    public CollectionEvidence(
        CollectionStatus status,
        int plannedArtifactCount,
        int usableArtifactCount,
        bool noTrafficExpected,
        EvidenceReasonCode reasonCode)
    {
        if (plannedArtifactCount < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(plannedArtifactCount),
                "The planned artifact count cannot be negative.");
        }

        if (usableArtifactCount < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(usableArtifactCount),
                "The usable artifact count cannot be negative.");
        }

        if (usableArtifactCount > plannedArtifactCount)
        {
            throw new ArgumentException(
                "The usable artifact count cannot exceed the planned artifact count.",
                nameof(usableArtifactCount));
        }

        Status = status;
        PlannedArtifactCount = plannedArtifactCount;
        UsableArtifactCount = usableArtifactCount;
        NoTrafficExpected = noTrafficExpected;
        ReasonCode = reasonCode;
    }

    public CollectionStatus Status { get; }

    public int PlannedArtifactCount { get; }

    public int UsableArtifactCount { get; }

    public bool NoTrafficExpected { get; }

    public EvidenceReasonCode ReasonCode { get; }
}

public sealed class CollectionValidationResult
{
    internal CollectionValidationResult(
        bool canFinalize,
        CollectionEvidence normalizedEvidence,
        EvidenceReasonCode reasonCode)
    {
        CanFinalize = canFinalize;
        NormalizedEvidence = normalizedEvidence;
        ReasonCode = reasonCode;
    }

    public bool CanFinalize { get; }

    public CollectionStatus Status => NormalizedEvidence.Status;

    public EvidenceReasonCode ReasonCode { get; }

    public CollectionEvidence NormalizedEvidence { get; }
}

public static class CollectionEvidenceValidator
{
    public static CollectionValidationResult ValidateForFinalization(
        CollectionEvidence collection)
    {
        ArgumentNullException.ThrowIfNull(collection);

        return collection.Status switch
        {
            CollectionStatus.Disabled => ValidateDisabled(collection),
            CollectionStatus.Pending => Result(false, collection, collection.ReasonCode),
            CollectionStatus.Complete => ValidateComplete(collection),
            CollectionStatus.Partial => ValidatePartial(collection),
            CollectionStatus.Unavailable => ValidateUnavailable(collection),
            _ => throw new ArgumentOutOfRangeException(
                nameof(collection),
                collection.Status,
                "Unknown collection status."),
        };
    }

    private static CollectionValidationResult ValidateDisabled(CollectionEvidence collection)
    {
        bool valid = collection.PlannedArtifactCount == 0 &&
                     collection.UsableArtifactCount == 0;
        return Result(valid, collection, collection.ReasonCode);
    }

    private static CollectionValidationResult ValidateComplete(CollectionEvidence collection)
    {
        if (collection.UsableArtifactCount == collection.PlannedArtifactCount)
        {
            if (collection.PlannedArtifactCount == 0 && !collection.NoTrafficExpected)
            {
                return NormalizeUnavailable(collection);
            }

            return Result(true, collection, collection.ReasonCode);
        }

        if (collection.UsableArtifactCount == 0)
        {
            return NormalizeUnavailable(collection);
        }

        var normalized = new CollectionEvidence(
            CollectionStatus.Partial,
            collection.PlannedArtifactCount,
            collection.UsableArtifactCount,
            collection.NoTrafficExpected,
            EvidenceReasonCode.CollectionGap);
        return Result(true, normalized, EvidenceReasonCode.CollectionGap);
    }

    private static CollectionValidationResult ValidatePartial(CollectionEvidence collection)
    {
        if (collection.UsableArtifactCount == 0)
        {
            return NormalizeUnavailable(collection);
        }

        var normalized = new CollectionEvidence(
            CollectionStatus.Partial,
            collection.PlannedArtifactCount,
            collection.UsableArtifactCount,
            collection.NoTrafficExpected,
            collection.ReasonCode);
        return Result(true, normalized, collection.ReasonCode);
    }

    private static CollectionValidationResult ValidateUnavailable(CollectionEvidence collection)
    {
        bool valid = collection.UsableArtifactCount == 0 &&
                     collection.ReasonCode != EvidenceReasonCode.None;
        return Result(valid, collection, collection.ReasonCode);
    }

    private static CollectionValidationResult NormalizeUnavailable(
        CollectionEvidence collection)
    {
        EvidenceReasonCode reasonCode =
            collection.ReasonCode == EvidenceReasonCode.None
                ? EvidenceReasonCode.UnexpectedEmptyEvidence
                : collection.ReasonCode;
        var normalized = new CollectionEvidence(
            CollectionStatus.Unavailable,
            collection.PlannedArtifactCount,
            collection.UsableArtifactCount,
            collection.NoTrafficExpected,
            reasonCode);
        return Result(
            canFinalize: true,
            normalized,
            reasonCode);
    }

    private static CollectionValidationResult Result(
        bool canFinalize,
        CollectionEvidence evidence,
        EvidenceReasonCode reasonCode)
    {
        return new CollectionValidationResult(canFinalize, evidence, reasonCode);
    }
}

public enum ArtifactFinalizationState
{
    Active,
    Finalized,
}

public enum ArtifactConfidentiality
{
    Public,
    Internal,
    Restricted,
}

public enum ArtifactRelationKind
{
    Original,
    Derived,
}

public sealed class ArtifactRelation
{
    private ArtifactRelation(
        ArtifactRelationKind kind,
        string? sourceRelativePath)
    {
        Kind = kind;
        SourceRelativePath = sourceRelativePath;
    }

    public static ArtifactRelation Original { get; } =
        new(ArtifactRelationKind.Original, sourceRelativePath: null);

    public ArtifactRelationKind Kind { get; }

    public string? SourceRelativePath { get; }

    public static ArtifactRelation DerivedFrom(string sourceRelativePath)
    {
        return new ArtifactRelation(
            ArtifactRelationKind.Derived,
            ArtifactPath.Normalize(sourceRelativePath));
    }
}

public sealed class ArtifactRecord
{
    private ArtifactRecord(
        string relativePath,
        string producer,
        long? byteCount,
        string? sha256,
        ArtifactFinalizationState finalizationState,
        ArtifactConfidentiality confidentiality,
        ArtifactRelation relation,
        string mediaType)
    {
        RelativePath = ArtifactPath.Normalize(relativePath);
        Producer = RequireText(producer, nameof(producer));
        ByteCount = byteCount;
        Sha256 = sha256;
        FinalizationState = finalizationState;
        Confidentiality = confidentiality;
        Relation = relation ?? throw new ArgumentNullException(nameof(relation));
        MediaType = RequireText(mediaType, nameof(mediaType));
    }

    public string RelativePath { get; }

    public string Producer { get; }

    public long? ByteCount { get; }

    public string? Sha256 { get; }

    public ArtifactFinalizationState FinalizationState { get; }

    public ArtifactConfidentiality Confidentiality { get; }

    public string MediaType { get; }

    public ArtifactRelation Relation { get; }

    public static ArtifactRecord CreateFinalized(
        string relativePath,
        string producer,
        long byteCount,
        string sha256,
        ArtifactConfidentiality confidentiality,
        ArtifactRelation relation,
        string? mediaType = null)
    {
        if (byteCount < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(byteCount),
                "The artifact byte count cannot be negative.");
        }

        string normalizedDigest = NormalizeSha256(sha256);
        string normalizedPath = ArtifactPath.Normalize(relativePath);
        return new ArtifactRecord(
            normalizedPath,
            producer,
            byteCount,
            normalizedDigest,
            ArtifactFinalizationState.Finalized,
            confidentiality,
            relation,
            mediaType ?? ArtifactMediaTypes.FromPath(normalizedPath));
    }

    public static ArtifactRecord CreateActive(
        string relativePath,
        string producer,
        ArtifactConfidentiality confidentiality,
        ArtifactRelation relation,
        string? mediaType = null)
    {
        string normalizedPath = ArtifactPath.Normalize(relativePath);
        return new ArtifactRecord(
            normalizedPath,
            producer,
            byteCount: null,
            sha256: null,
            ArtifactFinalizationState.Active,
            confidentiality,
            relation,
            mediaType ?? ArtifactMediaTypes.FromPath(normalizedPath));
    }

    internal static ArtifactRecord Restore(
        string relativePath,
        string producer,
        long? byteCount,
        string? sha256,
        ArtifactFinalizationState finalizationState,
        ArtifactConfidentiality confidentiality,
        ArtifactRelation relation,
        string? mediaType)
    {
        return finalizationState switch
        {
            ArtifactFinalizationState.Active when byteCount is null && sha256 is null =>
                CreateActive(relativePath, producer, confidentiality, relation, mediaType),
            ArtifactFinalizationState.Finalized when byteCount.HasValue && sha256 is not null =>
                CreateFinalized(
                    relativePath,
                    producer,
                    byteCount.Value,
                    sha256,
                    confidentiality,
                    relation,
                    mediaType),
            _ => throw new ArgumentException(
                "Artifact finalization state is inconsistent with its size or SHA-256 digest."),
        };
    }

    private static string NormalizeSha256(string sha256)
    {
        if (sha256 is null)
        {
            throw new ArgumentNullException(nameof(sha256));
        }

        if (sha256.Length != 64 || sha256.Any(character => !Uri.IsHexDigit(character)))
        {
            throw new ArgumentException(
                "A SHA-256 digest must contain exactly 64 hexadecimal characters.",
                nameof(sha256));
        }

        return sha256.ToUpperInvariant();
    }

    private static string RequireText(string value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("A non-empty value is required.", parameterName);
        }

        return value;
    }
}

public enum ArtifactKind
{
    Capture,
    RunnerResult,
    Log,
    Manifest,
    Configuration,
    Review,
    Other,
}

public enum ArtifactAvailability
{
    Unsupported,
    Missing,
}

public sealed class ArtifactAbsenceReason
{
    public ArtifactAbsenceReason(
        ArtifactAvailability availability,
        EvidenceReasonCode reasonCode,
        string? detail = null)
    {
        if (reasonCode == EvidenceReasonCode.None)
        {
            throw new ArgumentException(
                "An absent artifact requires a structured reason code.",
                nameof(reasonCode));
        }

        Availability = availability;
        ReasonCode = reasonCode;
        Detail = string.IsNullOrWhiteSpace(detail) ? null : detail;
    }

    public ArtifactAvailability Availability { get; }

    public EvidenceReasonCode ReasonCode { get; }

    public string? Detail { get; }
}

public sealed class ArtifactAbsence
{
    private ArtifactAbsence(ArtifactKind kind, ArtifactAbsenceReason reason)
    {
        Kind = kind;
        Reason = reason ?? throw new ArgumentNullException(nameof(reason));
    }

    public ArtifactKind Kind { get; }

    public ArtifactAbsenceReason Reason { get; }

    public ArtifactAvailability Availability => Reason.Availability;

    public EvidenceReasonCode ReasonCode => Reason.ReasonCode;

    public static ArtifactAbsence Unsupported(
        ArtifactKind kind,
        EvidenceReasonCode reasonCode,
        string? detail = null)
    {
        return new ArtifactAbsence(
            kind,
            new ArtifactAbsenceReason(
                ArtifactAvailability.Unsupported,
                reasonCode,
                detail));
    }

    public static ArtifactAbsence Missing(
        ArtifactKind kind,
        EvidenceReasonCode reasonCode,
        string? detail = null)
    {
        return new ArtifactAbsence(
            kind,
            new ArtifactAbsenceReason(
                ArtifactAvailability.Missing,
                reasonCode,
                detail));
    }
}

public enum ArtifactIntegrityStatus
{
    Valid,
    DigestMismatch,
    SizeMismatch,
    Missing,
    NotFinalized,
}

public sealed class ArtifactIntegrityResult
{
    internal ArtifactIntegrityResult(
        ArtifactIntegrityStatus status,
        long? actualByteCount,
        string? actualSha256)
    {
        Status = status;
        ActualByteCount = actualByteCount;
        ActualSha256 = actualSha256;
    }

    public ArtifactIntegrityStatus Status { get; }

    public long? ActualByteCount { get; }

    public string? ActualSha256 { get; }
}

public static class ArtifactIntegrity
{
    public static async Task<ArtifactIntegrityResult> ComputeAsync(
        string artifactRoot,
        ArtifactRecord record,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(record);

        if (record.FinalizationState != ArtifactFinalizationState.Finalized ||
            !record.ByteCount.HasValue ||
            record.Sha256 is null)
        {
            return new ArtifactIntegrityResult(
                ArtifactIntegrityStatus.NotFinalized,
                actualByteCount: null,
                actualSha256: null);
        }

        string artifactPath = ArtifactPath.ResolveWithinRoot(
            artifactRoot,
            record.RelativePath);
        if (!File.Exists(artifactPath))
        {
            return new ArtifactIntegrityResult(
                ArtifactIntegrityStatus.Missing,
                actualByteCount: null,
                actualSha256: null);
        }

        var fileInfo = new FileInfo(artifactPath);
        if (fileInfo.Length != record.ByteCount.Value)
        {
            return new ArtifactIntegrityResult(
                ArtifactIntegrityStatus.SizeMismatch,
                fileInfo.Length,
                actualSha256: null);
        }

        await using var stream = new FileStream(
            artifactPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 81920,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        using SHA256 sha256 = SHA256.Create();
        byte[] digest = await sha256
            .ComputeHashAsync(stream, cancellationToken)
            .ConfigureAwait(false);
        string actualDigest = Convert.ToHexString(digest);
        ArtifactIntegrityStatus status = string.Equals(
            actualDigest,
            record.Sha256,
            StringComparison.OrdinalIgnoreCase)
            ? ArtifactIntegrityStatus.Valid
            : ArtifactIntegrityStatus.DigestMismatch;

        return new ArtifactIntegrityResult(status, fileInfo.Length, actualDigest);
    }
}

public static class ArtifactIntegrityVerifier
{
    public static ArtifactIntegrityResult Verify(
        string artifactRoot,
        ArtifactRecord record)
    {
        return ArtifactIntegrity
            .ComputeAsync(artifactRoot, record)
            .GetAwaiter()
            .GetResult();
    }

    public static Task<ArtifactIntegrityResult> VerifyAsync(
        string artifactRoot,
        ArtifactRecord record,
        CancellationToken cancellationToken = default)
    {
        return ArtifactIntegrity.ComputeAsync(
            artifactRoot,
            record,
            cancellationToken);
    }
}

public sealed class UnsafeArtifactPathException : ArgumentException
{
    public UnsafeArtifactPathException(string path, string reason)
        : base($"Artifact path '{path}' is unsafe: {reason}", nameof(path))
    {
        UnsafePath = path;
    }

    public string UnsafePath { get; }
}

internal static class ArtifactPath
{
    public static string Normalize(string path)
    {
        try
        {
            return StorageArtifactPath.NormalizeRelativePath(path);
        }
        catch (ArtifactStorageException exception)
        {
            throw new UnsafeArtifactPathException(
                path ?? "<null>",
                exception.Message);
        }
    }

    public static string ResolveWithinRoot(string artifactRoot, string relativePath)
    {
        try
        {
            return StorageArtifactPath.ResolveRelativePathUnderRoot(
                artifactRoot,
                relativePath);
        }
        catch (ArtifactStorageException exception)
        {
            throw new UnsafeArtifactPathException(relativePath, exception.Message);
        }
    }
}

internal static class ArtifactMediaTypes
{
    public static string FromPath(string relativePath)
    {
        return Path.GetExtension(relativePath).ToLowerInvariant() switch
        {
            ".json" => "application/json",
            ".jsonl" => "application/x-ndjson",
            ".log" or ".txt" => "text/plain",
            ".pcap" => "application/vnd.tcpdump.pcap",
            ".pcapng" => "application/x-pcapng",
            ".trx" => "application/xml",
            _ => "application/octet-stream",
        };
    }
}
