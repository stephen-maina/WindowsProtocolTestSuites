// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json;
using Microsoft.Protocols.TestSuites.Diagnostics.Evidence;
using Microsoft.Protocols.TestSuites.Diagnostics.Manifest;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.Evidence;

/// <summary>
/// Red tests for Task 64410323 finalized artifact inventory records.
/// </summary>
[TestClass]
public sealed class ArtifactRecordTests
{
    private const string Sha256 = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

    [TestMethod]
    public void CreateFinalized_DerivedArtifact_RecordsCanonicalCompleteInventoryMetadata_Issue64410323()
    {
        // Arrange
        ArtifactRelation relation = ArtifactRelation.DerivedFrom("captures/original.pcapng");

        // Act
        ArtifactRecord record = ArtifactRecord.CreateFinalized(
            relativePath: @"captures\derived\filtered.pcapng",
            producer: "offline-filter 1.0",
            byteCount: 4096,
            sha256: Sha256.ToLowerInvariant(),
            confidentiality: ArtifactConfidentiality.Restricted,
            relation: relation);
        string actual = string.Join(
            "|",
            record.RelativePath,
            record.Producer,
            record.ByteCount,
            record.Sha256,
            record.FinalizationState,
            record.Confidentiality,
            record.Relation.Kind,
            record.Relation.SourceRelativePath);

        // Assert
        Assert.AreEqual(
            $"captures/derived/filtered.pcapng|offline-filter 1.0|4096|{Sha256}|Finalized|Restricted|Derived|captures/original.pcapng",
            actual);
    }

    [DataTestMethod]
    [DataRow(@"C:\outside\trace.pcapng")]
    [DataRow(@"\\server\share\trace.pcapng")]
    [DataRow("/outside/trace.pcapng")]
    [DataRow("../outside/trace.pcapng")]
    [DataRow("captures/../../outside.pcapng")]
    [DataRow(@"captures\..\outside.pcapng")]
    public void CreateFinalized_UnsafeRelativePath_RejectsPath_Issue64410323(string unsafePath)
    {
        // Arrange, act, and assert
        Assert.ThrowsExactly<UnsafeArtifactPathException>(() => ArtifactRecord.CreateFinalized(
            relativePath: unsafePath,
            producer: "test-producer",
            byteCount: 1,
            sha256: Sha256,
            confidentiality: ArtifactConfidentiality.Internal,
            relation: ArtifactRelation.Original));
    }

    [TestMethod]
    public void Seal_ActiveArtifact_RejectsFalseFinalRepresentation_Issue64410323()
    {
        // Arrange
        ManifestDocument manifest = CreateFinalizableManifest();
        manifest.Artifacts.Add(ArtifactRecord.CreateActive(
            relativePath: "captures/live.pcapng",
            producer: "dumpcap",
            confidentiality: ArtifactConfidentiality.Restricted,
            relation: ArtifactRelation.Original));

        // Act and assert
        Assert.ThrowsExactly<UnfinalizedArtifactException>(() => ManifestSealer.Seal(manifest));
    }

    [TestMethod]
    public void Serialize_UnsupportedAndMissingArtifacts_UsesStructuredReasonsOutsideArtifactInventory_Issue64410323()
    {
        // Arrange
        ManifestDocument manifest = CreateFinalizableManifest();
        manifest.ArtifactAbsences.Add(ArtifactAbsence.Unsupported(
            ArtifactKind.Capture,
            EvidenceReasonCode.ProviderUnsupported));
        manifest.ArtifactAbsences.Add(ArtifactAbsence.Missing(
            ArtifactKind.RunnerResult,
            EvidenceReasonCode.ArtifactMissing));

        // Act
        string json = ManifestSerializer.Serialize(manifest);
        using JsonDocument document = JsonDocument.Parse(json);
        JsonElement root = document.RootElement;
        JsonElement absences = root.GetProperty("artifactAbsences");
        string actual = string.Join(
            "|",
            root.GetProperty("artifacts").GetArrayLength(),
            absences[0].GetProperty("availability").GetString(),
            absences[0].GetProperty("reasonCode").GetString(),
            absences[1].GetProperty("availability").GetString(),
            absences[1].GetProperty("reasonCode").GetString());

        // Assert
        Assert.AreEqual("0|Unsupported|ProviderUnsupported|Missing|ArtifactMissing", actual);
    }

    private static ManifestDocument CreateFinalizableManifest()
    {
        return new ManifestDocument(ManifestSchema.SupportedVersion)
        {
            ProtocolResult = ProtocolResultState.Passed,
            Collection = new CollectionEvidence(
                CollectionStatus.Complete,
                plannedArtifactCount: 0,
                usableArtifactCount: 0,
                noTrafficExpected: true,
                EvidenceReasonCode.NoTrafficExpected),
            CoverageQualification = CoverageQualification.Unverified,
            CleanupStatus = LifecycleStatus.Complete,
            FinalizationStatus = LifecycleStatus.Pending,
            RunnerResult = RunnerResultState.Passed,
            CompletionState = CompletionState.Provisional,
        };
    }
}