// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Linq;
using Microsoft.Protocols.TestSuites.Diagnostics.Evidence;
using Microsoft.Protocols.TestSuites.Diagnostics.Manifest;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.Manifest;

/// <summary>
/// Red tests for Task 64410323 collection and completion-state semantics.
/// </summary>
[TestClass]
public sealed class CollectionSemanticsTests
{
    [DataTestMethod]
    [DataRow(CollectionStatus.Disabled, 0, 0, false, EvidenceReasonCode.None, true)]
    [DataRow(CollectionStatus.Pending, 1, 0, false, EvidenceReasonCode.None, false)]
    [DataRow(CollectionStatus.Complete, 1, 1, false, EvidenceReasonCode.None, true)]
    [DataRow(CollectionStatus.Partial, 2, 1, false, EvidenceReasonCode.CollectionGap, true)]
    [DataRow(CollectionStatus.Unavailable, 1, 0, false, EvidenceReasonCode.StorageUnavailable, true)]
    public void ValidateForFinalization_DefinedCollectionState_AppliesItsFinalizationSemantics_Issue64410323(
        CollectionStatus status,
        int plannedArtifactCount,
        int usableArtifactCount,
        bool noTrafficExpected,
        EvidenceReasonCode reasonCode,
        bool expectedCanFinalize)
    {
        // Arrange
        var collection = new CollectionEvidence(
            status,
            plannedArtifactCount,
            usableArtifactCount,
            noTrafficExpected,
            reasonCode);

        // Act
        CollectionValidationResult result = CollectionEvidenceValidator.ValidateForFinalization(collection);

        // Assert
        Assert.AreEqual(expectedCanFinalize, result.CanFinalize);
    }

    [TestMethod]
    public void ValidateForFinalization_CompletePlannedZeroTraffic_IsValidEmptyEvidence_Issue64410323()
    {
        // Arrange
        var collection = new CollectionEvidence(
            CollectionStatus.Complete,
            plannedArtifactCount: 0,
            usableArtifactCount: 0,
            noTrafficExpected: true,
            EvidenceReasonCode.NoTrafficExpected);

        // Act
        CollectionValidationResult result = CollectionEvidenceValidator.ValidateForFinalization(collection);

        // Assert
        Assert.IsTrue(result.CanFinalize);
    }

    [TestMethod]
    public void ValidateForFinalization_CompleteUnexpectedEmptyEvidence_ReturnsStructuredFailure_Issue64410323()
    {
        // Arrange
        var collection = new CollectionEvidence(
            CollectionStatus.Complete,
            plannedArtifactCount: 1,
            usableArtifactCount: 0,
            noTrafficExpected: false,
            EvidenceReasonCode.None);

        // Act
        CollectionValidationResult result = CollectionEvidenceValidator.ValidateForFinalization(collection);

        // Assert
        Assert.AreEqual(EvidenceReasonCode.UnexpectedEmptyEvidence, result.ReasonCode);
    }

    [TestMethod]
    public void Seal_UnresolvedWriter_PreventsFinalManifest_Issue64410323()
    {
        // Arrange
        var manifest = new ManifestDocument(ManifestSchema.SupportedVersion)
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
        manifest.UnresolvedWriters.Add("capture-session-17");

        // Act
        UnresolvedWritersException exception = Assert.ThrowsExactly<UnresolvedWritersException>(
            () => ManifestSealer.Seal(manifest));

        // Assert
        CollectionAssert.AreEqual(
            new[] { "capture-session-17" },
            exception.WriterIds.ToArray());
    }
}