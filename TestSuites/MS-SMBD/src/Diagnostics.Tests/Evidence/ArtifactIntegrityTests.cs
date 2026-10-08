// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;
using System.Security.Cryptography;
using Microsoft.Protocols.TestSuites.Diagnostics.Evidence;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.Evidence;

/// <summary>
/// Red tests for Task 64410323 artifact integrity verification.
/// </summary>
[TestClass]
public sealed class ArtifactIntegrityTests
{
    private string artifactRoot = null!;

    [TestInitialize]
    public void Initialize()
    {
        artifactRoot = Directory.CreateTempSubdirectory("smbd-b01-integrity-").FullName;
    }

    [TestCleanup]
    public void Cleanup()
    {
        if (Directory.Exists(artifactRoot))
        {
            Directory.Delete(artifactRoot, recursive: true);
        }
    }

    [TestMethod]
    public void Verify_LowercaseRecordedSha256MatchingUppercaseComputation_ReturnsValid_Issue64410323()
    {
        // Arrange
        byte[] payload = { 0x53, 0x4D, 0x42, 0x44, 0x01, 0x02, 0x03 };
        ArtifactRecord record = WriteFinalizedArtifact(payload, lowercaseDigest: true);

        // Act
        ArtifactIntegrityResult result = ArtifactIntegrityVerifier.Verify(artifactRoot, record);

        // Assert
        Assert.AreEqual(ArtifactIntegrityStatus.Valid, result.Status);
    }

    [TestMethod]
    public void Verify_FinalizedArtifactTamperedWithoutSizeChange_ReturnsDigestMismatch_Issue64410323()
    {
        // Arrange
        byte[] payload = { 0x10, 0x20, 0x30, 0x40 };
        ArtifactRecord record = WriteFinalizedArtifact(payload, lowercaseDigest: false);
        File.WriteAllBytes(GetArtifactPath(), new byte[] { 0x10, 0x20, 0x30, 0x41 });

        // Act
        ArtifactIntegrityResult result = ArtifactIntegrityVerifier.Verify(artifactRoot, record);

        // Assert
        Assert.AreEqual(ArtifactIntegrityStatus.DigestMismatch, result.Status);
    }

    [TestMethod]
    public void Verify_FinalizedArtifactTruncated_ReturnsSizeMismatch_Issue64410323()
    {
        // Arrange
        byte[] payload = { 0x10, 0x20, 0x30, 0x40 };
        ArtifactRecord record = WriteFinalizedArtifact(payload, lowercaseDigest: false);
        File.WriteAllBytes(GetArtifactPath(), new byte[] { 0x10, 0x20 });

        // Act
        ArtifactIntegrityResult result = ArtifactIntegrityVerifier.Verify(artifactRoot, record);

        // Assert
        Assert.AreEqual(ArtifactIntegrityStatus.SizeMismatch, result.Status);
    }

    private ArtifactRecord WriteFinalizedArtifact(byte[] payload, bool lowercaseDigest)
    {
        string artifactPath = GetArtifactPath();
        Directory.CreateDirectory(Path.GetDirectoryName(artifactPath)!);
        File.WriteAllBytes(artifactPath, payload);

        string digest = Convert.ToHexString(SHA256.HashData(payload));
        if (lowercaseDigest)
        {
            digest = digest.ToLowerInvariant();
        }

        return ArtifactRecord.CreateFinalized(
            relativePath: "captures/trace.pcapng",
            producer: "test-producer",
            byteCount: payload.LongLength,
            sha256: digest,
            confidentiality: ArtifactConfidentiality.Restricted,
            relation: ArtifactRelation.Original);
    }

    private string GetArtifactPath()
    {
        return Path.Combine(artifactRoot, "captures", "trace.pcapng");
    }
}