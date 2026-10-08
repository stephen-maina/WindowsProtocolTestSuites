// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;
using Microsoft.Protocols.TestSuites.Diagnostics.Evidence;
using Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.TestSupport;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.Evidence;

[TestClass]
public sealed class EvidenceReviewRegressionTests
{
    private const string Sha256 = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

    [DataTestMethod]
    [DataRow("captures/NUL.txt")]
    [DataRow("captures/COM\u00B9")]
    [DataRow("captures/COM\u00B2.txt")]
    [DataRow("captures/COM\u00B3.tar.gz")]
    [DataRow("captures/LPT\u00B9")]
    [DataRow("captures/LPT\u00B2.txt")]
    [DataRow("captures/LPT\u00B3.tar.gz")]
    [DataRow("captures/trace.pcapng.")]
    [DataRow("captures/trace.pcapng ")]
    public void CreateFinalized_WindowsAliasComponent_RejectsPath_Issue64410323(
        string unsafePath)
    {
        Assert.ThrowsExactly<UnsafeArtifactPathException>(() => ArtifactRecord.CreateFinalized(
            relativePath: unsafePath,
            producer: "test-producer",
            byteCount: 1,
            sha256: Sha256,
            confidentiality: ArtifactConfidentiality.Internal,
            relation: ArtifactRelation.Original));
    }

    [TestMethod]
    public void Verify_IntermediateReparsePoint_RejectsExternalArtifact_Issue64410323()
    {
        using TemporaryDirectory artifactRoot = TemporaryDirectory.Create();
        using TemporaryDirectory outside = TemporaryDirectory.Create();
        string linkPath = Path.Combine(artifactRoot.Path, "linked");
        string outsideArtifact = Path.Combine(outside.Path, "trace.pcapng");
        File.WriteAllBytes(outsideArtifact, new byte[] { 0x01 });
        if (!ReparsePointTestSupport.TryCreateDirectoryLink(linkPath, outside.Path))
        {
            Assert.Inconclusive(
                "This host cannot create the directory reparse point required by the containment regression.");
        }
        ArtifactRecord record = ArtifactRecord.CreateFinalized(
            relativePath: "linked/trace.pcapng",
            producer: "test-producer",
            byteCount: 1,
            sha256: Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(new byte[] { 0x01 })),
            confidentiality: ArtifactConfidentiality.Restricted,
            relation: ArtifactRelation.Original);

        try
        {
            Assert.ThrowsExactly<UnsafeArtifactPathException>(
                () => ArtifactIntegrityVerifier.Verify(artifactRoot.Path, record));
        }
        finally
        {
            ReparsePointTestSupport.DeleteDirectoryLink(linkPath);
        }
    }
}
