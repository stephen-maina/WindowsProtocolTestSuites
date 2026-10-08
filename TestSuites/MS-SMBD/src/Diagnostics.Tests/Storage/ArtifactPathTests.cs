// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;
using Microsoft.Protocols.TestSuites.Diagnostics.Storage;
using Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.TestSupport;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.Storage;

[TestClass]
public sealed class ArtifactPathTests
{
    [DataTestMethod]
    [DataRow("")]
    [DataRow(".")]
    [DataRow("..")]
    [DataRow(@"..\escape")]
    [DataRow(@"logs\..\escape")]
    [DataRow("logs/../escape")]
    [DataRow(@"logs/mixed\separator")]
    [DataRow(@"C:\outside")]
    [DataRow(@"\\server\share")]
    [DataRow("/outside")]
    [DataRow(@"\outside")]
    [DataRow("unsafe:name")]
    [DataRow("unsafe<name>")]
    [DataRow("unsafe\"name")]
    [DataRow("unsafe|name")]
    [DataRow("unsafe?name")]
    [DataRow("unsafe*name")]
    [DataRow("unsafe\u0001name")]
    [DataRow("trailing.")]
    [DataRow("trailing ")]
    [DataRow("CON")]
    [DataRow("nul.txt")]
    [DataRow("COM1.log")]
    [DataRow("LPT9")]
    [DataRow("COM\u00B9.log")]
    [DataRow("LPT\u00B2")]
    public void CombineUnderRoot_UnsafeComponent_RejectsComponent(string unsafeComponent)
    {
        using TemporaryDirectory temporaryDirectory = TemporaryDirectory.Create();

        ArtifactStorageException exception = Assert.ThrowsExactly<ArtifactStorageException>(
            () => ArtifactPath.CombineUnderRoot(temporaryDirectory.Path, unsafeComponent));

        Assert.AreEqual(ArtifactStorageFailure.UnsafePathComponent, exception.Failure);
    }

    [TestMethod]
    public void CombineUnderRoot_EmptyMiddleSegment_RejectsComponent()
    {
        using TemporaryDirectory temporaryDirectory = TemporaryDirectory.Create();

        ArtifactStorageException exception = Assert.ThrowsExactly<ArtifactStorageException>(
            () => ArtifactPath.CombineUnderRoot(temporaryDirectory.Path, "logs", string.Empty, "ptf.txt"));

        Assert.AreEqual(ArtifactStorageFailure.UnsafePathComponent, exception.Failure);
    }

    [TestMethod]
    public void CombineUnderRoot_OverlongComponent_RejectsComponent()
    {
        using TemporaryDirectory temporaryDirectory = TemporaryDirectory.Create();
        string overlongComponent = new('a', 256);

        ArtifactStorageException exception = Assert.ThrowsExactly<ArtifactStorageException>(
            () => ArtifactPath.CombineUnderRoot(temporaryDirectory.Path, overlongComponent));

        Assert.AreEqual(ArtifactStorageFailure.UnsafePathComponent, exception.Failure);
    }

    [TestMethod]
    public void CombineUnderRoot_DotPrefixedComponent_PreservesValidWindowsName()
    {
        using TemporaryDirectory temporaryDirectory = TemporaryDirectory.Create();

        string actual = ArtifactPath.CombineUnderRoot(
            temporaryDirectory.Path,
            ".checkpoint");

        Assert.AreEqual(
            Path.Combine(temporaryDirectory.Path, ".checkpoint"),
            actual);
    }

    [TestMethod]
    public void IsContained_PrefixSiblingPath_DoesNotTreatTextualPrefixAsContainment()
    {
        using TemporaryDirectory temporaryDirectory = TemporaryDirectory.Create();
        string root = temporaryDirectory.CreateSubdirectory("artifacts");
        string child = Path.Combine(root, "run", "manifest.json");
        string prefixSibling = root + "-escaped";

        Assert.IsTrue(ArtifactPath.IsContained(root, child));
        Assert.IsFalse(ArtifactPath.IsContained(root, prefixSibling));
        Assert.IsFalse(ArtifactPath.IsContained(root, Path.Combine(prefixSibling, "manifest.json")));
    }

    [TestMethod]
    public void IsContained_CaseVariantCanonicalChild_UsesWindowsComponentSemantics()
    {
        using TemporaryDirectory temporaryDirectory = TemporaryDirectory.Create();
        string root = temporaryDirectory.CreateSubdirectory("Artifacts");
        string caseVariantChild = Path.Combine(root.ToUpperInvariant(), "run", "manifest.json");

        Assert.IsTrue(ArtifactPath.IsContained(root, caseVariantChild));
    }

    [TestMethod]
    public void IsContainedCanonical_LinuxCaseVariant_IsNotContained_CPL06()
    {
        Assert.IsTrue(
            ArtifactPath.IsContainedCanonical(
                "/var/Artifacts",
                "/var/Artifacts/run/manifest.json",
                ArtifactPathPlatform.Linux));
        Assert.IsFalse(
            ArtifactPath.IsContainedCanonical(
                "/var/Artifacts",
                "/var/artifacts/run/manifest.json",
                ArtifactPathPlatform.Linux));
    }

    [TestMethod]
    public void IsContainedCanonical_LinuxPrefixSibling_IsNotContained_CPL06()
    {
        Assert.IsFalse(
            ArtifactPath.IsContainedCanonical(
                "/var/artifacts",
                "/var/artifacts-escaped/manifest.json",
                ArtifactPathPlatform.Linux));
    }

    [TestMethod]
    public void ValidateComponent_LinuxSpecificName_AcceptsWithoutChangingWindowsRules_CPL06()
    {
        ArtifactPath.ValidateComponent(
            "CON:trace.",
            ArtifactPathPlatform.Linux);

        Assert.ThrowsExactly<ArtifactStorageException>(
            () => ArtifactPath.ValidateComponent(
                "CON:trace.",
                ArtifactPathPlatform.Windows));
    }

    [DataTestMethod]
    [DataRow("")]
    [DataRow(".")]
    [DataRow("..")]
    [DataRow("folder/name")]
    [DataRow("bad\u0001name")]
    public void ValidateComponent_LinuxUnsafeName_RejectsComponent_CPL06(
        string component)
    {
        ArtifactStorageException exception =
            Assert.ThrowsExactly<ArtifactStorageException>(
                () => ArtifactPath.ValidateComponent(
                    component,
                    ArtifactPathPlatform.Linux));

        Assert.AreEqual(
            ArtifactStorageFailure.UnsafePathComponent,
            exception.Failure);
    }

    [TestMethod]
    public void EnsureContained_PrefixSiblingPath_RejectsEscapedCandidate()
    {
        using TemporaryDirectory temporaryDirectory = TemporaryDirectory.Create();
        string root = temporaryDirectory.CreateSubdirectory("artifacts");
        string prefixSibling = root + "-escaped";

        ArtifactStorageException exception = Assert.ThrowsExactly<ArtifactStorageException>(
            () => ArtifactPath.EnsureContained(root, Path.Combine(prefixSibling, "manifest.json")));

        Assert.AreEqual(ArtifactStorageFailure.PathOutsideRoot, exception.Failure);
    }
}
