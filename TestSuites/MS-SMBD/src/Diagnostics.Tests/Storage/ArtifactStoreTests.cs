// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Protocols.TestSuites.Diagnostics.Identity;
using Microsoft.Protocols.TestSuites.Diagnostics.Storage;
using Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.TestSupport;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.Storage;

[TestClass]
public sealed class ArtifactStoreTests
{
    [DataTestMethod]
    [DataRow("")]
    [DataRow("relative-artifacts")]
    public void Open_EmptyOrRelativeArtifactRoot_RejectsRoot(string artifactRoot)
    {
        using TemporaryDirectory temporaryDirectory = TemporaryDirectory.Create();
        string sourceRoot = temporaryDirectory.CreateSubdirectory("source");
        string buildRoot = temporaryDirectory.CreateSubdirectory("build");

        ArtifactStorageException exception = Assert.ThrowsExactly<ArtifactStorageException>(
            () => ArtifactStore.Open(artifactRoot, sourceRoot, buildRoot));

        Assert.IsTrue(
            exception.Failure is ArtifactStorageFailure.ArtifactRootRequired
                or ArtifactStorageFailure.ArtifactRootMustBeAbsolute);
    }

    [TestMethod]
    public void Open_ArtifactRootInsideSourceRoot_RejectsRoot()
    {
        using TemporaryDirectory temporaryDirectory = TemporaryDirectory.Create();
        string sourceRoot = temporaryDirectory.CreateSubdirectory("source");
        string buildRoot = temporaryDirectory.CreateSubdirectory("build");
        string artifactRoot = Path.Combine(sourceRoot, "diagnostics-artifacts");

        ArtifactStorageException exception = Assert.ThrowsExactly<ArtifactStorageException>(
            () => ArtifactStore.Open(artifactRoot, sourceRoot, buildRoot));

        Assert.AreEqual(ArtifactStorageFailure.ArtifactRootConflictsWithSource, exception.Failure);
        Assert.IsFalse(Directory.Exists(artifactRoot));
    }

    [TestMethod]
    public void Open_ArtifactRootEqualToSourceRoot_RejectsRoot()
    {
        using TemporaryDirectory temporaryDirectory = TemporaryDirectory.Create();
        string sourceRoot = temporaryDirectory.CreateSubdirectory("source");
        string buildRoot = temporaryDirectory.CreateSubdirectory("build");

        ArtifactStorageException exception = Assert.ThrowsExactly<ArtifactStorageException>(
            () => ArtifactStore.Open(sourceRoot, sourceRoot, buildRoot));

        Assert.AreEqual(ArtifactStorageFailure.ArtifactRootConflictsWithSource, exception.Failure);
    }

    [TestMethod]
    public void Open_ArtifactRootInsideBuildRoot_RejectsRoot()
    {
        using TemporaryDirectory temporaryDirectory = TemporaryDirectory.Create();
        string sourceRoot = temporaryDirectory.CreateSubdirectory("source");
        string buildRoot = temporaryDirectory.CreateSubdirectory("build");
        string artifactRoot = Path.Combine(buildRoot, "diagnostics-artifacts");

        ArtifactStorageException exception = Assert.ThrowsExactly<ArtifactStorageException>(
            () => ArtifactStore.Open(artifactRoot, sourceRoot, buildRoot));

        Assert.AreEqual(ArtifactStorageFailure.ArtifactRootConflictsWithBuild, exception.Failure);
        Assert.IsFalse(Directory.Exists(artifactRoot));
    }

    [TestMethod]
    public void Open_ArtifactRootEqualToBuildRoot_RejectsRoot()
    {
        using TemporaryDirectory temporaryDirectory = TemporaryDirectory.Create();
        string sourceRoot = temporaryDirectory.CreateSubdirectory("source");
        string buildRoot = temporaryDirectory.CreateSubdirectory("build");

        ArtifactStorageException exception = Assert.ThrowsExactly<ArtifactStorageException>(
            () => ArtifactStore.Open(buildRoot, sourceRoot, buildRoot));

        Assert.AreEqual(ArtifactStorageFailure.ArtifactRootConflictsWithBuild, exception.Failure);
    }

    [TestMethod]
    public void Open_PathOccupiedByFile_RejectsUnwritableRoot()
    {
        using TemporaryDirectory temporaryDirectory = TemporaryDirectory.Create();
        string sourceRoot = temporaryDirectory.CreateSubdirectory("source");
        string buildRoot = temporaryDirectory.CreateSubdirectory("build");
        string artifactRoot = Path.Combine(temporaryDirectory.Path, "artifact-root-file");
        File.WriteAllText(artifactRoot, "not a directory");

        ArtifactStorageException exception = Assert.ThrowsExactly<ArtifactStorageException>(
            () => ArtifactStore.Open(artifactRoot, sourceRoot, buildRoot));

        Assert.AreEqual(ArtifactStorageFailure.ArtifactRootNotWritable, exception.Failure);
    }

    [TestMethod]
    public void Open_ExplicitAbsoluteWritableRoot_CreatesEnabledStore()
    {
        using TemporaryDirectory temporaryDirectory = TemporaryDirectory.Create();
        string sourceRoot = temporaryDirectory.CreateSubdirectory("source");
        string buildRoot = temporaryDirectory.CreateSubdirectory("build");
        string artifactRoot = Path.Combine(temporaryDirectory.Path, "artifacts");

        ArtifactStore store = ArtifactStore.Open(artifactRoot, sourceRoot, buildRoot);

        Assert.IsTrue(store.IsEnabled);
        Assert.AreEqual(Path.GetFullPath(artifactRoot), store.RootPath);
        Assert.IsTrue(Directory.Exists(artifactRoot));
    }

    [TestMethod]
    public void CreateInvocationRoot_RepeatedRetryAndDataRowIdentities_CreatesUniqueContainedRoots()
    {
        using TemporaryDirectory temporaryDirectory = TemporaryDirectory.Create();
        ArtifactStore store = OpenStore(temporaryDirectory);
        InvocationIdentity[] identities =
        [
            CreateIdentity("attempt-1", "row-1"),
            CreateIdentity("attempt-1", "row-1"),
            CreateIdentity("attempt-2", "row-1"),
            CreateIdentity("attempt-1", "row-2"),
        ];

        string[] roots = identities.Select(store.CreateInvocationRoot).ToArray();

        Assert.AreEqual(roots.Length, roots.Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.IsTrue(roots.All(Directory.Exists));
        Assert.IsTrue(roots.All(path => ArtifactPath.IsContained(store.RootPath, path)));
        Assert.AreEqual(identities[0].DisplayName, identities[1].DisplayName);
        Assert.AreNotEqual(roots[0], roots[1]);
    }

    [TestMethod]
    public void CreateInvocationRoot_UnsafeDisplayIdentity_UsesBoundedDisplayNameAndOpaqueId()
    {
        using TemporaryDirectory temporaryDirectory = TemporaryDirectory.Create();
        ArtifactStore store = OpenStore(temporaryDirectory);
        InvocationIdentity identity = InvocationIdentity.Create(
            runId: "run-1",
            testIdentity: "CON:" + new string('x', 300) + "<row>",
            attemptIdentity: "attempt-1",
            dataRowIdentity: "row-1");

        string invocationRoot = store.CreateInvocationRoot(identity);
        string leaf = Path.GetFileName(invocationRoot);

        Assert.IsTrue(leaf.StartsWith(identity.DisplayName + "__", StringComparison.Ordinal));
        Assert.IsTrue(leaf.EndsWith(identity.InvocationId, StringComparison.Ordinal));
        Assert.IsTrue(leaf.Length <= 64 + 2 + identity.InvocationId.Length);
        Assert.IsTrue(ArtifactPath.IsContained(store.RootPath, invocationRoot));
    }

    [TestMethod]
    public void CreateDisabled_ConfiguredRootAndOperations_PerformsNoIo()
    {
        using TemporaryDirectory temporaryDirectory = TemporaryDirectory.Create();
        string configuredRoot = Path.Combine(temporaryDirectory.Path, "must-not-exist");
        ArtifactStore store = ArtifactStore.CreateDisabled(configuredRoot);
        InvocationIdentity identity = CreateIdentity("attempt-1", "row-1");

        ArtifactStorageException rootException = Assert.ThrowsExactly<ArtifactStorageException>(
            () => store.CreateInvocationRoot(identity));
        ArtifactStorageException checkpointException = Assert.ThrowsExactly<ArtifactStorageException>(
            () => store.CreateCheckpoint("run.json"));

        Assert.IsFalse(store.IsEnabled);
        Assert.AreEqual(ArtifactStorageFailure.DiagnosticsDisabled, rootException.Failure);
        Assert.AreEqual(ArtifactStorageFailure.DiagnosticsDisabled, checkpointException.Failure);
        Assert.IsFalse(Directory.Exists(configuredRoot));
        Assert.IsFalse(File.Exists(configuredRoot));
    }

    [TestMethod]
    public void CreateCheckpoint_HostileTraversal_PerformsNoEscapedIo()
    {
        using TemporaryDirectory temporaryDirectory = TemporaryDirectory.Create();
        ArtifactStore store = OpenStore(temporaryDirectory);
        string escapedFile = Path.Combine(temporaryDirectory.Path, "escaped.json");
        string escapedDirectory = Path.Combine(temporaryDirectory.Path, "escaped-directory");

        Assert.ThrowsExactly<ArtifactStorageException>(
            () => store.CreateCheckpoint("..", "escaped.json"));
        Assert.ThrowsExactly<ArtifactStorageException>(
            () => store.CreateCheckpoint(@"..\escaped.json"));
        Assert.ThrowsExactly<ArtifactStorageException>(
            () => store.CreateCheckpoint(@"mixed/..\escaped.json"));
        Assert.ThrowsExactly<ArtifactStorageException>(
            () => store.CreateCheckpoint(escapedFile));
        Assert.ThrowsExactly<ArtifactStorageException>(
            () => store.CreateDirectory("..", "escaped-directory"));
        Assert.ThrowsExactly<ArtifactStorageException>(
            () => store.CreateDirectory(escapedDirectory));

        Assert.IsFalse(File.Exists(escapedFile));
        Assert.IsFalse(Directory.Exists(escapedDirectory));
    }

    [TestMethod]
    public void Commit_ReplacementInProgress_NeverPublishesPartialFinalContent()
    {
        using TemporaryDirectory temporaryDirectory = TemporaryDirectory.Create();
        ArtifactStore store = OpenStore(temporaryDirectory);
        CommitText(store, "manifest.json", """{"state":"complete-old"}""");

        using ArtifactCheckpoint replacement = store.CreateCheckpoint("manifest.json");
        replacement.WriteText("""{"state":"part""");

        Assert.AreEqual("""{"state":"complete-old"}""", File.ReadAllText(replacement.FinalPath));

        replacement.WriteText("""{"state":"complete-new"}""");

        Assert.AreEqual("""{"state":"complete-old"}""", File.ReadAllText(replacement.FinalPath));

        replacement.Commit();

        Assert.AreEqual("""{"state":"complete-new"}""", File.ReadAllText(replacement.FinalPath));
        Assert.IsFalse(File.Exists(replacement.StagingPath));
    }

    [TestMethod]
    public void Dispose_UncommittedCheckpoint_LeavesIdentifiableInterruptedCheckpoint()
    {
        using TemporaryDirectory temporaryDirectory = TemporaryDirectory.Create();
        ArtifactStore store = OpenStore(temporaryDirectory);
        string stagingPath;
        string finalPath;

        using (ArtifactCheckpoint checkpoint = store.CreateCheckpoint("manifest.json"))
        {
            checkpoint.WriteText("""{"state":"interrupted""");
            stagingPath = checkpoint.StagingPath;
            finalPath = checkpoint.FinalPath;
        }

        IReadOnlyList<string> interrupted = store.EnumerateInterruptedCheckpoints();

        Assert.IsFalse(File.Exists(finalPath));
        Assert.IsTrue(File.Exists(stagingPath));
        Assert.IsTrue(Path.GetFileName(stagingPath).Contains(".checkpoint-", StringComparison.Ordinal));
        Assert.IsTrue(stagingPath.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase));
        CollectionAssert.Contains(interrupted.ToList(), stagingPath);
    }

    private static ArtifactStore OpenStore(TemporaryDirectory temporaryDirectory)
    {
        string sourceRoot = temporaryDirectory.CreateSubdirectory("source");
        string buildRoot = temporaryDirectory.CreateSubdirectory("build");
        string artifactRoot = Path.Combine(temporaryDirectory.Path, "artifacts");
        return ArtifactStore.Open(artifactRoot, sourceRoot, buildRoot);
    }

    private static InvocationIdentity CreateIdentity(string attemptIdentity, string dataRowIdentity)
    {
        return InvocationIdentity.Create(
            runId: "run-1",
            testIdentity: "Microsoft.Protocols.Tests.SmbdDataTransfer.SendSmallBytes",
            attemptIdentity: attemptIdentity,
            dataRowIdentity: dataRowIdentity);
    }

    private static void CommitText(ArtifactStore store, string fileName, string content)
    {
        using ArtifactCheckpoint checkpoint = store.CreateCheckpoint(fileName);
        checkpoint.WriteText(content);
        checkpoint.Commit();
    }
}
