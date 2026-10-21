// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Specialized;
using System.IO;
using Microsoft.Protocols.TestSuites.Diagnostics.Identity;
using Microsoft.Protocols.TestSuites.Diagnostics.Ptf;
using Microsoft.Protocols.TestSuites.Diagnostics.Storage;
using Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Ptf;
using Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.TestSupport;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.Ptf;

[TestClass]
public sealed class PtfSessionLayoutTests
{
    private static readonly DateTimeOffset Start =
        new(2026, 10, 8, 9, 30, 15, TimeSpan.Zero);

    [TestMethod]
    public void ResolveSessionName_Empty_UsesTimestampedDefaultAndIsStablePerProcess()
    {
        string first = PtfSessionLayout.ResolveSessionName(string.Empty, Start);
        string second = PtfSessionLayout.ResolveSessionName(
            string.Empty,
            Start.AddMinutes(5));

        Assert.IsTrue(
            System.Text.RegularExpressions.Regex.IsMatch(
                first,
                @"^session-\d{8}-\d{6}$"),
            first);
        Assert.AreEqual(first, second);
    }

    [TestMethod]
    public void ResolveSessionName_TokenAndUnsafeCharacters_AreExpandedAndSanitized()
    {
        string name = PtfSessionLayout.ResolveSessionName(
            @"nightly-{timestamp}\..\x",
            Start);

        Assert.AreEqual("nightly-20261008-093015_.._x", name);
        Assert.IsFalse(name.Contains('\\'));
    }

    [TestMethod]
    public void PrepareTestsRoot_CreatesSessionFolderWithMarker()
    {
        string root = NewRoot();
        try
        {
            var properties = new NameValueCollection
            {
                [PtfSessionLayout.SessionNameProperty] = "layout-basic",
            };

            string testsRoot = PtfSessionLayout.PrepareTestsRoot(root, properties, Start);

            Assert.AreEqual(
                Path.Combine(root, "layout-basic", "tests"),
                testsRoot);
            Assert.IsTrue(
                File.Exists(
                    Path.Combine(root, "layout-basic", PtfSessionLayout.MarkerFileName)));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [DataTestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public void PrepareTestsRoot_SessionReparsePoint_RejectsBeforeExternalMarkerMutation(
        bool existingMarker)
    {
        using TemporaryDirectory root = TemporaryDirectory.Create();
        using TemporaryDirectory outside = TemporaryDirectory.Create();
        const string SessionName = "linked-session";
        string link = Path.Combine(root.Path, SessionName);
        string marker = Path.Combine(outside.Path, PtfSessionLayout.MarkerFileName);
        DateTime originalStamp = Start.AddDays(-1).UtcDateTime;
        if (existingMarker)
        {
            File.WriteAllText(marker, "external-marker");
            File.SetLastWriteTimeUtc(marker, originalStamp);
        }

        if (!ReparsePointTestSupport.TryCreateDirectoryLink(link, outside.Path))
        {
            Assert.Inconclusive("The session containment regression requires a directory reparse point.");
        }

        try
        {
            var properties = new NameValueCollection
            {
                [PtfSessionLayout.SessionNameProperty] = SessionName,
            };
            ArtifactStorageException? failure = null;
            try
            {
                PtfSessionLayout.PrepareTestsRoot(root.Path, properties, Start);
            }
            catch (ArtifactStorageException exception)
            {
                failure = exception;
            }

            Assert.AreEqual(existingMarker, File.Exists(marker), "No external marker may be created.");
            if (existingMarker)
            {
                Assert.AreEqual("external-marker", File.ReadAllText(marker));
                Assert.AreEqual(originalStamp, File.GetLastWriteTimeUtc(marker), "No external marker may be touched.");
            }

            Assert.IsNotNull(failure, "The session reparse point must be rejected explicitly.");
            Assert.AreEqual(ArtifactStorageFailure.ReparsePointNotAllowed, failure.Failure);
        }
        finally
        {
            ReparsePointTestSupport.DeleteDirectoryLink(link);
        }
    }

    [TestMethod]
    public void PrepareTestsRoot_RepeatedSafeSession_PreservesMarkerAndRefreshesRetentionStamp()
    {
        using TemporaryDirectory root = TemporaryDirectory.Create();
        var properties = new NameValueCollection
        {
            [PtfSessionLayout.SessionNameProperty] = "repeated-safe-session",
        };
        string first = PtfSessionLayout.PrepareTestsRoot(root.Path, properties, Start);
        string marker = Path.Combine(Path.GetDirectoryName(first)!, PtfSessionLayout.MarkerFileName);
        string content = File.ReadAllText(marker);

        string second = PtfSessionLayout.PrepareTestsRoot(root.Path, properties, Start.AddMinutes(5));

        Assert.AreEqual(first, second);
        Assert.AreEqual(content, File.ReadAllText(marker));
        Assert.AreEqual(Start.AddMinutes(5).UtcDateTime, File.GetLastWriteTimeUtc(marker));
    }

    [TestMethod]
    public void PruneOldSessions_KeepsNewestAndCurrentAndIgnoresUnmarkedFolders()
    {
        string root = NewRoot();
        try
        {
            CreateSession(root, "old-1", Start.AddHours(-3));
            CreateSession(root, "old-2", Start.AddHours(-2));
            CreateSession(root, "recent", Start.AddHours(-1));
            CreateSession(root, "current", Start);
            Directory.CreateDirectory(Path.Combine(root, "not-a-session"));

            PtfSessionLayout.PruneOldSessions(root, "current", maxSessions: 2);

            Assert.IsTrue(Directory.Exists(Path.Combine(root, "current")));
            Assert.IsTrue(Directory.Exists(Path.Combine(root, "recent")));
            Assert.IsFalse(Directory.Exists(Path.Combine(root, "old-1")));
            Assert.IsFalse(Directory.Exists(Path.Combine(root, "old-2")));
            Assert.IsTrue(Directory.Exists(Path.Combine(root, "not-a-session")));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [TestMethod]
    [DataRow(null, 0)]
    [DataRow("", 0)]
    [DataRow("abc", 0)]
    [DataRow("-3", 0)]
    [DataRow("5", 5)]
    public void ReadMaxSessions_InvalidOrAbsent_MeansKeepAll(string? value, int expected)
    {
        Assert.AreEqual(expected, PtfSessionLayout.ReadMaxSessions(value));
    }

    [TestMethod]
    public void InvocationIdentity_LongTestName_KeepsClassAndMethodTail()
    {
        InvocationIdentity identity = InvocationIdentity.Create(
            "ptf",
            "Microsoft.Protocol.TestSuites.Smbd.TestSuite.SmbdNegotiate.BVT_SmbdNegotiate_Basic",
            "initial",
            string.Empty);

        Assert.IsTrue(identity.DisplayName.Length <= 64);
        Assert.IsTrue(
            identity.DisplayName.EndsWith("SmbdNegotiate.BVT_SmbdNegotiate_Basic", StringComparison.Ordinal),
            identity.DisplayName);
    }

    private static string NewRoot()
    {
        string root = Path.Combine(
            Path.GetTempPath(),
            "wpts-session-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return root;
    }

    private static void CreateSession(string root, string name, DateTimeOffset stamp)
    {
        string directory = Path.Combine(root, name);
        Directory.CreateDirectory(directory);
        string marker = Path.Combine(directory, PtfSessionLayout.MarkerFileName);
        File.WriteAllText(marker, name);
        File.SetLastWriteTimeUtc(marker, stamp.UtcDateTime);
    }
}
