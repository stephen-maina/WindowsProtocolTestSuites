// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Specialized;
using System.IO;
using Microsoft.Protocols.TestSuites.Diagnostics.Identity;
using Microsoft.Protocols.TestSuites.Diagnostics.Ptf;
using Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Ptf;
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
