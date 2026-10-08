// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.Protocols.TestSuites.Diagnostics.Identity;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.Identity;

[TestClass]
public sealed class InvocationIdentityTests
{
    [TestMethod]
    public void Create_DistinctLogicalIdentityParts_PreservesEveryPart()
    {
        // Act
        InvocationIdentity identity = InvocationIdentity.Create(
            runId: "runner-run-42",
            testIdentity: "Microsoft.Protocols.Tests.SmbdDataTransfer.SendSmallBytes",
            attemptIdentity: "retry-2",
            dataRowIdentity: "row-3");

        // Assert
        Assert.AreEqual("runner-run-42", identity.RunId);
        Assert.AreEqual(
            "Microsoft.Protocols.Tests.SmbdDataTransfer.SendSmallBytes",
            identity.TestIdentity);
        Assert.AreEqual("retry-2", identity.AttemptIdentity);
        Assert.AreEqual("row-3", identity.DataRowIdentity);
        Assert.IsFalse(string.IsNullOrWhiteSpace(identity.InvocationId));
    }

    [TestMethod]
    public void Create_SameLogicalIdentityTwice_AssignsNewOpaqueInvocationId()
    {
        // Arrange and act
        InvocationIdentity first = CreateIdentity();
        InvocationIdentity second = CreateIdentity();

        // Assert
        Assert.AreNotEqual(first.InvocationId, second.InvocationId);
        Assert.AreEqual(first.RunId, second.RunId);
        Assert.AreEqual(first.TestIdentity, second.TestIdentity);
        Assert.AreEqual(first.AttemptIdentity, second.AttemptIdentity);
        Assert.AreEqual(first.DataRowIdentity, second.DataRowIdentity);
    }

    [TestMethod]
    public void Create_LongUnsafeReservedTestName_ProducesBoundedSafeDisplayName()
    {
        // Arrange
        string unsafeName = "CON:" + new string('x', 300) + "<row>|?*";

        // Act
        InvocationIdentity identity = InvocationIdentity.Create(
            runId: "run",
            testIdentity: unsafeName,
            attemptIdentity: "attempt",
            dataRowIdentity: "row");

        // Assert
        Assert.IsTrue(identity.DisplayName.Length is > 0 and <= 64);
        Assert.AreEqual(-1, identity.DisplayName.IndexOfAny(['<', '>', ':', '"', '/', '\\', '|', '?', '*']));
        Assert.IsFalse(string.Equals("CON", identity.DisplayName, StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(identity.DisplayName.EndsWith(".", StringComparison.Ordinal));
        Assert.IsFalse(identity.DisplayName.EndsWith(" ", StringComparison.Ordinal));
    }

    [TestMethod]
    public void Create_SameTestNameTwice_UsesDisplayNameOnlyForPresentation()
    {
        // Arrange and act
        InvocationIdentity first = CreateIdentity();
        InvocationIdentity second = CreateIdentity();

        // Assert
        Assert.AreEqual(first.DisplayName, second.DisplayName);
        Assert.AreNotEqual(first.InvocationId, second.InvocationId);
        Assert.IsFalse(
            first.InvocationId.Contains(first.DisplayName, StringComparison.OrdinalIgnoreCase),
            "The opaque invocation ID must not be derived from the display name.");
    }

    private static InvocationIdentity CreateIdentity()
    {
        return InvocationIdentity.Create(
            runId: "runner-run-42",
            testIdentity: "Microsoft.Protocols.Tests.SmbdDataTransfer.SendSmallBytes",
            attemptIdentity: "retry-2",
            dataRowIdentity: "row-3");
    }
}
