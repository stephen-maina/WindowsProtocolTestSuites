// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Reflection;
using Microsoft.Protocols.TestSuites.FileSharing.SMB2.TestSuite;
using Microsoft.Protocols.TestTools;
using Microsoft.Protocols.TestTools.StackSdk.FileAccessService.Smb2;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Protocols.TestSuites.FileSharing.SMB2.Tests;

[TestClass]
[DoNotParallelize]
public sealed class SigningSelectionTests
{
    public static IEnumerable<object?[]> SigningSelections()
    {
        SigningAlgorithm[] offeredAlgorithms =
        {
            SigningAlgorithm.HMAC_SHA256,
            SigningAlgorithm.AES_CMAC,
            SigningAlgorithm.AES_GMAC,
        };
        SigningAlgorithm?[] selectedAlgorithms =
        {
            null,
            SigningAlgorithm.HMAC_SHA256,
            SigningAlgorithm.AES_CMAC,
            SigningAlgorithm.AES_GMAC,
            (SigningAlgorithm)byte.MaxValue,
        };
        foreach (SigningAlgorithm offered in offeredAlgorithms)
        {
            foreach (SigningAlgorithm? selected in selectedAlgorithms)
            {
                yield return new object?[] { offered, selected };
            }
        }
    }

    [TestMethod]
    [DynamicData(nameof(SigningSelections), DynamicDataSourceType.Method)]
    public void WrongSessionKeySigningSelection_ResponseSelection_FailsInvalidAndSkipsOnlyFallback(
        SigningAlgorithm offered,
        SigningAlgorithm? selected)
    {
        ITestSite site = DispatchProxy.Create<ITestSite, SigningSite>();
        var scenario = new Signing();
        MethodInfo check = typeof(Signing).GetMethod(
            "CheckWrongSessionKeySigningSelection",
            BindingFlags.NonPublic | BindingFlags.Instance)!;
        bool invalidSelection = selected.HasValue
            && selected != offered
            && selected != SigningAlgorithm.AES_CMAC;
        bool unavailableCase = !invalidSelection
            && selected != offered
            && offered != SigningAlgorithm.AES_CMAC;

        EncryptionPrerequisiteTests.WithSite(site, () =>
        {
            Action invoke = () => check.Invoke(scenario, new object?[] { offered, selected });
            if (invalidSelection || unavailableCase)
            {
                TargetInvocationException invocation = Assert.ThrowsException<TargetInvocationException>(invoke);
                if (invalidSelection)
                {
                    Assert.IsInstanceOfType<AssertFailedException>(
                        invocation.InnerException,
                        "An explicit unoffered non-fallback algorithm must fail, never become inconclusive.");
                }
                else
                {
                    Assert.IsInstanceOfType<AssertInconclusiveException>(invocation.InnerException);
                    StringAssert.Contains(invocation.InnerException!.Message, "signing algorithm");
                }
            }
            else
            {
                invoke();
            }
        });
    }

    public class SigningSite : EncryptionPrerequisiteTests.ScenarioSite
    {
        private readonly IChecker checker = DispatchProxy.Create<IChecker, SigningChecker>();

        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args) =>
            targetMethod?.Name == "get_Assert" ? checker : base.Invoke(targetMethod, args);
    }

    public class SigningChecker : DispatchProxy
    {
        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
        {
            switch (targetMethod?.Name)
            {
                case "IsTrue":
                    Assert.IsTrue((bool)args![0]!, (string)args[1]!);
                    return null;
                case "Inconclusive":
                    throw new AssertInconclusiveException((string)args![0]!);
                default:
                    throw new NotSupportedException($"Unexpected checker operation: {targetMethod?.Name}");
            }
        }
    }
}
