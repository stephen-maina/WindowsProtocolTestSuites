// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Reflection;
using Microsoft.Protocols.TestSuites.FileSharing.Common.TestSuite;
using Microsoft.Protocols.TestSuites.FileSharing.SMB2.Adapter;
using Microsoft.Protocols.TestSuites.FileSharing.SMB2.TestSuite;
using Microsoft.Protocols.TestTools;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Protocols.TestSuites.FileSharing.SMB2.Tests;

[TestClass]
[DoNotParallelize]
public sealed class EncryptionPrerequisiteTests
{
    public static IEnumerable<object?[]> EncryptionScenarios()
    {
        string[] methods =
        {
            nameof(AppInstanceIdExtendedTest.AppInstanceId_Encryption),
            nameof(AppInstanceIdExtendedTest.AppInstanceId_Negative_EncryptionInInitialOpen_NoEncryptionInReOpen),
            nameof(AppInstanceIdExtendedTest.AppInstanceId_Negative_NoEncryptionInInitialOpen_EncryptionInReOpen),
            nameof(MultipleChannelExtendedTest.MultipleChannel_EncryptionOnBothChannels),
            nameof(MultipleChannelExtendedTest.MultipleChannel_Negative_EncryptionOnMainChannel),
            nameof(MultipleChannelExtendedTest.MultipleChannel_Negative_EncryptionOnAlternativeChannel),
        };

        foreach (string method in methods)
        {
            foreach (string? support in new string?[] { "false", "true", null })
            {
                yield return new object?[] { method, support };
            }
        }
    }

    [TestMethod]
    [DynamicData(nameof(EncryptionScenarios), DynamicDataSourceType.Method)]
    public void EncryptionScenario_PerShareSupport_SelectsCorrectApplicabilityPath(
        string methodName,
        string? support)
    {
        var properties = new ScenarioProperties
        {
            ["Common.MaxSmbVersionSupported"] = "Smb30",
            ["Common.MaxSmbVersionClientSupported"] = "Smb30",
            ["Common.SendSignedRequest"] = "true",
            ["Common.IsEncryptionSupported"] = "true",
            ["Common.IsLeasingSupported"] = "true",
            ["Common.IsPersistentHandlesSupported"] = "true",
            ["Common.IsMultiChannelCapable"] = "true",
            ["Common.IsGlobalEncryptDataEnabled"] = "false",
        };
        if (support is not null)
        {
            properties["Common.IsPerShareEncryptionSupported"] = support;
        }

        ITestSite site = DispatchProxy.Create<ITestSite, ScenarioSite>();
        ((ScenarioSite)site).Properties = properties;
        var config = new SMB2TestConfig(site);
        Type scenarioType = methodName.StartsWith("AppInstanceId_", StringComparison.Ordinal)
            ? typeof(AppInstanceIdExtendedTest)
            : typeof(MultipleChannelExtendedTest);
        object scenario = Activator.CreateInstance(scenarioType)!;
        typeof(CommonTestBase)
            .GetField("testConfig", BindingFlags.NonPublic | BindingFlags.Instance)!
            .SetValue(scenario, config);

        WithSite(site, () =>
        {
            TargetInvocationException invocation = Assert.ThrowsException<TargetInvocationException>(
                () => scenarioType.GetMethod(methodName)!.Invoke(scenario, null));
            if (support == "false")
            {
                Assert.IsInstanceOfType<AssertInconclusiveException>(invocation.InnerException);
                StringAssert.Contains(invocation.InnerException!.Message, "IsPerShareEncryptionSupported");
                Assert.AreEqual(0, properties.ScenarioBoundaryReads);
            }
            else
            {
                Assert.IsInstanceOfType<ScenarioBoundaryReachedException>(invocation.InnerException);
                Assert.AreEqual(1, properties.ScenarioBoundaryReads);
            }
        });
    }

    internal static void WithSite(ITestSite site, Action scenario)
    {
        // PTF's static site has no setter. Isolate and restore it without running SUT initialization.
        FieldInfo siteField = typeof(TestClassBase)
            .GetField("baseTestSite", BindingFlags.NonPublic | BindingFlags.Static)!;
        object? previousSite = siteField.GetValue(null);
        siteField.SetValue(null, site);
        try
        {
            scenario();
        }
        finally
        {
            siteField.SetValue(null, previousSite);
        }
    }

    public class ScenarioSite : DispatchProxy
    {
        private readonly IChecker checker = DispatchProxy.Create<IChecker, ScenarioChecker>();

        public NameValueCollection Properties { get; set; } = new();

        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args) =>
            targetMethod?.Name switch
            {
                "get_Properties" => Properties,
                "get_Assert" or "get_Assume" => checker,
                _ => throw new NotSupportedException($"Unexpected PTF operation: {targetMethod?.Name}"),
            };
    }

    public class ScenarioChecker : DispatchProxy
    {
        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
        {
            if (targetMethod?.Name == "Inconclusive")
            {
                throw new AssertInconclusiveException((string)args![0]!);
            }

            throw new NotSupportedException($"Unexpected checker operation: {targetMethod?.Name}");
        }
    }

    private sealed class ScenarioProperties : NameValueCollection
    {
        public int ScenarioBoundaryReads { get; private set; }

        public override string? Get(string? name)
        {
            if (name == "Common.SutComputerName")
            {
                ScenarioBoundaryReads++;
                throw new ScenarioBoundaryReachedException();
            }

            return base.Get(name);
        }
    }

    private sealed class ScenarioBoundaryReachedException : Exception
    {
    }
}
