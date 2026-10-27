// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;
using Microsoft.Protocols.TestTools;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using FsaBase = Microsoft.Protocols.TestSuites.FileSharing.FSA.TestSuite.PtfTestClassBase;
using Smb2ModelBase = Microsoft.Protocols.TestSuites.FileSharing.SMB2Model.TestSuite.PtfTestClassBase;

namespace Microsoft.Protocols.TestSuites.FileSharing.Diagnostics.Tests;

public interface ILifecycleAdapter : IAdapter { }

public sealed class LifecycleAdapter : ManagedAdapterBase, ILifecycleAdapter
{
    public override void Initialize(ITestSite site)
    {
        base.Initialize(site);
        if (FixtureState.Scenario == "acquisition") throw new InvalidOperationException("PRIMARY-ACQUISITION");
    }

    public override void Reset()
    {
        FixtureState.Record("adapter-reset");
        if (FixtureState.Scenario is "reset" or "primary-reset")
            throw new InvalidOperationException("PRIMARY-RESET");
    }
}

internal static class FixtureState
{
    internal static string Scenario => Environment.GetEnvironmentVariable("WPTS_FILESERVER_SCENARIO")!;
    internal static string Root => Environment.GetEnvironmentVariable("WPTS_FILESERVER_CASE")!;
    internal static void Record(string value) => File.AppendAllText(Path.Combine(Root, "events.txt"), value + "\n");

    internal static void Initialize(TestContext context)
    {
        TestClassBase.Initialize(context, "FileServerLifecycleFixture");
        var p = TestClassBase.BaseTestSite.Properties;
        p["Common.Diagnostics.Enabled"] = Scenario == "disabled" ? "false" : "true";
        p["Common.Diagnostics.ArtifactRoot"] = Path.Combine(Root, "artifacts");
        p["Common.Diagnostics.Capture.Provider"] = "Automatic";
        p["Common.Diagnostics.Capture.ToolPath"] = "";
        p["Common.Diagnostics.Capture.Targets"] = "controlled-no-native";
        p["Common.Diagnostics.Capture.TrafficScope"] = "RdmaFocused";
        p["Common.Diagnostics.Capture.StartTimeout"] = "00:00:05";
        p["Common.Diagnostics.Capture.StopTimeout"] = "00:00:05";
        p["Common.Diagnostics.Capture.MaxDuration"] = "00:01:00";
        p["Common.Diagnostics.Capture.MaxBytes"] = "1048576";
        p["Common.Diagnostics.Capture.Format"] = "Native";
        p["Common.Diagnostics.Logs.NativeEnabled"] = "false";
        p["Common.Diagnostics.Retention"] = "KeepAll";
        p["Common.DriverPlatform"] = "Linux";
        p["Common.Platform"] = "Linux";
        p["Common.SutLog.Enabled"] = "false";
    }

    internal static void AfterAcquisition()
    {
        Record("acquired");
        if (Scenario == "setup") throw new InvalidOperationException("PRIMARY-SETUP");
    }

    internal static void Body()
    {
        Record("body");
        if (Scenario is "primary" or "primary-reset") throw new InvalidOperationException("PRIMARY-PROTOCOL");
    }

    internal static void CleanupClass()
    {
        Record("class-cleanup");
        // Snapshot before PTF class cleanup can close a leaked route.
        string root = Path.Combine(Root, "artifacts");
        if (Directory.Exists(root))
            foreach (string manifest in Directory.GetFiles(root, "manifest.json", SearchOption.AllDirectories))
                File.Copy(manifest, Path.Combine(Root, "observed-manifest.json"), overwrite: true);
        TestClassBase.Cleanup();
    }
}

[TestClass]
public sealed class FsaLifecycleFixture : FsaBase
{
    private ILifecycleAdapter adapter = null!;
    [ClassInitialize] public static void ClassInitialize(TestContext context) => FixtureState.Initialize(context);
    [ClassCleanup] public static void ClassCleanup() => FixtureState.CleanupClass();
    protected override void TestInitialize()
    {
        InitializeTestManager();
        adapter = (ILifecycleAdapter)GetAdapter(typeof(ILifecycleAdapter));
        FixtureState.AfterAcquisition();
    }
    protected override void TestCleanup()
    {
        _ = adapter.GetType(); // Generated unsubscribe likewise fails after acquisition leaves null.
        base.TestCleanup();
        CleanupTestManager();
        if (FixtureState.Scenario == "duplicate") CleanupTestManager();
        FixtureState.Record("cleanup-complete");
    }
    [TestMethod] public void Exercise() => FixtureState.Body();
}

[TestClass]
public sealed class FsaModelLifecycleFixture : FsaBase
{
    private ILifecycleAdapter adapter = null!;
    [ClassInitialize] public static void ClassInitialize(TestContext context) => FixtureState.Initialize(context);
    [ClassCleanup] public static void ClassCleanup() => FixtureState.CleanupClass();
    protected override void TestInitialize()
    {
        InitializeTestManager();
        adapter = (ILifecycleAdapter)GetAdapter(typeof(ILifecycleAdapter));
        FixtureState.AfterAcquisition();
    }
    protected override void TestCleanup()
    {
        _ = adapter.GetType();
        base.TestCleanup();
        CleanupTestManager();
        if (FixtureState.Scenario == "duplicate") CleanupTestManager();
        FixtureState.Record("cleanup-complete");
    }
    [TestMethod] public void Exercise() => FixtureState.Body();
}

[TestClass]
public sealed class Smb2ModelLifecycleFixture : Smb2ModelBase
{
    private ILifecycleAdapter adapter = null!;
    [ClassInitialize] public static void ClassInitialize(TestContext context) => FixtureState.Initialize(context);
    [ClassCleanup] public static void ClassCleanup() => FixtureState.CleanupClass();
    protected override void TestInitialize()
    {
        InitializeTestManager();
        adapter = (ILifecycleAdapter)GetAdapter(typeof(ILifecycleAdapter));
        FixtureState.AfterAcquisition();
    }
    protected override void TestCleanup()
    {
        _ = adapter.GetType();
        base.TestCleanup();
        CleanupTestManager();
        if (FixtureState.Scenario == "duplicate") CleanupTestManager();
        FixtureState.Record("cleanup-complete");
    }
    [TestMethod] public void Exercise() => FixtureState.Body();
}
