// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Protocols.TestSuites.FileSharing.Diagnostics.Tests;

[TestClass]
public sealed class FileServerLifecycleTests
{
    public TestContext TestContext { get; set; } = null!;

    [DataTestMethod]
    [DataRow("FsaLifecycleFixture", "acquisition")]
    [DataRow("FsaModelLifecycleFixture", "acquisition")]
    [DataRow("Smb2ModelLifecycleFixture", "acquisition")]
    [DataRow("Smb2ModelLifecycleFixture", "setup")]
    [DataRow("FsaLifecycleFixture", "reset")]
    [DataRow("FsaModelLifecycleFixture", "reset")]
    [DataRow("Smb2ModelLifecycleFixture", "reset")]
    [DataRow("Smb2ModelLifecycleFixture", "primary-reset")]
    [DataRow("Smb2ModelLifecycleFixture", "primary")]
    [DataRow("FsaLifecycleFixture", "normal")]
    [DataRow("FsaModelLifecycleFixture", "normal")]
    [DataRow("Smb2ModelLifecycleFixture", "normal")]
    [DataRow("Smb2ModelLifecycleFixture", "duplicate")]
    [DataRow("Smb2ModelLifecycleFixture", "disabled")]
    public async Task Cleanup_ActualMstestPtfLifecycle_FinalizesWithoutMaskingFailure(string fixture, string scenario)
    {
        string root = Environment.GetEnvironmentVariable("WPTS_CONSUMER_EVIDENCE")
            ?? Path.Combine(Path.GetTempPath(), "wpts-fileserver-lifecycle");
        string caseRoot = Path.Combine(root, fixture + "-" + scenario + "-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(caseRoot);
        var start = new ProcessStartInfo("dotnet")
        {
            RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false,
            WorkingDirectory = AppContext.BaseDirectory,
        };
        foreach (string arg in new[] { "test", typeof(FileServerLifecycleTests).Assembly.Location,
            "--filter", $"FullyQualifiedName~{fixture}.Exercise", "--logger", "trx;LogFileName=child.trx",
            "--results-directory", caseRoot })
            start.ArgumentList.Add(arg);
        start.Environment["WPTS_FILESERVER_SCENARIO"] = scenario;
        start.Environment["WPTS_FILESERVER_CASE"] = caseRoot;
        File.WriteAllText(Path.Combine(caseRoot, "command.txt"), "dotnet\n" + string.Join("\n", start.ArgumentList));
        using Process process = Process.Start(start)!;
        Task<string> output = process.StandardOutput.ReadToEndAsync();
        Task<string> error = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        try { await process.WaitForExitAsync(timeout.Token); }
        catch (OperationCanceledException) { process.Kill(entireProcessTree: true); Assert.Fail("Lifecycle fixture timed out."); }
        File.WriteAllText(Path.Combine(caseRoot, "stdout.txt"), await output);
        File.WriteAllText(Path.Combine(caseRoot, "stderr.txt"), await error);
        File.WriteAllText(Path.Combine(caseRoot, "exit.txt"), process.ExitCode.ToString());
        TestContext.WriteLine(caseRoot);
        string trxText = File.ReadAllText(Path.Combine(caseRoot, "child.trx"));
        XDocument trx = XDocument.Parse(trxText);
        XElement result = trx.Descendants().Single(e => e.Name.LocalName == "UnitTestResult");
        bool fails = scenario is "acquisition" or "setup" or "reset" or "primary" or "primary-reset";
        Assert.AreEqual(fails ? 1 : 0, process.ExitCode, trxText);
        Assert.AreEqual(fails ? "Failed" : "Passed", result.Attribute("outcome")!.Value);
        if (fails)
            StringAssert.Contains(trxText, scenario.StartsWith("primary", StringComparison.Ordinal)
                ? "PRIMARY-PROTOCOL" : "PRIMARY-" + scenario.ToUpperInvariant());
        string events = File.ReadAllText(Path.Combine(caseRoot, "events.txt"));
        Assert.AreEqual(1, events.Split('\n').Count(line => line == "class-cleanup"));
        Assert.AreEqual(scenario == "acquisition" ? 0 : 1,
            events.Split('\n').Count(line => line == "adapter-reset"), "PTF cleanup must dispatch only once.");
        Assert.AreEqual(scenario is "acquisition" or "reset" or "primary-reset" ? 0 : 1,
            events.Split('\n').Count(line => line == "cleanup-complete"));
        if (scenario == "disabled")
        {
            Assert.IsFalse(Directory.Exists(Path.Combine(caseRoot, "artifacts")));
            return;
        }
        string manifestPath = Path.Combine(caseRoot, "observed-manifest.json");
        Assert.IsTrue(File.Exists(manifestPath), "No invocation manifest; lifecycle did not start.");
        using JsonDocument manifest = JsonDocument.Parse(File.ReadAllText(manifestPath));
        // Per-test disposal finalizes artifacts, not the runner's authoritative TRX outcome.
        Assert.AreEqual("Provisional", manifest.RootElement.GetProperty("completionState").GetString());
        // A setup/protocol failure does not by itself make a successfully completed cleanup fail.
        Assert.AreEqual(scenario is "acquisition" or "reset" or "primary-reset" ? "Failed" : "Complete",
            manifest.RootElement.GetProperty("cleanupStatus").GetString());
        Assert.AreEqual("Complete", manifest.RootElement.GetProperty("finalizationStatus").GetString());
    }
}
