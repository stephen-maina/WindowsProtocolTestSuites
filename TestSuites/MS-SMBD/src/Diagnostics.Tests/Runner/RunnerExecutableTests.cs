// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.Runner;

[TestClass]
public sealed class RunnerExecutableTests
{
    public TestContext TestContext { get; set; } = null!;

    [DataTestMethod]
    [DataRow("bootstrap", false)]
    [DataRow("stdout-open", true)]
    [DataRow("stderr-open", false)]
    [DataRow("copy", false)]
    [DataRow("copy", true)]
    [DataRow("flush", true)]
    [DataRow("append", false)]
    [DataRow("console", false)]
    [DataRow("console", true)]
    [DataRow("healthy", false)]
    [DataRow("healthy", true)]
    [DataRow("disabled", false)]
    [DataRow("result-directory", false)]
    [DataRow("invalid-config", true)]
    [DataRow("start", false)]
    [DataRow("invalid-command", false)]
    public async Task Run_StorageFailure_PreservesChildAndReportsDiagnostics(string fault, bool childFails)
    {
        string root = Environment.GetEnvironmentVariable("WPTS_CONSUMER_EVIDENCE")
            ?? Path.Combine(Environment.CurrentDirectory, ".test-scratch", "runner-evidence");
        string caseRoot = Path.Combine(root, fault + "-" + childFails + "-" + Guid.NewGuid().ToString("N"));
        string build = Path.Combine(caseRoot, "source", "bin");
        Directory.CreateDirectory(build);
        string artifacts = Path.Combine(caseRoot, "artifacts");
        string config = Path.Combine(build, "canonical.ptfconfig");
        string deployment = Path.Combine(build, "deployment.ptfconfig");
        XNamespace ns = "http://schemas.microsoft.com/windows/ProtocolsTest/2007/07/TestConfig";
        new XDocument(new XElement(ns + "TestSite",
            new XElement(ns + "Properties",
                new XElement(ns + "Property", new XAttribute("name", "Diagnostics.Enabled"),
                    new XAttribute("value", fault is "disabled" or "result-directory" ? "false" : "true")),
                new XElement(ns + "Property", new XAttribute("name", "Diagnostics.ArtifactRoot"),
                    new XAttribute("value", artifacts))))).Save(config);
        File.WriteAllText(deployment, $"<TestSite xmlns=\"{ns}\"/>");
        if (fault == "invalid-config") File.WriteAllText(config, "<invalid");
        string host = Path.Combine(AppContext.BaseDirectory, "runner-host");
        var start = new ProcessStartInfo("dotnet")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (string arg in new[]
        {
            Path.Combine(host, "Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Runner.dll"),
            fault == "invalid-command" ? "invalid" : "run",
            "--config", config, "--deployment-config", deployment,
            "--binary", typeof(RunnerExecutableTests).Assembly.Location,
            "--filter", "FullyQualifiedName~RunnerChildTests.Child"
        }) start.ArgumentList.Add(arg);
        start.Environment["DOTNET_STARTUP_HOOKS"] =
            Path.Combine(host, "Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Runner.TestSupport.dll");
        start.Environment["WPTS_RUNNER_STORAGE_FAULT"] = fault;
        start.Environment["WPTS_CHILD_MARKER"] = Path.Combine(caseRoot, "child-starts.txt");
        start.Environment["WPTS_CHILD_FAIL"] = childFails.ToString();
        start.Environment["WPTS_CHILD_EVIDENCE"] = caseRoot;
        if (fault == "start") start.Environment["PATH"] = Path.Combine(caseRoot, "missing-executables");
        File.WriteAllText(Path.Combine(caseRoot, "command.txt"),
            start.FileName + Environment.NewLine + string.Join(Environment.NewLine, start.ArgumentList));
        using Process process = Process.Start(start)!;
        Task<string> stdout = process.StandardOutput.ReadToEndAsync();
        Task<string> stderr = process.StandardError.ReadToEndAsync();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(75));
        try { await process.WaitForExitAsync(deadline.Token); }
        catch (OperationCanceledException) { process.Kill(entireProcessTree: true); Assert.Fail("Runner deadlocked draining child output."); }
        string output = await stdout;
        string error = await stderr;
        File.WriteAllText(Path.Combine(caseRoot, "stdout.txt"), output);
        File.WriteAllText(Path.Combine(caseRoot, "stderr.txt"), error);
        File.WriteAllText(Path.Combine(caseRoot, "exit.txt"), process.ExitCode.ToString());
        TestContext.WriteLine(caseRoot);
        bool shouldStart = fault is not ("start" or "invalid-command");
        int starts = File.Exists(Path.Combine(caseRoot, "child-starts.txt"))
            ? File.ReadAllLines(Path.Combine(caseRoot, "child-starts.txt")).Length : 0;
        Assert.AreEqual(shouldStart ? 1 : 0, starts, error);
        Assert.AreEqual(fault == "invalid-command" ? 2 : fault == "start" || childFails ? 1 : 0,
            process.ExitCode, error);
        if (fault is not ("healthy" or "disabled" or "console"))
            StringAssert.Contains(error, "MS-SMBD diagnostics");
        if (fault is "copy" or "flush")
        {
            StringAssert.Contains(output, "CHILD-STDOUT-END");
            StringAssert.Contains(error, "CHILD-STDERR-END");
        }
        if (fault == "healthy")
        {
            string runner = Directory.GetDirectories(artifacts).Single() + Path.DirectorySeparatorChar + "runner";
            Assert.IsTrue(File.Exists(Path.Combine(runner, "results.trx")));
            Assert.IsTrue(new FileInfo(Path.Combine(runner, "stdout.log")).Length > 0);
        }
        if (fault == "disabled") Assert.IsFalse(Directory.Exists(artifacts));
    }
}

[TestClass]
public sealed class RunnerChildTests
{
    [TestMethod]
    public void Child()
    {
        string? marker = Environment.GetEnvironmentVariable("WPTS_CHILD_MARKER");
        if (marker is null) return;
        File.AppendAllText(marker, "started" + Environment.NewLine);
        string evidence = Environment.GetEnvironmentVariable("WPTS_CHILD_EVIDENCE")!;
        File.WriteAllText(Path.Combine(evidence, "child-runtime.txt"),
            System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription);
        using (Stream stdout = Console.OpenStandardOutput())
            stdout.Write(System.Text.Encoding.UTF8.GetBytes(new string('O', 300_000) + "CHILD-STDOUT-END\n"));
        using (Stream stderr = Console.OpenStandardError())
            stderr.Write(System.Text.Encoding.UTF8.GetBytes(new string('E', 300_000) + "CHILD-STDERR-END\n"));
        if (bool.Parse(Environment.GetEnvironmentVariable("WPTS_CHILD_FAIL")!))
            Assert.Fail("Controlled protocol failure.");
    }
}
