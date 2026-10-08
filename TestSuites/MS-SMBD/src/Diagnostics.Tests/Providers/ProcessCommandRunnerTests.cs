// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Protocols.TestSuites.Diagnostics.Providers;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.Providers;

[TestClass]
public sealed class ProcessCommandRunnerTests
{
    [TestMethod]
    public async Task RunAsync_TimeoutIsBoundedAndTerminatesSpawnedProcess()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Inconclusive(
                "The concrete netsh command runner is qualified on Windows.");
        }

        string executablePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            "ping.exe");
        if (!File.Exists(executablePath))
        {
            Assert.Inconclusive(
                "The Windows ping executable is unavailable.");
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = executablePath,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        startInfo.ArgumentList.Add("127.0.0.1");
        startInfo.ArgumentList.Add("-n");
        startInfo.ArgumentList.Add("30");
        var stopwatch = Stopwatch.StartNew();

        ProcessCommandResult result = await new ProcessCommandRunner().RunAsync(
            startInfo,
            TimeSpan.FromMilliseconds(100),
            CancellationToken.None);
        stopwatch.Stop();

        Assert.AreEqual(ProcessCommandStatus.TimedOut, result.Status);
        Assert.IsTrue(result.SpawnedProcessTerminated);
        Assert.IsTrue(
            stopwatch.Elapsed < TimeSpan.FromSeconds(5),
            $"The command runner exceeded its bounded timeout path: {stopwatch.Elapsed}.");
    }
}
