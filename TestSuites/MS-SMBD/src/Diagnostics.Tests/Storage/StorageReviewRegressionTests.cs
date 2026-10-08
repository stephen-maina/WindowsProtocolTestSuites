// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Microsoft.Protocols.TestSuites.Diagnostics.Identity;
using Microsoft.Protocols.TestSuites.Diagnostics.Storage;
using Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.TestSupport;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.Storage;

[TestClass]
public sealed class StorageReviewRegressionTests
{
    [TestMethod]
    public void Open_ExtendedNamespaceRoot_RejectsAliasBeforeFileSystemAccess_Issue64410323()
    {
        using TemporaryDirectory source = TemporaryDirectory.Create();
        using TemporaryDirectory buildOutput = TemporaryDirectory.Create();
        string physicalRoot = Path.Combine(source.Path, "artifacts");
        string extendedRoot = $@"\\?\{physicalRoot}";

        Assert.ThrowsExactly<ArtifactStorageException>(
            () => ArtifactStore.Open(extendedRoot, source.Path, buildOutput.Path));

        Assert.IsFalse(Directory.Exists(physicalRoot));
    }

    [TestMethod]
    public void CreateCheckpoint_IntermediateReparsePoint_RejectsEscape_Issue64410323()
    {
        using TemporaryDirectory root = TemporaryDirectory.Create();
        using TemporaryDirectory source = TemporaryDirectory.Create();
        using TemporaryDirectory buildOutput = TemporaryDirectory.Create();
        using TemporaryDirectory outside = TemporaryDirectory.Create();
        using ArtifactStore store = ArtifactStore.Open(root.Path, source.Path, buildOutput.Path);
        using ArtifactInvocation invocation = store.CreateInvocation(CreateIdentity());
        string linkPath = Path.Combine(invocation.DirectoryPath, "linked");

        if (!ReparsePointTestSupport.TryCreateDirectoryLink(linkPath, outside.Path))
        {
            Assert.Inconclusive(
                "This host cannot create the directory reparse point required by the containment regression.");
        }

        try
        {
            Assert.ThrowsExactly<ArtifactStorageException>(
                () => invocation.CreateCheckpoint("linked", "escape.log"));
        }
        finally
        {
            ReparsePointTestSupport.DeleteDirectoryLink(linkPath);
        }
    }

    [TestMethod]
    public void CreateDirectory_IntermediateReparsePoint_RejectsEscapeWithoutExternalMutation_Issue64410323()
    {
        using TemporaryDirectory root = TemporaryDirectory.Create();
        using TemporaryDirectory source = TemporaryDirectory.Create();
        using TemporaryDirectory buildOutput = TemporaryDirectory.Create();
        using TemporaryDirectory outside = TemporaryDirectory.Create();
        using ArtifactStore store = ArtifactStore.Open(root.Path, source.Path, buildOutput.Path);
        string linkPath = Path.Combine(root.Path, "linked");
        string escapedDirectory = Path.Combine(outside.Path, "child");

        if (!ReparsePointTestSupport.TryCreateDirectoryLink(linkPath, outside.Path))
        {
            Assert.Inconclusive(
                "This host cannot create the directory reparse point required by the containment regression.");
        }

        try
        {
            Assert.ThrowsExactly<ArtifactStorageException>(
                () => store.CreateDirectory("linked", "child"));
            Assert.IsFalse(
                Directory.Exists(escapedDirectory),
                "A rejected directory request must not mutate the reparse-point target.");
        }
        finally
        {
            ReparsePointTestSupport.DeleteDirectoryLink(linkPath);
        }
    }

    [TestMethod]
    public void EnumerateInterruptedCheckpoints_FileReparsePoint_RejectsStoreAndInvocationWithoutExternalMutation_B01()
    {
        using TemporaryDirectory root = TemporaryDirectory.Create();
        using TemporaryDirectory source = TemporaryDirectory.Create();
        using TemporaryDirectory buildOutput = TemporaryDirectory.Create();
        using TemporaryDirectory outside = TemporaryDirectory.Create();
        using ArtifactStore store = ArtifactStore.Open(root.Path, source.Path, buildOutput.Path);
        using ArtifactInvocation invocation = store.CreateInvocation(CreateIdentity());
        string ordinaryPath = Path.Combine(invocation.DirectoryPath, ".checkpoint-ordinary.tmp");
        string externalTargetPath = Path.Combine(outside.Path, "external-target.txt");
        string linkPath = Path.Combine(invocation.DirectoryPath, ".checkpoint-linked.tmp");
        const string ExternalContent = "external-content-must-not-change";
        File.WriteAllText(ordinaryPath, "ordinary-interrupted-checkpoint");
        File.WriteAllText(externalTargetPath, ExternalContent);

        if (!TryCreateFileLink(linkPath, externalTargetPath))
        {
            Assert.Inconclusive(
                "This host cannot create the file reparse point required by the enumeration regression.");
        }

        try
        {
            Assert.ThrowsExactly<ArtifactStorageException>(
                () => store.EnumerateInterruptedCheckpoints());
            Assert.ThrowsExactly<ArtifactStorageException>(
                () => invocation.FindInterruptedCheckpoints());
            Assert.AreEqual(
                ExternalContent,
                File.ReadAllText(externalTargetPath),
                "Rejected enumeration must not mutate the reparse-point target.");
        }
        finally
        {
            File.Delete(linkPath);
        }

        CollectionAssert.AreEqual(
            new[] { ordinaryPath },
            store.EnumerateInterruptedCheckpoints().ToArray());
        CollectionAssert.AreEqual(
            new[] { ordinaryPath },
            invocation.FindInterruptedCheckpoints().ToArray());
    }

    [TestMethod]
    [DoNotParallelize]
    public void TryCreateFileLink_CommandMetacharacterPath_DoesNotInvokeCommandProcessor_B01()
    {
        using TemporaryDirectory root = TemporaryDirectory.Create();
        using TemporaryDirectory outside = TemporaryDirectory.Create();
        using TemporaryDirectory commandProbe = TemporaryDirectory.Create();
        string linkDirectory = root.CreateSubdirectory("literal&path");
        string targetDirectory = outside.CreateSubdirectory("literal&target");
        string linkPath = Path.Combine(linkDirectory, "linked.txt");
        string targetPath = Path.Combine(targetDirectory, "target.txt");
        string commandProcessor = Path.Combine(commandProbe.Path, "sentinel.cmd");
        string commandMarker = Path.Combine(commandProbe.Path, "command-processor-invoked.txt");
        string? originalCommandProcessor =
            Environment.GetEnvironmentVariable("ComSpec");
        File.WriteAllText(targetPath, "target-content");
        File.WriteAllText(
            commandProcessor,
            $"@echo invoked>\"{commandMarker}\"{Environment.NewLine}@exit /b 1");

        try
        {
            Environment.SetEnvironmentVariable("ComSpec", commandProcessor);

            bool linkCreated = TryCreateFileLink(
                linkPath,
                targetPath,
                forceWslFallback: true);
            Assert.IsFalse(
                File.Exists(commandMarker),
                "File-link fallback must not interpret legitimate paths through a command processor.");
            if (!linkCreated)
            {
                Assert.Inconclusive(
                    "This host does not provide the WSL file-link fallback required by the command-safety regression.");
            }

            Assert.IsTrue(File.Exists(linkPath));
            Assert.IsTrue(
                (File.GetAttributes(linkPath) & FileAttributes.ReparsePoint) != 0);
            Assert.AreEqual("target-content", File.ReadAllText(targetPath));
        }
        finally
        {
            Environment.SetEnvironmentVariable(
                "ComSpec",
                originalCommandProcessor);
            if (File.Exists(linkPath))
            {
                File.Delete(linkPath);
            }
        }
    }

    private static InvocationIdentity CreateIdentity()
    {
        return InvocationIdentity.Create(
            "run-review",
            "StorageReviewRegressionTests.CreateCheckpoint",
            "attempt-1",
            "row-0");
    }

    private static bool TryCreateFileLink(
        string linkPath,
        string targetPath,
        bool forceWslFallback = false)
    {
        if (!forceWslFallback)
        {
            try
            {
                File.CreateSymbolicLink(linkPath, targetPath);
                return true;
            }
            catch (Exception exception) when (
                exception is UnauthorizedAccessException or
                IOException or
                PlatformNotSupportedException)
            {
            }
        }

        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        return TryCreateWslFileLink(linkPath, targetPath);
    }

    private static bool TryCreateWslFileLink(string linkPath, string targetPath)
    {
        try
        {
            string? wslLinkPath = TryConvertToWslPath(linkPath);
            string? wslTargetPath = TryConvertToWslPath(targetPath);
            if (wslLinkPath is null || wslTargetPath is null)
            {
                return false;
            }

            var startInfo = new ProcessStartInfo("wsl.exe")
            {
                CreateNoWindow = true,
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                UseShellExecute = false,
            };
            startInfo.ArgumentList.Add("-e");
            startInfo.ArgumentList.Add("ln");
            startInfo.ArgumentList.Add("-s");
            startInfo.ArgumentList.Add("--");
            startInfo.ArgumentList.Add(wslTargetPath);
            startInfo.ArgumentList.Add(wslLinkPath);

            using Process? process = Process.Start(startInfo);
            if (process is null)
            {
                return false;
            }

            process.WaitForExit();
            return process.ExitCode == 0
                && File.Exists(linkPath)
                && (File.GetAttributes(linkPath) & FileAttributes.ReparsePoint) != 0;
        }
        catch (Exception exception) when (
            exception is Win32Exception or
            IOException or
            InvalidOperationException)
        {
            return false;
        }
    }

    private static string? TryConvertToWslPath(string path)
    {
        var startInfo = new ProcessStartInfo("wsl.exe")
        {
            CreateNoWindow = true,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
        };
        startInfo.ArgumentList.Add("-e");
        startInfo.ArgumentList.Add("wslpath");
        startInfo.ArgumentList.Add("-a");
        startInfo.ArgumentList.Add("-u");
        startInfo.ArgumentList.Add(path);

        using Process? process = Process.Start(startInfo);
        if (process is null)
        {
            return null;
        }

        string convertedPath = process.StandardOutput.ReadToEnd().Trim();
        process.WaitForExit();
        return process.ExitCode == 0 && convertedPath.Length > 0
            ? convertedPath
            : null;
    }

}
