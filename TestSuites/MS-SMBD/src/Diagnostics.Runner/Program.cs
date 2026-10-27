// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Protocols.TestSuites.Diagnostics.Manifest;
using Microsoft.Protocols.TestSuites.Diagnostics.Runner;
using Microsoft.Protocols.TestSuites.Diagnostics.Storage;
using Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Runner;

namespace Microsoft.Protocols.TestSuites.Smbd.Diagnostics.RunnerHost;

internal static class Program
{
    internal static RunnerEvidenceStorage EvidenceStorage { get; set; } = new();
    internal static string DotnetExecutable { get; set; } = "dotnet";

    public static async Task<int> Main(string[] args)
    {
        try
        {
            RunnerCliOptions options = RunnerCliOptions.Parse(args);
            return await ExecuteAsync(options).ConfigureAwait(false);
        }
        catch (RunnerConfigurationException exception)
        {
            WriteDiagnostic(
                $"MS-SMBD diagnostics runner configuration error: {exception.Message}");
            return 2;
        }
        catch (RunnerEvidenceException exception)
        {
            WriteDiagnostic(
                $"MS-SMBD diagnostics runner evidence error: {exception.Message}");
            return 2;
        }
        catch (ArgumentException exception)
        {
            WriteDiagnostic(
                $"MS-SMBD diagnostics runner argument error: {exception.Message}");
            return 2;
        }
        catch (IOException)
        {
            WriteDiagnostic(
                "MS-SMBD diagnostics runner encountered an I/O error.");
            return 2;
        }
        catch (UnauthorizedAccessException)
        {
            WriteDiagnostic(
                "MS-SMBD diagnostics runner encountered an access error.");
            return 2;
        }
        catch (Win32Exception)
        {
            WriteDiagnostic(
                "MS-SMBD diagnostics runner could not start dotnet test.");
            return 2;
        }
    }

    private static async Task<int> ExecuteAsync(RunnerCliOptions options)
    {
        string runId = RunnerRunContext.CreateRunId();
        RunnerExecutionPlan plan;
        try
        {
            plan = RunnerExecutionPlan.Create(
                options.CanonicalConfigurationPath,
                options.DeploymentConfigurationPath,
                runId);
        }
        catch (RunnerConfigurationException)
        {
            return await ExecuteBestEffortFallbackAsync(
                    options,
                    "configuration-unavailable")
                .ConfigureAwait(false);
        }
        catch (ArtifactStorageException)
        {
            return await ExecuteBestEffortFallbackAsync(
                    options,
                    "storage-validation-unavailable")
                .ConfigureAwait(false);
        }
        catch (IOException)
        {
            return await ExecuteBestEffortFallbackAsync(
                    options,
                    "configuration-io-unavailable")
                .ConfigureAwait(false);
        }
        catch (UnauthorizedAccessException)
        {
            return await ExecuteBestEffortFallbackAsync(
                    options,
                    "configuration-access-unavailable")
                .ConfigureAwait(false);
        }
        catch (ArgumentException)
        {
            return await ExecuteBestEffortFallbackAsync(
                    options,
                    "configuration-invalid")
                .ConfigureAwait(false);
        }

        if (!plan.IsEnabled)
        {
            return await ExecuteDisabledAsync(options).ConfigureAwait(false);
        }

        RunnerArtifactLayout layout;
        RunnerProvenance provenance;
        try
        {
            string sourceRoot = SmbdRunnerContext.FindSourceRoot(
                plan.BuildOutputRoot!);
            layout = RunnerArtifactLayout.Create(plan, sourceRoot);
            provenance = RunnerProvenance.Create(
                options.BinaryPaths,
                options.Filter,
                options.CanonicalConfigurationPath,
                options.DeploymentConfigurationPath);
        }
        catch (RunnerEvidenceException)
        {
            return await ExecuteBestEffortFallbackAsync(
                    options,
                    "runner-evidence-unavailable")
                .ConfigureAwait(false);
        }
        catch (ArtifactStorageException)
        {
            return await ExecuteBestEffortFallbackAsync(
                    options,
                    "runner-storage-unavailable")
                .ConfigureAwait(false);
        }
        catch (IOException)
        {
            return await ExecuteBestEffortFallbackAsync(
                    options,
                    "runner-io-unavailable")
                .ConfigureAwait(false);
        }
        catch (UnauthorizedAccessException)
        {
            return await ExecuteBestEffortFallbackAsync(
                    options,
                    "runner-access-unavailable")
                .ConfigureAwait(false);
        }
        catch (ArgumentException)
        {
            return await ExecuteBestEffortFallbackAsync(
                    options,
                    "runner-input-invalid")
                .ConfigureAwait(false);
        }

        TryEvidence(
            () => WriteBootstrap(
                layout.BootstrapPath,
                plan.RunId,
                options.BinaryPaths.Count,
                string.IsNullOrEmpty(options.Filter)),
            "bootstrap-write");
        int runnerExitCode;
        try
        {
            runnerExitCode = await ExecuteCapturedAsync(
                    options,
                    layout,
                    plan.RunId)
                .ConfigureAwait(false);
        }
        catch (Win32Exception)
        {
            TryAppendBootstrap(
                layout.BootstrapPath,
                "test-process-start=failed");
            WriteDiagnostic(
                "MS-SMBD diagnostics runner could not start the dotnet test process.");
            return 1;
        }

        try
        {
            RunnerEvidenceReconciler.Reconcile(
                layout.RunRoot,
                layout.TrxPath,
                layout.StdoutPath,
                layout.StderrPath,
                layout.BootstrapPath,
                runnerExitCode,
                provenance);
        }
        catch (RunnerEvidenceException exception)
        {
            TryAppendBootstrap(
                layout.BootstrapPath,
                "reconciliation=unavailable");
            WriteDiagnostic(
                $"MS-SMBD diagnostics reconciliation warning: {exception.Message}");
        }
        catch (IOException)
        {
            TryAppendBootstrap(
                layout.BootstrapPath,
                "reconciliation=unavailable");
            WriteDiagnostic(
                "MS-SMBD diagnostics reconciliation warning: evidence I/O was unavailable.");
        }
        catch (UnauthorizedAccessException)
        {
            TryAppendBootstrap(
                layout.BootstrapPath,
                "reconciliation=unavailable");
            WriteDiagnostic(
                "MS-SMBD diagnostics reconciliation warning: evidence access was unavailable.");
        }
        catch (ManifestSerializationException)
        {
            TryAppendBootstrap(
                layout.BootstrapPath,
                "reconciliation=unavailable");
            WriteDiagnostic(
                "MS-SMBD diagnostics reconciliation warning: a provisional manifest was invalid.");
        }
        catch (ArtifactStorageException)
        {
            TryAppendBootstrap(
                layout.BootstrapPath,
                "reconciliation=unavailable");
            WriteDiagnostic(
                "MS-SMBD diagnostics reconciliation warning: artifact storage was unavailable.");
        }
        catch (InvalidOperationException)
        {
            TryAppendBootstrap(
                layout.BootstrapPath,
                "reconciliation=unavailable");
            WriteDiagnostic(
                "MS-SMBD diagnostics reconciliation warning: evidence finalization was unavailable.");
        }
        catch (ArgumentException)
        {
            TryAppendBootstrap(
                layout.BootstrapPath,
                "reconciliation=unavailable");
            WriteDiagnostic(
                "MS-SMBD diagnostics reconciliation warning: correlation input was invalid.");
        }

        return runnerExitCode;
    }

    private static async Task<int> ExecuteBestEffortFallbackAsync(
        RunnerCliOptions options,
        string reasonCode)
    {
        WriteDiagnostic(
            $"MS-SMBD diagnostics unavailable ({reasonCode}); continuing the test run without runner evidence.");
        return await ExecuteDisabledAsync(options).ConfigureAwait(false);
    }

    private static async Task<int> ExecuteDisabledAsync(
        RunnerCliOptions options)
    {
        string resultRoot = Path.Combine(
            Path.GetDirectoryName(
                Path.GetDirectoryName(options.BinaryPaths[0])) ??
                Path.GetDirectoryName(options.BinaryPaths[0])!,
            "TestResults");
        bool resultStorageAvailable = TryEvidence(
            () => EvidenceStorage.CreateResultsDirectory(resultRoot), "results-directory");
        using Process process = CreateProcess(
            options,
            resultStorageAvailable ? resultRoot : null,
            trxFileName: null,
            redirectOutput: false,
            runId: null);
        if (!process.Start())
        {
            return 1;
        }

        await process.WaitForExitAsync().ConfigureAwait(false);
        return process.ExitCode;
    }

    private static async Task<int> ExecuteCapturedAsync(
        RunnerCliOptions options,
        RunnerArtifactLayout layout,
        string runId)
    {
        using Process process = CreateProcess(
            options,
            layout.RunnerRoot,
            "results.trx",
            redirectOutput: true,
            runId);
        Stream stdout = OpenOutputOrDiscard(layout.StdoutPath, "stdout-open");
        Stream stderr = OpenOutputOrDiscard(layout.StderrPath, "stderr-open");
        try
        {
            if (!process.Start())
            {
                return 1;
            }

            Task stdoutCopy = CopyOutputAsync(
                process.StandardOutput.BaseStream,
                stdout,
                Console.OpenStandardOutput());
            Task stderrCopy = CopyOutputAsync(
                process.StandardError.BaseStream,
                stderr,
                Console.OpenStandardError());
            await process.WaitForExitAsync().ConfigureAwait(false);
            await Task.WhenAll(stdoutCopy, stderrCopy).ConfigureAwait(false);
            if (stdout != Stream.Null)
                TryEvidence(() => EvidenceStorage.FlushOutput(stdout), "stdout-flush");
            if (stderr != Stream.Null)
                TryEvidence(() => EvidenceStorage.FlushOutput(stderr), "stderr-flush");
            return process.ExitCode;
        }
        finally
        {
            TryEvidence(stdout.Dispose, "stdout-close");
            TryEvidence(stderr.Dispose, "stderr-close");
        }
    }

    private static Process CreateProcess(
        RunnerCliOptions options,
        string? resultsDirectory,
        string? trxFileName,
        bool redirectOutput,
        string? runId)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = DotnetExecutable,
            CreateNoWindow = true,
            RedirectStandardError = redirectOutput,
            RedirectStandardOutput = redirectOutput,
            UseShellExecute = false,
        };
        startInfo.ArgumentList.Add("test");
        foreach (string binaryPath in options.BinaryPaths)
        {
            startInfo.ArgumentList.Add(binaryPath);
        }

        if (!string.IsNullOrEmpty(options.Filter))
        {
            startInfo.ArgumentList.Add("--filter");
            startInfo.ArgumentList.Add(options.Filter);
        }

        if (resultsDirectory is not null)
        {
            startInfo.ArgumentList.Add("--logger");
            startInfo.ArgumentList.Add(
                trxFileName is null
                    ? "trx"
                    : $"trx;LogFileName={trxFileName}");
            startInfo.ArgumentList.Add("--results-directory");
            startInfo.ArgumentList.Add(resultsDirectory);
        }
        if (runId is not null)
        {
            startInfo.Environment[
                SmbdRunnerContext.RunIdEnvironmentVariable] = runId;
        }

        return new Process { StartInfo = startInfo };
    }

    private static async Task CopyOutputAsync(
        Stream source,
        Stream evidence,
        Stream console)
    {
        byte[] buffer = new byte[81920];
        while (true)
        {
            int read = await source
                .ReadAsync(buffer.AsMemory(0, buffer.Length))
                .ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            if (!await TryWriteAsync(evidence, buffer.AsMemory(0, read), "evidence-copy").ConfigureAwait(false))
                evidence = Stream.Null;
            if (!await TryWriteAsync(console, buffer.AsMemory(0, read), "console-copy").ConfigureAwait(false))
                console = Stream.Null;
        }

        TryEvidence(evidence.Flush, "evidence-copy-flush");
        TryEvidence(console.Flush, "console-copy-flush");
    }

    private static Stream OpenOutputOrDiscard(string path, string stage)
    {
        Stream stream = Stream.Null;
        TryEvidence(() => stream = EvidenceStorage.OpenOutput(path), stage);
        return stream;
    }

    private static async Task<bool> TryWriteAsync(Stream stream, ReadOnlyMemory<byte> bytes, string stage)
    {
        try
        {
            await stream.WriteAsync(bytes).ConfigureAwait(false);
            return true;
        }
        catch (IOException) { ReportEvidenceFailure(stage); }
        catch (UnauthorizedAccessException) { ReportEvidenceFailure(stage); }
        catch (ObjectDisposedException) { ReportEvidenceFailure(stage); }
        return false;
    }

    private static bool TryEvidence(Action action, string stage)
    {
        try { action(); return true; }
        catch (IOException) { ReportEvidenceFailure(stage); }
        catch (UnauthorizedAccessException) { ReportEvidenceFailure(stage); }
        catch (ObjectDisposedException) { ReportEvidenceFailure(stage); }
        return false;
    }

    private static void ReportEvidenceFailure(string stage)
    {
        // Do not include paths, exception messages or command-line secrets in the fallback channel.
        WriteDiagnostic($"MS-SMBD diagnostics evidence unavailable ({stage}); preserving the test process result.");
    }

    private static void WriteDiagnostic(string message)
    {
        try { Console.Error.WriteLine(message); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        catch (ObjectDisposedException) { }
    }

    private static void WriteBootstrap(
        string path,
        string runId,
        int binaryCount,
        bool emptyFilter)
    {
        string content = string.Join(
            Environment.NewLine,
            "schemaVersion=1.0",
            $"runId={runId}",
            "policy=canonical-ptf-validated",
            $"binaryCount={binaryCount.ToString(CultureInfo.InvariantCulture)}",
            $"filter={(emptyFilter ? "empty" : "sha256-projected")}",
            "test-process=dotnet-test",
            string.Empty);
        EvidenceStorage.WriteText(path, content);
    }

    private static void TryAppendBootstrap(string path, string status)
    {
        TryEvidence(() => EvidenceStorage.AppendText(
            path,
            status + Environment.NewLine), "bootstrap-append");
    }
}

internal sealed class RunnerCliOptions
{
    private RunnerCliOptions(
        string canonicalConfigurationPath,
        string deploymentConfigurationPath,
        IReadOnlyList<string> binaryPaths,
        string? filter)
    {
        CanonicalConfigurationPath = canonicalConfigurationPath;
        DeploymentConfigurationPath = deploymentConfigurationPath;
        BinaryPaths = binaryPaths;
        Filter = filter;
    }

    public string CanonicalConfigurationPath { get; }

    public string DeploymentConfigurationPath { get; }

    public IReadOnlyList<string> BinaryPaths { get; }

    public string? Filter { get; }

    public static RunnerCliOptions Parse(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);
        if (args.Length == 0 ||
            !string.Equals(args[0], "run", StringComparison.Ordinal))
        {
            throw new RunnerConfigurationException(
                "Expected the 'run' command.");
        }

        string? canonicalConfigurationPath = null;
        string? deploymentConfigurationPath = null;
        string? filter = null;
        var binaryPaths = new List<string>();
        for (int index = 1; index < args.Length; index++)
        {
            string option = args[index];
            if (index + 1 >= args.Length)
            {
                throw new RunnerConfigurationException(
                    $"Runner option '{option}' requires a value.");
            }

            string value = args[++index];
            switch (option)
            {
                case "--config":
                    canonicalConfigurationPath = AssignSingle(
                        canonicalConfigurationPath,
                        value,
                        option);
                    break;
                case "--deployment-config":
                    deploymentConfigurationPath = AssignSingle(
                        deploymentConfigurationPath,
                        value,
                        option);
                    break;
                case "--binary":
                    binaryPaths.Add(ValidateBinary(value));
                    break;
                case "--filter":
                    filter = AssignSingle(filter, value, option);
                    break;
                default:
                    throw new RunnerConfigurationException(
                        $"Runner option '{option}' is not supported.");
            }
        }

        if (canonicalConfigurationPath is null ||
            deploymentConfigurationPath is null ||
            binaryPaths.Count == 0)
        {
            throw new RunnerConfigurationException(
                "Runner config, deployment config, and at least one binary are required.");
        }

        return new RunnerCliOptions(
            Path.GetFullPath(canonicalConfigurationPath),
            Path.GetFullPath(deploymentConfigurationPath),
            binaryPaths.AsReadOnly(),
            filter);
    }

    private static string AssignSingle(
        string? current,
        string value,
        string option)
    {
        if (current is not null)
        {
            throw new RunnerConfigurationException(
                $"Runner option '{option}' cannot be repeated.");
        }

        if (string.IsNullOrEmpty(value) ||
            value.Any(char.IsControl))
        {
            throw new RunnerConfigurationException(
                $"Runner option '{option}' has an invalid value.");
        }

        return value;
    }

    private static string ValidateBinary(string path)
    {
        string fullPath = Path.GetFullPath(path);
        if (!string.Equals(
                Path.GetExtension(fullPath),
                ".dll",
                StringComparison.OrdinalIgnoreCase) ||
            !File.Exists(fullPath))
        {
            throw new RunnerConfigurationException(
                "Each runner binary must be an existing .dll file.");
        }

        return fullPath;
    }
}
