// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.Protocols.TestSuites.Diagnostics.Providers;

public enum ProcessCommandStatus
{
    Completed,
    ToolMissing,
    PermissionDenied,
    StartFailed,
    TimedOut,
    Cancelled,
}

public sealed class ProcessCommandResult
{
    private ProcessCommandResult(
        ProcessCommandStatus status,
        int? exitCode,
        string standardOutput,
        string standardError,
        bool spawnedProcessTerminated)
    {
        Status = status;
        ExitCode = exitCode;
        StandardOutput = standardOutput;
        StandardError = standardError;
        SpawnedProcessTerminated = spawnedProcessTerminated;
    }

    public ProcessCommandStatus Status { get; }

    public int? ExitCode { get; }

    public string StandardOutput { get; }

    public string StandardError { get; }

    public bool SpawnedProcessTerminated { get; }

    public static ProcessCommandResult Completed(
        int exitCode,
        string standardOutput = "",
        string standardError = "")
    {
        return new ProcessCommandResult(
            ProcessCommandStatus.Completed,
            exitCode,
            standardOutput ?? string.Empty,
            standardError ?? string.Empty,
            spawnedProcessTerminated: false);
    }

    public static ProcessCommandResult ToolMissing()
    {
        return new ProcessCommandResult(
            ProcessCommandStatus.ToolMissing,
            exitCode: null,
            string.Empty,
            string.Empty,
            spawnedProcessTerminated: false);
    }

    public static ProcessCommandResult PermissionDenied()
    {
        return new ProcessCommandResult(
            ProcessCommandStatus.PermissionDenied,
            exitCode: null,
            string.Empty,
            string.Empty,
            spawnedProcessTerminated: false);
    }

    public static ProcessCommandResult StartFailed()
    {
        return new ProcessCommandResult(
            ProcessCommandStatus.StartFailed,
            exitCode: null,
            string.Empty,
            string.Empty,
            spawnedProcessTerminated: false);
    }

    public static ProcessCommandResult TimedOut(bool spawnedProcessTerminated)
    {
        return new ProcessCommandResult(
            ProcessCommandStatus.TimedOut,
            exitCode: null,
            string.Empty,
            string.Empty,
            spawnedProcessTerminated);
    }

    public static ProcessCommandResult Cancelled(bool spawnedProcessTerminated)
    {
        return new ProcessCommandResult(
            ProcessCommandStatus.Cancelled,
            exitCode: null,
            string.Empty,
            string.Empty,
            spawnedProcessTerminated);
    }
}

public interface IProcessCommandRunner
{
    bool ExecutableExists(string executablePath);

    Task<ProcessCommandResult> RunAsync(
        ProcessStartInfo startInfo,
        TimeSpan timeout,
        CancellationToken cancellationToken);
}

public sealed class ProcessCommandRunner : IProcessCommandRunner
{
    private static readonly TimeSpan TerminationWaitTimeout =
        TimeSpan.FromSeconds(2);

    public bool ExecutableExists(string executablePath)
    {
        return !string.IsNullOrWhiteSpace(executablePath) &&
            File.Exists(executablePath);
    }

    public async Task<ProcessCommandResult> RunAsync(
        ProcessStartInfo startInfo,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(startInfo);
        ProviderContractValidation.ValidateTimeout(timeout, nameof(timeout));

        if (cancellationToken.IsCancellationRequested)
        {
            return ProcessCommandResult.Cancelled(
                spawnedProcessTerminated: false);
        }

        using var process = new Process
        {
            StartInfo = startInfo,
        };

        try
        {
            if (!process.Start())
            {
                return ProcessCommandResult.StartFailed();
            }
        }
        catch (Win32Exception exception)
            when (exception.NativeErrorCode is 2 or 3)
        {
            return ProcessCommandResult.ToolMissing();
        }
        catch (Win32Exception exception)
            when (exception.NativeErrorCode == 5)
        {
            return ProcessCommandResult.PermissionDenied();
        }
        catch (UnauthorizedAccessException)
        {
            return ProcessCommandResult.PermissionDenied();
        }
        catch (Exception exception)
            when (exception is Win32Exception or InvalidOperationException)
        {
            return ProcessCommandResult.StartFailed();
        }

        Task<string> standardOutput = process.StandardOutput.ReadToEndAsync();
        Task<string> standardError = process.StandardError.ReadToEndAsync();
        Task exit = process.WaitForExitAsync(CancellationToken.None);
        Task limit = Task.Delay(timeout, cancellationToken);
        Task completed = await Task.WhenAny(exit, limit).ConfigureAwait(false);

        if (completed == exit)
        {
            await exit.ConfigureAwait(false);
            return ProcessCommandResult.Completed(
                process.ExitCode,
                await standardOutput.ConfigureAwait(false),
                await standardError.ConfigureAwait(false));
        }

        TryTerminate(process);
        bool terminated = await WaitForTerminationAsync(
            exit,
            standardOutput,
            standardError).ConfigureAwait(false);

        return cancellationToken.IsCancellationRequested
            ? ProcessCommandResult.Cancelled(terminated)
            : ProcessCommandResult.TimedOut(terminated);
    }

    private static bool TryTerminate(Process process)
    {
        try
        {
            if (process.HasExited)
            {
                return false;
            }

            process.Kill();
            return true;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
        catch (Win32Exception)
        {
            return false;
        }
    }

    private static async Task<bool> WaitForTerminationAsync(
        Task exit,
        Task<string> standardOutput,
        Task<string> standardError)
    {
        Task exitLimit = Task.Delay(TerminationWaitTimeout);
        if (await Task.WhenAny(exit, exitLimit).ConfigureAwait(false) != exit)
        {
            ObserveFault(exit);
            ObserveFault(standardOutput);
            ObserveFault(standardError);
            return false;
        }

        try
        {
            await exit.ConfigureAwait(false);
        }
        catch (InvalidOperationException)
        {
            ObserveFault(standardOutput);
            ObserveFault(standardError);
            return false;
        }

        Task output = Task.WhenAll(standardOutput, standardError);
        Task outputLimit = Task.Delay(TerminationWaitTimeout);
        if (await Task.WhenAny(output, outputLimit).ConfigureAwait(false) == output)
        {
            await output.ConfigureAwait(false);
        }
        else
        {
            ObserveFault(output);
        }

        return true;
    }

    private static void ObserveFault(Task task)
    {
        _ = task.ContinueWith(
            completed => _ = completed.Exception,
            CancellationToken.None,
            TaskContinuationOptions.OnlyOnFaulted |
                TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }
}
