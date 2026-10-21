// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Protocols.TestSuites.Diagnostics.Evidence;
using Microsoft.Protocols.TestSuites.Diagnostics.Manifest;
using Microsoft.Protocols.TestSuites.Diagnostics.Storage;
using StorageArtifactPath =
    Microsoft.Protocols.TestSuites.Diagnostics.Storage.ArtifactPath;

namespace Microsoft.Protocols.TestSuites.Diagnostics.Providers;

/// <summary>
/// Captures RoCE/RDMA traffic with the NVIDIA/Mellanox WinOF-2 NIC sniffer
/// (<c>Mlx5Cmd -Sniffer</c>). RDMA data bypasses the Windows network stack, so
/// <c>netsh trace</c> cannot see it; the NIC sniffer can.
/// </summary>
public sealed class Mlx5SnifferCaptureProvider : ICaptureProvider
{
    public const string ProviderIdentifier = "Mlx5Sniffer";
    public const string DefaultExecutablePath =
        @"C:\Program Files\Mellanox\MLNX_WinOF2\Management Tools\Mlx5Cmd.exe";
    public const string OutputFileName = "rdma.pcap";
    public const string RotatedOutputFileName = "rdma.pcap_prev";

    private const long BytesPerMebibyte = 1024 * 1024;
    private const string RunningText = "Sniffer is running";

    private readonly string executablePath;
    private readonly TimeSpan commandTimeout;
    private readonly IProcessCommandRunner commandRunner;
    private readonly Func<string, string?> adapterNameResolver;
    private readonly Func<TimeSpan, CancellationToken, Task> delayAsync;
    private readonly ConcurrentDictionary<string, OwnedSession> ownedSessions =
        new(StringComparer.Ordinal);

    public Mlx5SnifferCaptureProvider(
        string executablePath,
        TimeSpan commandTimeout)
        : this(
            executablePath,
            commandTimeout,
            new ProcessCommandRunner(),
            ResolveMellanoxAdapterName,
            static (delay, token) => Task.Delay(delay, token))
    {
    }

    public Mlx5SnifferCaptureProvider(
        string executablePath,
        TimeSpan commandTimeout,
        IProcessCommandRunner commandRunner,
        Func<string, string?> adapterNameResolver,
        Func<TimeSpan, CancellationToken, Task> delayAsync)
    {
        this.executablePath = ProviderContractValidation.RequireText(
            executablePath,
            nameof(executablePath));
        this.commandTimeout = ProviderContractValidation.ValidatePositiveTimeout(
            commandTimeout,
            nameof(commandTimeout));
        this.commandRunner = commandRunner ??
            throw new ArgumentNullException(nameof(commandRunner));
        this.adapterNameResolver = adapterNameResolver ??
            throw new ArgumentNullException(nameof(adapterNameResolver));
        this.delayAsync = delayAsync ??
            throw new ArgumentNullException(nameof(delayAsync));
    }

    public string ProviderId => ProviderIdentifier;

    public Task<CaptureProviderProbeResult> ProbeAsync(
        CaptureProviderStartRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!commandRunner.ExecutableExists(executablePath))
        {
            return Task.FromResult(
                CaptureProviderProbeResult.Unavailable(
                    CaptureProviderFailureCode.ToolMissing,
                    "The Mlx5Cmd sniffer executable is unavailable."));
        }

        if (!TryResolveAdapter(request, out _, out CaptureProviderFailureCode failure))
        {
            return Task.FromResult(
                CaptureProviderProbeResult.Unavailable(
                    failure,
                    "No Mellanox/NVIDIA adapter owns the capture target address."));
        }

        return Task.FromResult(
            CaptureProviderProbeResult.Available(
                new CaptureProviderCapabilities(
                    ProviderIdentifier,
                    new[] { "IPv4" },
                    new[] { "PCAP" },
                    "NIC-level sniffer on the adapter that owns the target IPv4 address; sees RoCE (UDP 4791) packets that bypass the OS network stack.",
                    "Whole-MiB file size limit with one rotated previous file, plus provider-coordinated duration limit.",
                    "The owned sniffer is stopped by adapter name.",
                    "Readiness requires the sniffer query to report it is running.",
                    new[]
                    {
                        "Only the sniffer-capable Mellanox/NVIDIA adapter is covered.",
                        "Packets beyond the size limit rotate into the previous file and older ones are discarded.",
                    },
                    CoverageQualification.Unverified)));
    }

    public async Task<CaptureProviderStartResult> StartAsync(
        CaptureProviderStartRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!commandRunner.ExecutableExists(executablePath))
        {
            return CaptureProviderStartResult.Failed(
                CaptureProviderFailureCode.ToolMissing,
                "The Mlx5Cmd sniffer executable is unavailable.");
        }

        if (!TryResolveAdapter(
                request,
                out string adapterName,
                out CaptureProviderFailureCode targetFailure))
        {
            return CaptureProviderStartResult.Failed(
                targetFailure,
                "No Mellanox/NVIDIA adapter owns the capture target address.");
        }

        long limitMebibytes = Math.Max(1, request.MaxBytes / BytesPerMebibyte);
        string outputPath;
        try
        {
            outputPath = StorageArtifactPath.CombineUnderRoot(
                request.ArtifactInvocation.DirectoryPath,
                OutputFileName);
            StorageArtifactPath.EnsureNoReparsePoints(
                request.ArtifactInvocation.DirectoryPath,
                outputPath);
        }
        catch (ArtifactStorageException)
        {
            return CaptureProviderStartResult.Failed(
                CaptureProviderFailureCode.StartFailed,
                "The sniffer output path is not safe.");
        }

        CaptureProviderSessionHandle handle =
            CaptureProviderSessionHandle.Create(
                ProviderIdentifier,
                request.Identity.InvocationId,
                adapterName);
        var state = new OwnedSession(
            handle,
            adapterName,
            outputPath,
            request.ArtifactInvocation.DirectoryPath,
            request.MaxDuration);
        if (!TryReserveSession(state))
        {
            return CaptureProviderStartResult.Failed(
                CaptureProviderFailureCode.CaptureBusy,
                "The adapter sniffer is already owned by this provider.");
        }

        bool started = false;
        try
        {
            ProcessCommandResult preflight = await QueryAsync(
                adapterName,
                cancellationToken).ConfigureAwait(false);
            if (preflight.Status != ProcessCommandStatus.Completed)
            {
                return CaptureProviderStartResult.Failed(
                    Classify(preflight, CaptureProviderFailureCode.StartFailed),
                    "The sniffer preflight failed.");
            }

            if (IsRunning(preflight))
            {
                return CaptureProviderStartResult.Failed(
                    CaptureProviderFailureCode.CaptureBusy,
                    "A sniffer is already running on the adapter.");
            }

            ProcessCommandResult start = await commandRunner.RunAsync(
                CreateStartInfo(
                    "-Sniffer",
                    "-Name",
                    adapterName,
                    "-start",
                    "-filename",
                    outputPath,
                    "-limit_file_size",
                    limitMebibytes.ToString(CultureInfo.InvariantCulture)),
                commandTimeout,
                cancellationToken).ConfigureAwait(false);
            if (start.Status != ProcessCommandStatus.Completed ||
                start.ExitCode != 0 ||
                !Contains(start, RunningText))
            {
                return CaptureProviderStartResult.Failed(
                    Classify(start, CaptureProviderFailureCode.StartFailed),
                    "The sniffer could not be started.");
            }

            started = true;
            state.DurationTask = EnforceMaximumDurationAsync(state);
            return CaptureProviderStartResult.Started(handle);
        }
        finally
        {
            if (!started)
            {
                ownedSessions.TryRemove(adapterName, out _);
            }
        }
    }

    private bool TryReserveSession(OwnedSession state)
    {
        while (!ownedSessions.TryAdd(state.AdapterName, state))
        {
            if (!ownedSessions.TryGetValue(state.AdapterName, out OwnedSession? previous))
            {
                continue;
            }

            if (Volatile.Read(ref previous.StopCompleted) == 0)
            {
                return false;
            }

            // Old stop calls/timers see StopCompleted; handle reference checks reject
            // stale external callers after the atomic replacement.
            if (ownedSessions.TryUpdate(state.AdapterName, state, previous))
            {
                return true;
            }
        }

        return true;
    }

    public async Task<CaptureProviderReadinessResult> WaitForReadinessAsync(
        CaptureProviderSessionHandle handle,
        CancellationToken cancellationToken)
    {
        if (!TryGetOwnedSession(handle, out OwnedSession state))
        {
            return CaptureProviderReadinessResult.Failed(
                CaptureProviderFailureCode.OwnershipMismatch,
                "The sniffer is not owned by this provider instance.");
        }

        ProcessCommandResult status = await QueryAsync(
            state.AdapterName,
            cancellationToken).ConfigureAwait(false);
        if (status.Status != ProcessCommandStatus.Completed)
        {
            return CaptureProviderReadinessResult.Failed(
                Classify(status, CaptureProviderFailureCode.ReadinessUnverified),
                "Sniffer readiness could not be verified.");
        }

        return IsRunning(status)
            ? CaptureProviderReadinessResult.Ready(
                "Sniffer query confirmed the owned sniffer is running.")
            : CaptureProviderReadinessResult.Unverified(
                "Sniffer query did not confirm a running sniffer.");
    }

    public async Task<CaptureProviderHealthResult> ObserveHealthAsync(
        CaptureProviderSessionHandle handle,
        CancellationToken cancellationToken)
    {
        if (!TryGetOwnedSession(handle, out OwnedSession state))
        {
            return CaptureProviderHealthResult.Failed(
                CaptureProviderFailureCode.OwnershipMismatch,
                "The sniffer is not owned by this provider instance.");
        }

        if (Volatile.Read(ref state.StopCompleted) != 0)
        {
            return CaptureProviderHealthResult.ExitedEarly(
                "The sniffer has already stopped.");
        }

        ProcessCommandResult status = await QueryAsync(
            state.AdapterName,
            cancellationToken).ConfigureAwait(false);
        if (status.Status == ProcessCommandStatus.TimedOut)
        {
            return CaptureProviderHealthResult.TimedOut(
                "Sniffer health inspection timed out.");
        }

        if (status.Status != ProcessCommandStatus.Completed)
        {
            return CaptureProviderHealthResult.Failed(
                Classify(status, CaptureProviderFailureCode.HealthFailed),
                "Sniffer health inspection failed.");
        }

        return IsRunning(status)
            ? CaptureProviderHealthResult.Healthy(
                "Sniffer query confirmed the owned sniffer is running.")
            : CaptureProviderHealthResult.ExitedEarly(
                "Sniffer query did not confirm a running sniffer.");
    }

    public Task<CaptureProviderStopResult> RequestStopAsync(
        CaptureProviderSessionHandle handle,
        CancellationToken cancellationToken)
    {
        if (!TryGetOwnedSession(handle, out OwnedSession state))
        {
            return Task.FromResult(
                CaptureProviderStopResult.Failed(
                    writerResolved: true,
                    CaptureProviderFailureCode.OwnershipMismatch,
                    "The sniffer is not owned by this provider instance."));
        }

        return StopOwnedAsync(state, cancellationToken);
    }

    public Task<CaptureProviderFinalizationResult> WaitForFinalizationAsync(
        CaptureProviderSessionHandle handle,
        CancellationToken cancellationToken)
    {
        if (!TryGetOwnedSession(handle, out OwnedSession state))
        {
            return Task.FromResult(
                CaptureProviderFinalizationResult.Failed(
                    CaptureProviderFailureCode.OwnershipMismatch,
                    "The sniffer is not owned by this provider instance."));
        }

        if (Volatile.Read(ref state.StopCompleted) == 0)
        {
            return Task.FromResult(
                CaptureProviderFinalizationResult.Failed(
                    CaptureProviderFailureCode.FinalizationFailed,
                    "The sniffer has not been stopped."));
        }

        try
        {
            var artifacts = new System.Collections.Generic.List<ArtifactRecord>();
            artifacts.Add(Finalize(state, state.OutputPath, OutputFileName));
            string rotated = state.OutputPath + "_prev";
            if (File.Exists(rotated))
            {
                artifacts.Add(Finalize(state, rotated, RotatedOutputFileName));
            }

            return Task.FromResult(
                CaptureProviderFinalizationResult.Finalized(
                    "The stopped, nonempty sniffer pcap was finalized.",
                    artifacts));
        }
        catch (Exception exception)
            when (exception is IOException
                or UnauthorizedAccessException
                or ArtifactStorageException)
        {
            return Task.FromResult(
                CaptureProviderFinalizationResult.Failed(
                    CaptureProviderFailureCode.FinalizationFailed,
                    "The sniffer pcap could not be finalized safely."));
        }
    }

    private static ArtifactRecord Finalize(
        OwnedSession state,
        string path,
        string relativePath)
    {
        StorageArtifactPath.EnsureNoReparsePoints(state.ArtifactRoot, path);
        using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.None,
            bufferSize: 81920,
            FileOptions.SequentialScan);
        if (stream.Length == 0)
        {
            throw new IOException("The sniffer pcap is empty.");
        }

        long byteCount = stream.Length;
        string sha256 = Convert.ToHexString(SHA256.HashData(stream));
        return ArtifactRecord.CreateFinalized(
            relativePath,
            ProviderIdentifier,
            byteCount,
            sha256,
            ArtifactConfidentiality.Restricted,
            ArtifactRelation.Original,
            "application/vnd.tcpdump.pcap");
    }

    private async Task<CaptureProviderStopResult> StopOwnedAsync(
        OwnedSession state,
        CancellationToken cancellationToken)
    {
        try
        {
            await state.StopGate.WaitAsync(cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return CaptureProviderStopResult.Failed(
                writerResolved: false,
                CaptureProviderFailureCode.Cancelled,
                "Sniffer stop was cancelled.");
        }

        try
        {
            if (Volatile.Read(ref state.StopCompleted) != 0)
            {
                return CaptureProviderStopResult.AlreadyStopped(
                    "The owned sniffer is already stopped.");
            }

            ProcessCommandResult stop = await commandRunner.RunAsync(
                CreateStartInfo("-Sniffer", "-Name", state.AdapterName, "-stop"),
                commandTimeout,
                cancellationToken).ConfigureAwait(false);
            if (stop.Status != ProcessCommandStatus.Completed ||
                stop.ExitCode != 0)
            {
                return CaptureProviderStopResult.Failed(
                    writerResolved: false,
                    stop.Status == ProcessCommandStatus.TimedOut
                        ? CaptureProviderFailureCode.StopTimeout
                        : CaptureProviderFailureCode.StopFailed,
                    "The owned sniffer could not be stopped.");
            }

            Volatile.Write(ref state.StopCompleted, 1);
            state.DurationCancellation.Cancel();
            return CaptureProviderStopResult.Stopped("The owned sniffer stopped.");
        }
        finally
        {
            state.StopGate.Release();
        }
    }

    private async Task EnforceMaximumDurationAsync(OwnedSession state)
    {
        try
        {
            await delayAsync(
                    state.MaximumDuration,
                    state.DurationCancellation.Token)
                .ConfigureAwait(false);
            await StopOwnedAsync(state, CancellationToken.None)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
            when (state.DurationCancellation.IsCancellationRequested)
        {
        }
        catch (Exception)
        {
            // The explicit stop path still runs and reports its own result.
        }
    }

    private Task<ProcessCommandResult> QueryAsync(
        string adapterName,
        CancellationToken cancellationToken)
    {
        return commandRunner.RunAsync(
            CreateStartInfo("-Sniffer", "-Name", adapterName, "-query"),
            commandTimeout,
            cancellationToken);
    }

    private ProcessStartInfo CreateStartInfo(params string[] arguments)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = executablePath,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };

        foreach (string argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        return startInfo;
    }

    private bool TryResolveAdapter(
        CaptureProviderStartRequest request,
        out string adapterName,
        out CaptureProviderFailureCode failure)
    {
        adapterName = string.Empty;
        failure = CaptureProviderFailureCode.TargetAmbiguous;
        if (request.TargetIds.Count != 1 ||
            !IPAddress.TryParse(request.TargetIds[0], out IPAddress? address) ||
            address.AddressFamily != AddressFamily.InterNetwork)
        {
            return false;
        }

        string? resolved = adapterNameResolver(address.ToString());
        if (string.IsNullOrWhiteSpace(resolved))
        {
            return false;
        }

        adapterName = resolved;
        failure = CaptureProviderFailureCode.None;
        return true;
    }

    /// <summary>
    /// Returns the connection name (as accepted by <c>Mlx5Cmd -Name</c>) of the
    /// Mellanox/NVIDIA adapter on the subnet of <paramref name="ipv4Address"/>, or null.
    /// </summary>
    public static string? ResolveMellanoxAdapterName(string ipv4Address)
    {
        try
        {
            foreach (NetworkInterface nic in
                NetworkInterface.GetAllNetworkInterfaces())
            {
                string description = nic.Description;
                bool vendorMatch =
                    description.Contains("Mellanox", StringComparison.OrdinalIgnoreCase) ||
                    description.Contains("NVIDIA", StringComparison.OrdinalIgnoreCase) ||
                    description.Contains("ConnectX", StringComparison.OrdinalIgnoreCase);
                if (!vendorMatch)
                {
                    continue;
                }

                foreach (UnicastIPAddressInformation unicast in
                    nic.GetIPProperties().UnicastAddresses)
                {
                    if (unicast.Address.AddressFamily == AddressFamily.InterNetwork &&
                        IPAddress.TryParse(ipv4Address, out IPAddress? target) &&
                        IsSameSubnet(
                            unicast.Address,
                            target,
                            unicast.PrefixLength))
                    {
                        return nic.Name;
                    }
                }
            }
        }
        catch (NetworkInformationException)
        {
        }

        return null;
    }

    private static bool IsSameSubnet(
        IPAddress local,
        IPAddress target,
        int prefixLength)
    {
        byte[] a = local.GetAddressBytes();
        byte[] b = target.GetAddressBytes();
        if (a.Length != 4 || b.Length != 4 || prefixLength is < 1 or > 32)
        {
            return false;
        }

        uint mask = uint.MaxValue << (32 - prefixLength);
        uint x = (uint)(a[0] << 24 | a[1] << 16 | a[2] << 8 | a[3]);
        uint y = (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]);
        return (x & mask) == (y & mask);
    }

    private static CaptureProviderFailureCode Classify(
        ProcessCommandResult result,
        CaptureProviderFailureCode defaultFailure)
    {
        return result.Status switch
        {
            ProcessCommandStatus.ToolMissing => CaptureProviderFailureCode.ToolMissing,
            ProcessCommandStatus.PermissionDenied => CaptureProviderFailureCode.PermissionDenied,
            ProcessCommandStatus.TimedOut => CaptureProviderFailureCode.StartTimeout,
            ProcessCommandStatus.Cancelled => CaptureProviderFailureCode.Cancelled,
            _ => defaultFailure,
        };
    }

    private static bool IsRunning(ProcessCommandResult result)
    {
        return result.ExitCode == 0 &&
            Contains(result, RunningText) &&
            !Contains(result, "not running");
    }

    private static bool Contains(ProcessCommandResult result, string text)
    {
        return result.StandardOutput.Contains(
                text,
                StringComparison.OrdinalIgnoreCase) ||
            result.StandardError.Contains(
                text,
                StringComparison.OrdinalIgnoreCase);
    }

    private bool TryGetOwnedSession(
        CaptureProviderSessionHandle handle,
        out OwnedSession state)
    {
        state = null!;
        if (handle is null ||
            !string.Equals(
                handle.ProviderId,
                ProviderIdentifier,
                StringComparison.Ordinal) ||
            !ownedSessions.TryGetValue(handle.SessionId, out OwnedSession? owned) ||
            owned is null ||
            !ReferenceEquals(handle, owned.Handle))
        {
            return false;
        }

        state = owned;
        return true;
    }

    private sealed class OwnedSession
    {
        public OwnedSession(
            CaptureProviderSessionHandle handle,
            string adapterName,
            string outputPath,
            string artifactRoot,
            TimeSpan maximumDuration)
        {
            Handle = handle;
            AdapterName = adapterName;
            OutputPath = outputPath;
            ArtifactRoot = artifactRoot;
            MaximumDuration = maximumDuration;
        }

        public CaptureProviderSessionHandle Handle { get; }

        public string AdapterName { get; }

        public string OutputPath { get; }

        public string ArtifactRoot { get; }

        public TimeSpan MaximumDuration { get; }

        public CancellationTokenSource DurationCancellation { get; } = new();

        public SemaphoreSlim StopGate { get; } = new(1, 1);

        public Task? DurationTask { get; set; }

        public int StopCompleted;
    }
}
