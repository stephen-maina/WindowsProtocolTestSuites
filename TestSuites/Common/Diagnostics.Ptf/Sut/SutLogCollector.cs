// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Specialized;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace Microsoft.Protocols.TestSuites.Diagnostics.Sut;

/// <summary>
/// WHAT: Collects the SUT's own log for the duration of one test case, so a failure can be debugged from the
/// product's side (kernel log (dmesg) on Linux, which covers ksmbd or any other SMB server implementation, SMB Server / SMB Direct event logs on Windows) without having to
/// map one large log back to test cases afterwards.
/// WHY: Driver-side traces show what the driver sent and received, not why the SUT reacted. The SUT clock can
/// differ from the driver clock, so the window is delimited with SUT-side markers (Linux) or the SUT's own
/// clock (Windows), never the driver clock.
/// SPEC: Not protocol behaviour; this is a debugging aid only. It is best-effort and must never fail a test.
/// </summary>
public sealed class SutLogCollector
{
    public const string EnabledProperty = "SutLog.Enabled";

    private const int CommandTimeoutMilliseconds = 30000;
    private const string LinuxLogFileName = "sut-linux-dmesg.log";
    private const string WindowsLogFileName = "sut-windows.log";

    // After one connection failure every later test would wait for the connect timeout again, so give up for the run.
    private static volatile bool unavailableForRun;

    private readonly SutKind kind;
    private readonly string host;
    private readonly string user;
    private readonly string password;
    private readonly string token;
    private string? windowsStartTime;
    private bool started;

    private enum SutKind
    {
        None,
        Linux,
        Windows,
    }

    private SutLogCollector(
        SutKind kind,
        string host,
        string user,
        string password,
        string? testName)
    {
        this.kind = kind;
        this.host = host;
        this.user = user;
        this.password = password;
        string safeName = Regex.Replace(testName ?? "test", "[^A-Za-z0-9_]", "_");
        token = safeName + "_" + Guid.NewGuid().ToString("N").Substring(0, 8);
    }

    public string? LastError { get; private set; }

    /// <summary>
    /// Names of the configuration properties that locate and authenticate to the SUT. Suites name these differently
    /// (MS-SMBD: SutUserName/SutPassword; FileServer: AdminUserName/PasswordForAllUsers).
    /// </summary>
    public sealed record PropertyNames(
        string Host = "SutComputerName",
        string User = "SutUserName",
        string Password = "SutPassword",
        string Platform = "Platform");

    /// <summary>
    /// Returns null when collection is not enabled or not applicable.
    /// </summary>
    public static SutLogCollector? Create(NameValueCollection properties, string? testName, PropertyNames? names = null)
    {
        if (properties == null ||
            !bool.TryParse(properties[EnabledProperty], out bool enabled) ||
            !enabled ||
            unavailableForRun)
        {
            return null;
        }

        names ??= new PropertyNames();
        string? host = properties[names.Host];
        string? user = properties[names.User];
        string? password = properties[names.Password];
        string platform = properties[names.Platform] ?? string.Empty;
        if (string.IsNullOrWhiteSpace(host) || string.IsNullOrWhiteSpace(user))
        {
            return null;
        }

        SutKind kind = platform.Equals("NonWindows", StringComparison.OrdinalIgnoreCase)
            ? SutKind.Linux
            : platform.StartsWith("Windows", StringComparison.OrdinalIgnoreCase)
                ? SutKind.Windows
                : SutKind.None;
        return kind == SutKind.None
            ? null
            : new SutLogCollector(kind, host, user, password ?? string.Empty, testName);
    }

    /// <summary>
    /// Marks the start of the test window on the SUT. Never throws.
    /// </summary>
    public void Begin()
    {
        try
        {
            if (kind == SutKind.Linux)
            {
                started = RunLinux("echo WPTS-BEGIN-" + token + " > /dev/kmsg", out _);
            }
            else
            {
                started = RunWindows("(Get-Date).ToUniversalTime().ToString('o')", out string output) &&
                    !string.IsNullOrWhiteSpace(output);
                windowsStartTime = started ? output.Trim() : null;
            }

            if (!started)
            {
                unavailableForRun = true;
            }
        }
        catch (Exception ex)
        {
            LastError = ex.Message;
            unavailableForRun = true;
        }
    }

    /// <summary>
    /// Marks the end of the window, fetches the SUT log for it and writes it into the test's artifact folder.
    /// Never throws.
    /// </summary>
    public void EndAndSave(string? artifactDirectory)
    {
        if (!started || string.IsNullOrWhiteSpace(artifactDirectory) || !Directory.Exists(artifactDirectory))
        {
            return;
        }

        try
        {
            string output = string.Empty;
            bool ok;
            string fileName;
            if (kind == SutKind.Linux)
            {
                fileName = LinuxLogFileName;
                // The sed range prints only the lines between this test's markers; no spaces or quotes are used in the
                // script because Windows OpenSSH flattens the argument list into a single remote command line.
                ok = RunLinux(
                    "echo WPTS-END-" + token + " > /dev/kmsg; dmesg --time-format iso | sed -n /WPTS-BEGIN-" +
                        token + "/,/WPTS-END-" + token + "/p",
                    out output);
            }
            else
            {
                fileName = WindowsLogFileName;
                ok = RunWindows(BuildWindowsFetchScript(windowsStartTime ?? string.Empty), out output);
            }

            if (ok)
            {
                File.WriteAllText(Path.Combine(artifactDirectory, fileName), output, Encoding.UTF8);
            }
        }
        catch (Exception ex)
        {
            LastError = ex.Message;
        }
    }

    private static string BuildWindowsFetchScript(string startTimeUtc)
    {
        // The start time came from the SUT's own clock in Begin(), so driver/SUT clock skew does not matter.
        return "$s=[datetime]::Parse('" + startTimeUtc + "').ToUniversalTime();" +
            "foreach($l in 'Microsoft-Windows-SMBServer/Operational','Microsoft-Windows-SMBServer/Security'," +
            "'Microsoft-Windows-SMBDirect/Admin','Microsoft-Windows-SMBDirect/Debug'){" +
            "'=== '+$l;" +
            "Get-WinEvent -FilterHashtable @{LogName=$l;StartTime=$s} -ErrorAction SilentlyContinue|" +
            "Sort-Object TimeCreated|ForEach-Object{'{0:o} id={1} {2}' -f $_.TimeCreated,$_.Id,($_.Message -replace '\\s+',' ')}}";
    }

    private bool RunLinux(string remoteScript, out string output)
    {
        // sudo reads the password from stdin (-S) so it never appears in a process list on either machine.
        string remoteCommand = "sudo -S -p '' sh -c '" + remoteScript + "'";
        string askpass = Path.Combine(Path.GetTempPath(), "wpts-askpass-" + Guid.NewGuid().ToString("N") +
            (OperatingSystem.IsWindows() ? ".cmd" : ".sh"));
        File.WriteAllText(
            askpass,
            OperatingSystem.IsWindows()
                ? "@echo %SUT_SSH_PASSWORD%\r\n"
                : "#!/bin/sh\necho \"$SUT_SSH_PASSWORD\"\n");
        try
        {
            string ssh = OperatingSystem.IsWindows()
                ? Path.Combine(Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows", @"System32\OpenSSH\ssh.exe")
                : "ssh";
            var psi = new ProcessStartInfo(ssh)
            {
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            foreach (string arg in new[]
            {
                "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=accept-new",
                "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no",
                "-o", "NumberOfPasswordPrompts=1", user + "@" + host, remoteCommand,
            })
            {
                psi.ArgumentList.Add(arg);
            }

            psi.Environment["SUT_SSH_PASSWORD"] = password;
            psi.Environment["SSH_ASKPASS"] = askpass;
            psi.Environment["SSH_ASKPASS_REQUIRE"] = "force";
            psi.Environment["DISPLAY"] = "dummy";
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(askpass, UnixFileMode.UserRead | UnixFileMode.UserExecute);
            }

            return Execute(psi, password + "\n", out output);
        }
        finally
        {
            try { File.Delete(askpass); } catch { }
        }
    }

    private bool RunWindows(string script, out string output)
    {
        // The credential is built inside the child process from an environment variable, not the command line.
        string wrapper =
            "$ErrorActionPreference='Stop';" +
            "$c=New-Object System.Management.Automation.PSCredential(('" + host + "\\" + user + "')," +
            "(ConvertTo-SecureString $env:SUT_WINRM_PASSWORD -AsPlainText -Force));" +
            "$o=New-PSSessionOption -OperationTimeout 20000 -OpenTimeout 10000;" +
            "Invoke-Command -ComputerName '" + host + "' -Credential $c -Authentication Negotiate -SessionOption $o" +
            " -ScriptBlock ([scriptblock]::Create('" + script.Replace("'", "''") + "'))|Out-String -Width 400";
        var psi = new ProcessStartInfo("powershell.exe")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add("-NoProfile");
        psi.ArgumentList.Add("-NonInteractive");
        psi.ArgumentList.Add("-EncodedCommand");
        psi.ArgumentList.Add(Convert.ToBase64String(Encoding.Unicode.GetBytes(wrapper)));
        psi.Environment["SUT_WINRM_PASSWORD"] = password;
        return Execute(psi, null, out output);
    }

    private bool Execute(ProcessStartInfo psi, string? stdin, out string output)
    {
        output = string.Empty;
        using Process? process = Process.Start(psi);
        if (process == null)
        {
            LastError = "process did not start";
            return false;
        }

        if (psi.RedirectStandardInput)
        {
            process.StandardInput.Write(stdin ?? string.Empty);
            process.StandardInput.Close();
        }

        // Read both streams asynchronously so a full pipe cannot block the child.
        var stderr = new StringBuilder();
        process.ErrorDataReceived += (_, e) => { if (e.Data != null) { stderr.AppendLine(e.Data); } };
        process.BeginErrorReadLine();
        var stdout = new StringBuilder();
        process.OutputDataReceived += (_, e) => { if (e.Data != null) { stdout.AppendLine(e.Data); } };
        process.BeginOutputReadLine();

        if (!process.WaitForExit(CommandTimeoutMilliseconds))
        {
            try { process.Kill(true); } catch { }
            LastError = "timed out";
            return false;
        }

        process.WaitForExit();
        output = stdout.ToString();
        if (process.ExitCode != 0)
        {
            LastError = "exit " + process.ExitCode + ": " + stderr.ToString().Trim();
            return false;
        }

        return true;
    }
}
