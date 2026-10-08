// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;

namespace Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Ptf;

/// <summary>
/// Groups the artifacts of one test run ("session") under
/// <c>&lt;ArtifactRoot&gt;\&lt;session&gt;\tests\&lt;test&gt;__&lt;id&gt;</c> and optionally prunes
/// older sessions. Mirrors the layout used by the managed runner.
/// </summary>
public static class PtfSessionLayout
{
    public const string SessionNameProperty = "Diagnostics.SessionName";
    public const string MaxSessionsProperty = "Diagnostics.Retention.MaxSessions";
    public const string TimestampToken = "{timestamp}";
    public const string MarkerFileName = ".wpts-session";
    public const string TestsDirectoryName = "tests";

    private const string TimestampFormat = "yyyyMMdd-HHmmss";
    private const int MaximumSessionNameLength = 80;

    private static readonly ConcurrentDictionary<string, string> ResolvedSessions =
        new(StringComparer.Ordinal);
    private static readonly object PruneGate = new();
    private static readonly HashSet<string> PrunedRoots =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Resolves the session name once per process so every test in one run shares a session.
    /// An empty setting yields <c>session-&lt;timestamp&gt;</c>; <c>{timestamp}</c> in a custom
    /// name is replaced by the process-start timestamp. A fixed name is reused across runs.
    /// </summary>
    public static string ResolveSessionName(string? configured, DateTimeOffset now)
    {
        string key = configured?.Trim() ?? string.Empty;
        return ResolvedSessions.GetOrAdd(
            key,
            static (setting, state) =>
            {
                string timestamp = state.ToString(
                    TimestampFormat,
                    CultureInfo.InvariantCulture);
                string name = setting.Length == 0
                    ? "session-" + timestamp
                    : setting.Replace(
                        TimestampToken,
                        timestamp,
                        StringComparison.OrdinalIgnoreCase);
                return Sanitize(name);
            },
            now);
    }

    /// <summary>
    /// Creates (if needed) the session directory under <paramref name="artifactRoot"/>,
    /// prunes older sessions when a maximum is configured, and returns the directory
    /// that must be used as the per-test artifact root.
    /// </summary>
    public static string PrepareTestsRoot(
        string artifactRoot,
        NameValueCollection effectiveProperties,
        DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(artifactRoot);
        ArgumentNullException.ThrowIfNull(effectiveProperties);

        string sessionName = ResolveSessionName(
            effectiveProperties[SessionNameProperty],
            now);
        string sessionRoot = Path.Combine(artifactRoot, sessionName);
        Directory.CreateDirectory(sessionRoot);

        string marker = Path.Combine(sessionRoot, MarkerFileName);
        if (!File.Exists(marker))
        {
            File.WriteAllText(
                marker,
                now.ToString("o", CultureInfo.InvariantCulture));
        }
        else
        {
            File.SetLastWriteTimeUtc(marker, now.UtcDateTime);
        }

        int maxSessions = ReadMaxSessions(effectiveProperties[MaxSessionsProperty]);
        if (maxSessions > 0)
        {
            lock (PruneGate)
            {
                if (PrunedRoots.Add(artifactRoot + "|" + sessionName))
                {
                    PruneOldSessions(artifactRoot, sessionName, maxSessions);
                }
            }
        }

        return Path.Combine(sessionRoot, TestsDirectoryName);
    }

    public static int ReadMaxSessions(string? configured)
    {
        if (string.IsNullOrWhiteSpace(configured))
        {
            return 0;
        }

        return int.TryParse(
                configured.Trim(),
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out int value)
            ? value
            : 0;
    }

    public static void PruneOldSessions(
        string artifactRoot,
        string currentSessionName,
        int maxSessions)
    {
        try
        {
            var sessions = new DirectoryInfo(artifactRoot)
                .EnumerateDirectories()
                .Where(directory =>
                    (directory.Attributes & FileAttributes.ReparsePoint) == 0 &&
                    File.Exists(Path.Combine(directory.FullName, MarkerFileName)))
                .Select(directory => new
                {
                    Directory = directory,
                    Stamp = File.GetLastWriteTimeUtc(
                        Path.Combine(directory.FullName, MarkerFileName)),
                })
                .OrderByDescending(session => session.Stamp)
                .ThenByDescending(
                    session => session.Directory.Name,
                    StringComparer.Ordinal)
                .ToList();

            // The current session always counts as one of the retained sessions.
            IEnumerable<DirectoryInfo> expired = sessions
                .Where(session => !string.Equals(
                    session.Directory.Name,
                    currentSessionName,
                    StringComparison.OrdinalIgnoreCase))
                .Skip(Math.Max(0, maxSessions - 1))
                .Select(session => session.Directory);
            foreach (DirectoryInfo directory in expired)
            {
                try
                {
                    directory.Delete(recursive: true);
                }
                catch (Exception exception)
                    when (exception is IOException or UnauthorizedAccessException)
                {
                    // Best effort: a locked old session must not fail the test run.
                }
            }
        }
        catch (Exception exception)
            when (exception is IOException or UnauthorizedAccessException)
        {
            // Best effort retention.
        }
    }

    private static string Sanitize(string name)
    {
        var builder = new StringBuilder(Math.Min(name.Length, MaximumSessionNameLength));
        foreach (char character in name)
        {
            if (builder.Length == MaximumSessionNameLength)
            {
                break;
            }

            builder.Append(
                character is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9'
                    or '.' or '-' or '_'
                    ? character
                    : '_');
        }

        string sanitized = builder.ToString().Trim('.', ' ');
        return sanitized.Length == 0 ? "session" : sanitized;
    }
}
