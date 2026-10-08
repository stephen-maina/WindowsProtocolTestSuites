// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Threading;

namespace Microsoft.Protocols.TestSuites.Diagnostics.Logging;

public sealed record InvocationLogRecord(
    long Sequence,
    DateTimeOffset Timestamp,
    string Kind,
    string Message);

public sealed class BoundedInvocationLogCollector
{
    private readonly object syncRoot = new();
    private readonly int capacity;
    private readonly int maxMessageLength;
    private readonly string[] sensitiveValues;
    private readonly List<InvocationLogRecord> records = new();
    private long nextSequence;

    public BoundedInvocationLogCollector(
        int capacity,
        int maxMessageLength,
        IEnumerable<string>? sensitiveValues = null)
    {
        if (capacity <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(capacity));
        }

        if (maxMessageLength <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxMessageLength));
        }

        this.capacity = capacity;
        this.maxMessageLength = maxMessageLength;
        this.sensitiveValues = sensitiveValues?
            .Where(value => !string.IsNullOrEmpty(value))
            .Distinct(StringComparer.Ordinal)
            .OrderByDescending(value => value.Length)
            .ToArray() ?? Array.Empty<string>();
    }

    public IReadOnlyList<InvocationLogRecord> Records
    {
        get
        {
            lock (syncRoot)
            {
                return records.ToArray();
            }
        }
    }

    public void Write(DateTimeOffset timestamp, string kind, string message)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(kind);
        ArgumentNullException.ThrowIfNull(message);

        string safeKind = Normalize(kind, 64);
        string safeMessage = Normalize(Redact(message), maxMessageLength);
        lock (syncRoot)
        {
            if (records.Count == capacity)
            {
                records.RemoveAt(0);
            }

            records.Add(
                new InvocationLogRecord(
                    Interlocked.Increment(ref nextSequence),
                    timestamp,
                    safeKind,
                    safeMessage));
        }
    }

    public string SerializeNdjson()
    {
        var builder = new StringBuilder();
        foreach (InvocationLogRecord record in Records)
        {
            builder.Append(JsonSerializer.Serialize(record));
            builder.Append('\n');
        }

        return builder.ToString();
    }

    private string Redact(string value)
    {
        foreach (string sensitiveValue in sensitiveValues)
        {
            value = value.Replace(
                sensitiveValue,
                "[REDACTED]",
                StringComparison.Ordinal);
        }

        return value;
    }

    private static string Normalize(string value, int maximumLength)
    {
        var builder = new StringBuilder(Math.Min(value.Length, maximumLength));
        foreach (char character in value)
        {
            if (builder.Length == maximumLength)
            {
                break;
            }

            builder.Append(char.IsControl(character) ? ' ' : character);
        }

        return builder.ToString();
    }
}

public sealed class InvocationLogRouter
{
    private readonly ConcurrentDictionary<string, BoundedInvocationLogCollector> routes =
        new(StringComparer.Ordinal);

    public IDisposable Register(
        string scopeKey,
        BoundedInvocationLogCollector target)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(scopeKey);
        ArgumentNullException.ThrowIfNull(target);
        if (!routes.TryAdd(scopeKey, target))
        {
            throw new InvalidOperationException(
                "A diagnostics log route is already active for this scope.");
        }

        return new Registration(this, scopeKey, target);
    }

    public bool Route(
        string scopeKey,
        DateTimeOffset timestamp,
        string kind,
        string message)
    {
        if (!string.IsNullOrWhiteSpace(scopeKey) &&
            routes.TryGetValue(scopeKey, out BoundedInvocationLogCollector? target))
        {
            target.Write(timestamp, kind, message);
            return true;
        }

        return false;
    }

    private sealed class Registration : IDisposable
    {
        private readonly InvocationLogRouter owner;
        private readonly string scopeKey;
        private readonly BoundedInvocationLogCollector target;
        private int disposed;

        internal Registration(
            InvocationLogRouter owner,
            string scopeKey,
            BoundedInvocationLogCollector target)
        {
            this.owner = owner;
            this.scopeKey = scopeKey;
            this.target = target;
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) == 0)
            {
                owner.routes.TryRemove(
                    new KeyValuePair<string, BoundedInvocationLogCollector>(
                        scopeKey,
                        target));
            }
        }
    }
}

public sealed class SharedInvocationLogRouterRegistry
{
    private readonly ConditionalWeakTable<object, InvocationLogRouter> routers = new();

    public InvocationLogRouter GetOrCreate(
        object owner,
        Func<InvocationLogRouter> factory)
    {
        ArgumentNullException.ThrowIfNull(owner);
        ArgumentNullException.ThrowIfNull(factory);
        return routers.GetValue(
            owner,
            _ => factory() ??
                throw new InvalidOperationException(
                    "The diagnostics log router factory returned null."));
    }
}
