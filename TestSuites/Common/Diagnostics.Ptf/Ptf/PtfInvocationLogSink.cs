// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Globalization;
using Microsoft.Protocols.TestTools;
using Microsoft.Protocols.TestTools.Logging;
using Microsoft.Protocols.TestSuites.Diagnostics.Logging;

namespace Microsoft.Protocols.TestSuites.Diagnostics.Ptf;

public sealed class PtfInvocationLogSink : LogSink
{
    public const string SinkName = "MS-SMBD-Diagnostics-InvocationRouter";

    private const string LogEntryKindKey = "LogEntryKind";
    private const string MessageKey = "Message";
    private const string CurrentTestCaseNameKey = "CurrentTestCaseName";
    private const string TestCaseNameKey = "TestCaseName";
    private const string TestNameKey = "TestName";
    private const string TimeStampKey = "TimeStamp";

    private readonly InvocationLogRouter router;

    public PtfInvocationLogSink(InvocationLogRouter router)
        : base(SinkName)
    {
        this.router = router ?? throw new ArgumentNullException(nameof(router));
    }

    public override bool NotifyImmediately => true;

    public override void Flush()
    {
    }

    protected override void OnWriteBeginGroup(Dictionary<string, object> information)
    {
        Route(information);
    }

    protected override void OnWriteEndGroup(Dictionary<string, object> information)
    {
        Route(information);
    }

    protected override void OnWriteEntry(Dictionary<string, object> information)
    {
        Route(information);
    }

    private void Route(Dictionary<string, object> information)
    {
        ArgumentNullException.ThrowIfNull(information);

        string? scopeKey = ReadText(information, CurrentTestCaseNameKey) ??
                           ReadText(information, TestCaseNameKey) ??
                           ReadText(information, TestNameKey);
        if (string.IsNullOrWhiteSpace(scopeKey))
        {
            return;
        }

        router.Route(
            scopeKey,
            ReadTimestamp(information),
            ReadKind(information),
            ReadText(information, MessageKey) ?? string.Empty);
    }

    private static string ReadKind(IReadOnlyDictionary<string, object> information)
    {
        if (!information.TryGetValue(LogEntryKindKey, out object? value) || value is null)
        {
            return LogEntryKind.Comment.ToString();
        }

        return value is LogEntryKind kind
            ? kind.ToString()
            : Convert.ToString(value, CultureInfo.InvariantCulture) ??
              LogEntryKind.Comment.ToString();
    }

    private static string? ReadText(
        IReadOnlyDictionary<string, object> information,
        string key)
    {
        return information.TryGetValue(key, out object? value) && value is string text
            ? text
            : null;
    }

    private static DateTimeOffset ReadTimestamp(
        IReadOnlyDictionary<string, object> information)
    {
        if (!information.TryGetValue(TimeStampKey, out object? value) || value is null)
        {
            return DateTimeOffset.UtcNow;
        }

        return value switch
        {
            DateTimeOffset timestamp => timestamp,
            DateTime timestamp => new DateTimeOffset(timestamp),
            _ => DateTimeOffset.UtcNow,
        };
    }
}
