// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Runtime.CompilerServices;
using Microsoft.Protocols.TestTools;
using Microsoft.Protocols.TestTools.Logging;
using Microsoft.Protocols.TestSuites.Diagnostics.Logging;

namespace Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Ptf;

public sealed class PtfInvocationLogBridge
{
    private static readonly object SyncRoot = new();
    private static readonly ConditionalWeakTable<ILogger, PtfInvocationLogBridge> Bridges = new();
    private static readonly SharedInvocationLogRouterRegistry Routers = new();

    private PtfInvocationLogBridge(ILogger logger)
    {
        Router = Routers.GetOrCreate(logger, static () => new InvocationLogRouter());
        Sink = new PtfInvocationLogSink(Router);
        RegisterSink(logger, Sink);
    }

    public InvocationLogRouter Router { get; }

    public PtfInvocationLogSink Sink { get; }

    public static PtfInvocationLogBridge GetOrCreate(ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(logger);

        lock (SyncRoot)
        {
            return Bridges.GetValue(
                logger,
                static currentLogger => new PtfInvocationLogBridge(currentLogger));
        }
    }

    private static void RegisterSink(ILogger logger, PtfInvocationLogSink sink)
    {
        LogProfile profile = logger.LogProfile;
        if (!profile.IsSinkExist(PtfInvocationLogSink.SinkName))
        {
            profile.AddSink(PtfInvocationLogSink.SinkName, sink);
        }

        string activeProfile = logger.ActiveLoggingProfile;
        foreach (LogEntryKind kind in Enum.GetValues<LogEntryKind>())
        {
            if (logger.IsActive(kind))
            {
                profile.AddProfileEntry(activeProfile, kind, PtfInvocationLogSink.SinkName);
            }
        }
    }
}
