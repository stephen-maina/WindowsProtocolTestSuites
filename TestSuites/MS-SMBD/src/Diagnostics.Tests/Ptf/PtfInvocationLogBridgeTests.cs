// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using Microsoft.Protocols.TestTools;
using Microsoft.Protocols.TestTools.Logging;
using Microsoft.Protocols.TestSuites.Diagnostics.Logging;
using Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Ptf;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.Ptf;

[TestClass]
public sealed class PtfInvocationLogBridgeTests
{
    [TestMethod]
    public void GetOrCreate_RegistersOneSharedSinkWithoutReplacingExistingProfile()
    {
        var logger = new TestLogger(
            "Default",
            new[] { LogEntryKind.Comment, LogEntryKind.Warning });
        var existingSink = new RecordingLogSink("existing");
        logger.LogProfile.AddSink(existingSink.Name, existingSink);
        logger.LogProfile.AddProfileEntry(
            logger.ActiveLoggingProfile,
            LogEntryKind.Comment,
            existingSink.Name);

        PtfInvocationLogBridge first = PtfInvocationLogBridge.GetOrCreate(logger);
        PtfInvocationLogBridge second = PtfInvocationLogBridge.GetOrCreate(logger);

        Assert.AreSame(first, second);
        Assert.AreEqual(2, logger.LogProfile.AllSinks.Count);
        Assert.IsTrue(
            logger.LogProfile.ProfilesMap[logger.ActiveLoggingProfile][existingSink.Name]
                .Contains(LogEntryKind.Comment));
        Assert.IsTrue(
            logger.LogProfile.ProfilesMap[logger.ActiveLoggingProfile][PtfInvocationLogSink.SinkName]
                .Contains(LogEntryKind.Comment));
        Assert.IsTrue(
            logger.LogProfile.ProfilesMap[logger.ActiveLoggingProfile][PtfInvocationLogSink.SinkName]
                .Contains(LogEntryKind.Warning));
    }

    [TestMethod]
    public void Sink_RoutesOnlyScopedRecordsAndSurvivesInvocationRouteDisposal()
    {
        var router = new InvocationLogRouter();
        var sink = new PtfInvocationLogSink(router);
        var alpha = new BoundedInvocationLogCollector(10, 256);
        var beta = new BoundedInvocationLogCollector(10, 256);
        using IDisposable alphaRoute = router.Register("alpha", alpha);
        using IDisposable betaRoute = router.Register("beta", beta);

        sink.WriteEntry(CreateEntry("alpha", LogEntryKind.Comment, "alpha-message"));
        sink.WriteEntry(CreateEntry("other", LogEntryKind.Warning, "other-message"));
        sink.WriteEntry(CreateEntry(null, LogEntryKind.Warning, "unscoped-message"));
        alphaRoute.Dispose();
        sink.WriteEntry(CreateEntry("alpha", LogEntryKind.Comment, "late-message"));
        sink.WriteEntry(CreateEntry("beta", LogEntryKind.Warning, "beta-message"));

        Assert.AreEqual(1, alpha.Records.Count);
        Assert.AreEqual("alpha-message", alpha.Records[0].Message);
        Assert.AreEqual(1, beta.Records.Count);
        Assert.AreEqual("beta-message", beta.Records[0].Message);
        Assert.IsTrue(sink.NotifyImmediately);
    }

    [TestMethod]
    public void Sink_RoutesGroupMarkersWithoutCrossInvocationState()
    {
        var router = new InvocationLogRouter();
        var sink = new PtfInvocationLogSink(router);
        var alpha = new BoundedInvocationLogCollector(10, 256);
        var beta = new BoundedInvocationLogCollector(10, 256);
        using IDisposable alphaRoute = router.Register("alpha", alpha);
        using IDisposable betaRoute = router.Register("beta", beta);

        sink.WriteEntry(CreateEntry("alpha", LogEntryKind.BeginGroup, "alpha-begin"));
        sink.WriteEntry(CreateEntry("beta", LogEntryKind.BeginGroup, "beta-begin"));
        sink.WriteEntry(CreateEntry("alpha", LogEntryKind.EndGroup, "alpha-end"));
        sink.WriteEntry(CreateEntry("beta", LogEntryKind.EndGroup, "beta-end"));

        CollectionAssert.AreEqual(
            new[] { "alpha-begin", "alpha-end" },
            GetMessages(alpha));
        CollectionAssert.AreEqual(
            new[] { "beta-begin", "beta-end" },
            GetMessages(beta));
    }

    [TestMethod]
    public void Sink_HostileScope_DoesNotInvokeConversionOrRoute()
    {
        var router = new InvocationLogRouter();
        var sink = new PtfInvocationLogSink(router);
        var collector = new BoundedInvocationLogCollector(10, 256);
        using IDisposable route = router.Register("scope-a", collector);
        var scope = new HostileValue();
        Dictionary<string, object> entry =
            CreateEntry("scope-a", LogEntryKind.Comment, "message");
        entry["CurrentTestCaseName"] = scope;

        sink.WriteEntry(entry);

        Assert.AreEqual(0, scope.ConversionAttempts);
        Assert.AreEqual(0, collector.Records.Count);
    }

    [TestMethod]
    public void Sink_HostileMessage_DoesNotInvokeConversionAndUsesEmptyFallback()
    {
        var router = new InvocationLogRouter();
        var sink = new PtfInvocationLogSink(router);
        var collector = new BoundedInvocationLogCollector(10, 256);
        using IDisposable route = router.Register("scope-a", collector);
        var message = new HostileValue();
        Dictionary<string, object> entry =
            CreateEntry("scope-a", LogEntryKind.Warning, "message");
        entry["Message"] = message;

        sink.WriteEntry(entry);

        Assert.AreEqual(0, message.ConversionAttempts);
        Assert.AreEqual(1, collector.Records.Count);
        Assert.AreEqual(
            LogEntryKind.Warning.ToString(),
            collector.Records[0].Kind);
        Assert.AreEqual(string.Empty, collector.Records[0].Message);
    }

    private static Dictionary<string, object> CreateEntry(
        string? scope,
        LogEntryKind kind,
        string message)
    {
        var information = new Dictionary<string, object>
        {
            ["LogEntryKind"] = kind,
            ["Message"] = message,
            ["TimeStamp"] = DateTimeOffset.UtcNow,
        };
        if (scope is not null)
        {
            information["CurrentTestCaseName"] = scope;
        }

        return information;
    }

    private static string[] GetMessages(BoundedInvocationLogCollector collector)
    {
        var messages = new string[collector.Records.Count];
        for (int index = 0; index < messages.Length; index++)
        {
            messages[index] = collector.Records[index].Message;
        }

        return messages;
    }

    private sealed class TestLogger : ILogger
    {
        private readonly HashSet<LogEntryKind> activeKinds;

        internal TestLogger(string profileName, IEnumerable<LogEntryKind> activeKinds)
        {
            ActiveLoggingProfile = profileName;
            this.activeKinds = new HashSet<LogEntryKind>(activeKinds);
            LogProfile = new LogProfile();
            LogProfile.ProfilesMap.Add(
                profileName,
                new Dictionary<string, List<LogEntryKind>>(StringComparer.Ordinal));
        }

        public ITestSite Site => null!;

        public string ActiveLoggingProfile { get; set; }

        public LogProfile LogProfile { get; }

        public void Add(LogEntryKind kind, string format, params object[] args)
        {
        }

        public void AddTestStatistic()
        {
        }

        public void Dispose()
        {
        }

        public bool IsActive(LogEntryKind kind)
        {
            return activeKinds.Contains(kind);
        }
    }

    private sealed class HostileValue
    {
        internal int ConversionAttempts { get; private set; }

        public override string ToString()
        {
            ConversionAttempts++;
            throw new InvalidOperationException(
                "Conversion should not be attempted.");
        }
    }

    private sealed class RecordingLogSink : LogSink
    {
        internal RecordingLogSink(string name)
            : base(name)
        {
        }

        public override void Flush()
        {
        }

        protected override void OnWriteBeginGroup(Dictionary<string, object> information)
        {
        }

        protected override void OnWriteEndGroup(Dictionary<string, object> information)
        {
        }

        protected override void OnWriteEntry(Dictionary<string, object> information)
        {
        }
    }
}
