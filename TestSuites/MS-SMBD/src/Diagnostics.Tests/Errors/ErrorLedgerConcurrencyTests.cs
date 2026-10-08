// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using Microsoft.Protocols.TestSuites.Diagnostics.Errors;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.Errors;

[TestClass]
public sealed class ErrorLedgerConcurrencyTests
{
    [TestMethod]
    public void RecordProtocolError_ConcurrentCallers_PreservesExactlyOnePrimary_Issue64410323()
    {
        const int callerCount = 32;
        var ledger = new DiagnosticErrorLedger();
        using var ready = new CountdownEvent(callerCount);
        using var start = new ManualResetEventSlim();
        int accepted = 0;
        var unexpected = new ConcurrentQueue<Exception>();
        IReadOnlyList<Thread> threads = Enumerable.Range(0, callerCount)
            .Select(index => new Thread(() =>
            {
                ready.Signal();
                start.Wait();
                try
                {
                    ledger.RecordProtocolError(
                        $"Protocol-{index}",
                        "Concurrent protocol failure.",
                        DateTimeOffset.UtcNow);
                    Interlocked.Increment(ref accepted);
                }
                catch (InvalidOperationException)
                {
                }
                catch (Exception exception)
                {
                    unexpected.Enqueue(exception);
                }
            }))
            .ToArray();

        foreach (Thread thread in threads)
        {
            thread.Start();
        }

        ready.Wait();
        start.Set();
        foreach (Thread thread in threads)
        {
            thread.Join();
        }

        Assert.AreEqual(0, unexpected.Count);
        Assert.AreEqual(1, accepted);
        Assert.AreEqual(1, ledger.Chronology.Count);
    }

    [TestMethod]
    public void Record_ConcurrentSecondaryErrors_PreservesCompleteUniqueChronology_Issue64410323()
    {
        const int callerCount = 32;
        const int errorsPerCaller = 100;
        var ledger = new DiagnosticErrorLedger();
        using var ready = new CountdownEvent(callerCount);
        using var start = new ManualResetEventSlim();
        var unexpected = new ConcurrentQueue<Exception>();
        IReadOnlyList<Thread> threads = Enumerable.Range(0, callerCount)
            .Select(caller => new Thread(() =>
            {
                ready.Signal();
                start.Wait();
                try
                {
                    for (int index = 0; index < errorsPerCaller; index++)
                    {
                        ledger.Record(
                            DiagnosticErrorCategory.Storage,
                            $"Storage-{caller}-{index}",
                            "Concurrent storage failure.",
                            DateTimeOffset.UtcNow);
                    }
                }
                catch (Exception exception)
                {
                    unexpected.Enqueue(exception);
                }
            }))
            .ToArray();

        foreach (Thread thread in threads)
        {
            thread.Start();
        }

        ready.Wait();
        start.Set();
        foreach (Thread thread in threads)
        {
            thread.Join();
        }

        DiagnosticError[] chronology = ledger.Chronology.ToArray();
        Assert.AreEqual(0, unexpected.Count);
        Assert.AreEqual(callerCount * errorsPerCaller, chronology.Length);
        Assert.AreEqual(chronology.Length, chronology.Select(error => error.Sequence).Distinct().Count());
        CollectionAssert.AreEqual(
            Enumerable.Range(1, chronology.Length).Select(value => (long)value).ToArray(),
            chronology.Select(error => error.Sequence).OrderBy(value => value).ToArray());
    }
}
