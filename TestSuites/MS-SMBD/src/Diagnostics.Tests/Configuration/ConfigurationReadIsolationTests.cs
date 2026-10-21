// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Protocols.TestSuites.Diagnostics.Configuration;
using Microsoft.Protocols.TestSuites.Diagnostics.Errors;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.Configuration;

[TestClass]
public sealed class ConfigurationReadIsolationTests
{
    private static readonly DateTimeOffset OccurredAt =
        new(2026, 10, 21, 0, 0, 0, TimeSpan.Zero);

    [TestMethod]
    public void Read_ValidConfigurationWithConcurrentCaptureError_RemainsEnabled()
    {
        var errors = new DiagnosticErrorLedger();
        var source = new TestEffectiveConfigurationSource(
            ValidValues(),
            property =>
            {
                if (property == DiagnosticsConfigurationPropertyNames.ArtifactRoot)
                {
                    Task.Run(() => errors.Record(
                        DiagnosticErrorCategory.Capture,
                        "UnrelatedCapture",
                        "Another capture failed.",
                        OccurredAt)).GetAwaiter().GetResult();
                }
            });

        DiagnosticsConfiguration configuration =
            DiagnosticsConfigurationReader.Read(source, errors, OccurredAt);

        Assert.AreEqual(DiagnosticsConfigurationState.Enabled, configuration.State);
        Assert.AreEqual("UnrelatedCapture", errors.Chronology.Single().Code);
        Assert.IsNotNull(configuration.Capture);
    }

    [TestMethod]
    public void Read_InvalidConfigurationWithConcurrentError_RemainsInvalidAndPreservesBothErrors()
    {
        var values = ValidValues();
        values[DiagnosticsConfigurationPropertyNames.Provider] = "unsupported-provider";
        var errors = new DiagnosticErrorLedger();
        var source = new TestEffectiveConfigurationSource(
            values,
            property =>
            {
                if (property == DiagnosticsConfigurationPropertyNames.MaxBytes)
                {
                    Task.Run(() => errors.Record(
                        DiagnosticErrorCategory.Storage,
                        "UnrelatedStorage",
                        "Another storage operation failed.",
                        OccurredAt)).GetAwaiter().GetResult();
                }
            });

        DiagnosticsConfiguration configuration =
            DiagnosticsConfigurationReader.Read(source, errors, OccurredAt);

        Assert.AreEqual(DiagnosticsConfigurationState.Invalid, configuration.State);
        CollectionAssert.AreEqual(
            new[] { DiagnosticsConfigurationErrorCodes.ProviderUnsupported, "UnrelatedStorage" },
            errors.Chronology.Select(error => error.Code).ToArray());
        Assert.IsNull(configuration.Capture);
    }

    [TestMethod]
    public void Read_SourceThrowsAfterValidationError_PreservesErrorAndPropagatesException()
    {
        var values = ValidValues();
        values[DiagnosticsConfigurationPropertyNames.Provider] = "unsupported-provider";
        var errors = new DiagnosticErrorLedger();
        var failure = new InvalidOperationException("Configuration source failed.");
        var source = new TestEffectiveConfigurationSource(
            values,
            property =>
            {
                if (property == DiagnosticsConfigurationPropertyNames.MaxBytes)
                {
                    Assert.AreEqual(
                        DiagnosticsConfigurationErrorCodes.ProviderUnsupported,
                        errors.Chronology.Single().Code);
                    throw failure;
                }
            });

        InvalidOperationException actual = Assert.ThrowsException<InvalidOperationException>(
            () => DiagnosticsConfigurationReader.Read(source, errors, OccurredAt));

        Assert.AreSame(failure, actual);
        Assert.AreEqual(
            DiagnosticsConfigurationErrorCodes.ProviderUnsupported,
            errors.Chronology.Single().Code);
    }

    [TestMethod]
    public void Read_ValidConfigurationWithPreexistingError_RemainsEnabled()
    {
        var errors = new DiagnosticErrorLedger();
        errors.RecordProtocolError("EarlierProtocol", "A protocol operation failed.", OccurredAt);

        DiagnosticsConfiguration configuration = DiagnosticsConfigurationReader.Read(
            new TestEffectiveConfigurationSource(ValidValues()),
            errors,
            OccurredAt);

        Assert.AreEqual(DiagnosticsConfigurationState.Enabled, configuration.State);
        Assert.AreSame(errors.Chronology.Single(), errors.PrimaryProtocolError);
    }

    private static Dictionary<string, string?> ValidValues() => new()
    {
        [DiagnosticsConfigurationPropertyNames.Enabled] = "true",
        [DiagnosticsConfigurationPropertyNames.ArtifactRoot] =
            Path.Combine(Path.GetTempPath(), "diagnostics-read-isolation"),
        [DiagnosticsConfigurationPropertyNames.Targets] = "192.0.2.1",
        [DiagnosticsConfigurationPropertyNames.StartTimeout] = "00:00:01",
        [DiagnosticsConfigurationPropertyNames.StopTimeout] = "00:00:01",
        [DiagnosticsConfigurationPropertyNames.MaxDuration] = "00:01:00",
        [DiagnosticsConfigurationPropertyNames.MaxBytes] = "1024",
    };
}
