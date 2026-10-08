// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.Protocols.TestSuites.Diagnostics.Errors;

public enum DiagnosticErrorCategory
{
    Protocol,
    Capture,
    Storage,
    Cleanup,
    Finalization,
}

public sealed class DiagnosticError
{
    internal DiagnosticError(
        long sequence,
        DiagnosticErrorCategory category,
        string code,
        string message,
        DateTimeOffset occurredAt)
    {
        Sequence = sequence;
        Category = category;
        Code = RequireText(code, nameof(code));
        Message = RequireText(message, nameof(message));
        OccurredAt = occurredAt;
    }

    public long Sequence { get; }

    public DiagnosticErrorCategory Category { get; }

    public string Code { get; }

    public string Message { get; }

    public DateTimeOffset OccurredAt { get; }

    private static string RequireText(string value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("A non-empty value is required.", parameterName);
        }

        return value;
    }
}

public sealed class DiagnosticErrorLedger
{
    private const long MaximumSequence = long.MaxValue - 1;
    private readonly List<DiagnosticError> errors = new();
    private readonly object syncRoot = new();
    private DiagnosticError? primaryProtocolError;
    private long nextSequence = 1;

    public DiagnosticError? PrimaryProtocolError
    {
        get
        {
            lock (syncRoot)
            {
                return primaryProtocolError;
            }
        }
    }

    public IReadOnlyList<DiagnosticError> Chronology
    {
        get
        {
            lock (syncRoot)
            {
                return errors
                    .OrderBy(error => error.Sequence)
                    .ToArray();
            }
        }
    }

    public DiagnosticError RecordProtocolError(
        string code,
        string message,
        DateTimeOffset occurredAt)
    {
        lock (syncRoot)
        {
            if (primaryProtocolError is not null)
            {
                throw new DuplicatePrimaryProtocolErrorException(
                    primaryProtocolError.Code,
                    code);
            }

            DiagnosticError error = Create(
                DiagnosticErrorCategory.Protocol,
                code,
                message,
                occurredAt);
            primaryProtocolError = error;
            return error;
        }
    }

    public DiagnosticError Record(
        DiagnosticErrorCategory category,
        string code,
        string message,
        DateTimeOffset occurredAt)
    {
        if (category == DiagnosticErrorCategory.Protocol)
        {
            throw new ArgumentException(
                "Protocol errors must be recorded with RecordProtocolError so the primary error cannot be overwritten.",
                nameof(category));
        }

        lock (syncRoot)
        {
            return Create(category, code, message, occurredAt);
        }
    }

    internal DiagnosticError Restore(
        long sequence,
        DiagnosticErrorCategory category,
        string code,
        string message,
        DateTimeOffset occurredAt)
    {
        lock (syncRoot)
        {
            if (sequence <= 0 || sequence > MaximumSequence)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(sequence),
                    "A persisted error sequence must be positive and leave room for subsequent errors.");
            }

            if (sequence < nextSequence)
            {
                throw new InvalidOperationException(
                    "Persisted error sequences must be unique and strictly increasing.");
            }

            if (category == DiagnosticErrorCategory.Protocol &&
                primaryProtocolError is not null)
            {
                throw new DuplicatePrimaryProtocolErrorException(
                    primaryProtocolError.Code,
                    code);
            }

            var error = new DiagnosticError(
                sequence,
                category,
                code,
                message,
                occurredAt);
            errors.Add(error);
            if (category == DiagnosticErrorCategory.Protocol)
            {
                primaryProtocolError = error;
            }

            nextSequence = sequence + 1;
            return error;
        }
    }

    private DiagnosticError Create(
        DiagnosticErrorCategory category,
        string code,
        string message,
        DateTimeOffset occurredAt)
    {
        if (nextSequence > MaximumSequence)
        {
            throw new InvalidOperationException(
                "The diagnostic error sequence space is exhausted.");
        }

        var error = new DiagnosticError(
            nextSequence++,
            category,
            code,
            message,
            occurredAt);
        errors.Add(error);
        return error;
    }
}

public sealed class DuplicatePrimaryProtocolErrorException : InvalidOperationException
{
    public DuplicatePrimaryProtocolErrorException(
        string existingCode,
        string attemptedCode)
        : base(
            $"A primary protocol error with code '{existingCode}' is already recorded; " +
            $"the attempted primary error '{attemptedCode}' was rejected.")
    {
        ExistingCode = existingCode;
        AttemptedCode = attemptedCode;
    }

    public string ExistingCode { get; }

    public string AttemptedCode { get; }
}
