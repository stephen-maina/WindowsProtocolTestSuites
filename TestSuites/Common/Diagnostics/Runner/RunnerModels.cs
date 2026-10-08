// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using Microsoft.Protocols.TestSuites.Diagnostics.Configuration;
using Microsoft.Protocols.TestSuites.Diagnostics.Identity;
using Microsoft.Protocols.TestSuites.Diagnostics.Providers;
using Microsoft.Protocols.TestSuites.Diagnostics.Storage;

namespace Microsoft.Protocols.TestSuites.Diagnostics.Runner;

public static class RunnerCorrelationMetadata
{
    public const string InvocationId = "invocationId";
    public const string RunId = "runner.runId";
    public const string ManagedTestIdentitySha256 =
        "runner.managedTestIdentitySha256";
    public const string TestDisplayNameSha256 =
        "runner.testDisplayNameSha256";
    public const string AttemptIdentity = "runner.attemptIdentity";
    public const string OutcomeAuthority = "outcomeAuthority";
    public const string ReconciliationStatus = "runner.reconciliationStatus";
    public const string CandidateCount = "runner.candidateCount";
    public const string TrxSha256 = "runner.trxSha256";
    public const string TrxRunId = "runner.trxRunId";
    public const string TestId = "runner.testId";
    public const string ExecutionId = "runner.executionId";

    internal static string ComputeSha256(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    }

    internal static string ComputeManagedTestIdentity(
        string managedType,
        string managedMethod)
    {
        return ComputeSha256(
            managedType + "\n" + NormalizeManagedMethod(managedMethod));
    }

    private static string NormalizeManagedMethod(string managedMethod)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(managedMethod);

        int openParenthesis = managedMethod.IndexOf('(');
        if (openParenthesis <= 0 ||
            managedMethod[^1] != ')' ||
            managedMethod.IndexOf(')', openParenthesis) !=
                managedMethod.Length - 1)
        {
            return managedMethod;
        }

        ReadOnlySpan<char> methodName =
            managedMethod.AsSpan(0, openParenthesis);
        ReadOnlySpan<char> signature = managedMethod.AsSpan(
            openParenthesis + 1,
            managedMethod.Length - openParenthesis - 2);
        if (!IsManagedIdentifier(methodName) ||
            !IsParameterSignature(signature))
        {
            return managedMethod;
        }

        return methodName.ToString();
    }

    private static bool IsManagedIdentifier(ReadOnlySpan<char> value)
    {
        if (value.IsEmpty ||
            !(char.IsLetter(value[0]) || value[0] == '_'))
        {
            return false;
        }

        foreach (char character in value[1..])
        {
            if (!(char.IsLetterOrDigit(character) ||
                  character is '_' or '.' or '`'))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsParameterSignature(ReadOnlySpan<char> value)
    {
        int squareDepth = 0;
        int angleDepth = 0;
        foreach (char character in value)
        {
            if (char.IsControl(character) ||
                character is '"' or '\'' or '(' or ')')
            {
                return false;
            }

            switch (character)
            {
                case '[':
                    squareDepth++;
                    break;
                case ']':
                    squareDepth--;
                    break;
                case '<':
                    angleDepth++;
                    break;
                case '>':
                    angleDepth--;
                    break;
            }

            if (squareDepth < 0 || angleDepth < 0)
            {
                return false;
            }

            if (!(char.IsLetterOrDigit(character) ||
                  char.IsWhiteSpace(character) ||
                  character is '_' or '.' or ',' or '[' or ']' or
                      '<' or '>' or '`' or '+' or '&' or '*' or '?'))
            {
                return false;
            }
        }

        return squareDepth == 0 && angleDepth == 0;
    }
}

public static class RunnerRunContext
{
    public static string CreateRunId()
    {
        return "run-" + Guid.NewGuid().ToString("N");
    }

    public static string ValidateRunId(string runId)
    {
        ArgumentNullException.ThrowIfNull(runId);
        if (runId.Length != 36 ||
            !runId.StartsWith("run-", StringComparison.Ordinal) ||
            runId.AsSpan(4).IndexOfAnyExcept(
                "0123456789abcdefABCDEF".AsSpan()) >= 0)
        {
            throw new ArgumentException(
                "A runner-managed run ID must be 'run-' followed by 32 hexadecimal characters.",
                nameof(runId));
        }

        ArtifactPath.ValidateComponent(runId);
        return runId.ToLowerInvariant();
    }

    public static bool IsRunnerManaged(string runId)
    {
        if (runId is null)
        {
            return false;
        }

        try
        {
            _ = ValidateRunId(runId);
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (ArtifactStorageException)
        {
            return false;
        }
    }
}

public sealed class RunnerTestExecutionIdentity
{
    public RunnerTestExecutionIdentity(
        string managedType,
        string managedMethod,
        string testDisplayName,
        int testRunCount)
    {
        ManagedType = RequireIdentity(managedType, nameof(managedType));
        ManagedMethod = RequireIdentity(managedMethod, nameof(managedMethod));
        TestDisplayName = RequireIdentity(
            testDisplayName,
            nameof(testDisplayName));
        if (testRunCount < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(testRunCount),
                "The MSTest run count cannot be negative.");
        }

        TestRunCount = testRunCount;
    }

    public string ManagedType { get; }

    public string ManagedMethod { get; }

    public string TestDisplayName { get; }

    public int TestRunCount { get; }

    public InvocationIdentity CreateInvocationIdentity(string? runId)
    {
        string effectiveRunId = runId is null
            ? "ptf"
            : RunnerRunContext.ValidateRunId(runId);
        string testIdentity = ManagedType + "." + ManagedMethod;
        string attemptIdentity = TestRunCount.ToString(
            CultureInfo.InvariantCulture);
        string displayHash = RunnerCorrelationMetadata.ComputeSha256(
            TestDisplayName);
        string managedHash =
            RunnerCorrelationMetadata.ComputeManagedTestIdentity(
                ManagedType,
                ManagedMethod);

        return InvocationIdentity.CreateCorrelated(
            effectiveRunId,
            testIdentity,
            attemptIdentity,
            displayHash,
            managedHash,
            displayHash);
    }

    private static string RequireIdentity(
        string value,
        string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            value.Any(char.IsControl))
        {
            throw new ArgumentException(
                "A non-empty control-free runner identity is required.",
                parameterName);
        }

        return value;
    }
}

public sealed class RunnerExecutionPlan
{
    private RunnerExecutionPlan(
        bool isEnabled,
        string runId,
        string? artifactRoot,
        string? runRoot,
        string? buildOutputRoot)
    {
        IsEnabled = isEnabled;
        RunId = runId;
        ArtifactRoot = artifactRoot;
        RunRoot = runRoot;
        BuildOutputRoot = buildOutputRoot;
    }

    public bool IsEnabled { get; }

    public string RunId { get; }

    public string? ArtifactRoot { get; }

    public string? RunRoot { get; }

    public string? BuildOutputRoot { get; }

    public static RunnerExecutionPlan Create(
        string canonicalConfigurationPath,
        string deploymentConfigurationPath,
        string runId)
    {
        string normalizedRunId = RunnerRunContext.ValidateRunId(runId);
        bool enabled = RunnerPtfPolicyReader.ReadEnabled(
            canonicalConfigurationPath);
        if (!enabled)
        {
            return new RunnerExecutionPlan(
                isEnabled: false,
                normalizedRunId,
                artifactRoot: null,
                runRoot: null,
                buildOutputRoot: null);
        }

        RunnerPtfPolicyReader.EnsureDeploymentHasNoDiagnosticsPolicy(
            deploymentConfigurationPath);
        string artifactRoot = RunnerPtfPolicyReader.ReadArtifactRoot(
            canonicalConfigurationPath);
        if (!DiagnosticsConfigurationReader
                .TryNormalizeConcreteLocalPath(
                    artifactRoot,
                    allowDriveRoot: true,
                    allowTrailingSeparator: true,
                    DiagnosticsRuntimePlatformDetector.Detect(),
                    out string? normalizedArtifactRoot))
        {
            throw new RunnerConfigurationException(
                "The canonical diagnostics artifact root is invalid.");
        }

        string runRoot = ArtifactPath.CombineUnderRoot(
            normalizedArtifactRoot,
            normalizedRunId);
        string buildOutputRoot = Path.GetDirectoryName(
            Path.GetFullPath(canonicalConfigurationPath))
            ?? throw new RunnerConfigurationException(
                "The canonical PTF configuration path has no parent directory.");
        return new RunnerExecutionPlan(
            isEnabled: true,
            normalizedRunId,
            normalizedArtifactRoot,
            runRoot,
            buildOutputRoot);
    }
}

public sealed class RunnerProvenance
{
    private RunnerProvenance(
        IReadOnlyList<string> binarySha256,
        string filterSha256,
        string canonicalConfigurationSha256,
        string deploymentConfigurationSha256)
    {
        BinarySha256 = binarySha256;
        FilterSha256 = filterSha256;
        CanonicalConfigurationSha256 = canonicalConfigurationSha256;
        DeploymentConfigurationSha256 = deploymentConfigurationSha256;
    }

    public IReadOnlyList<string> BinarySha256 { get; }

    public string FilterSha256 { get; }

    public string CanonicalConfigurationSha256 { get; }

    public string DeploymentConfigurationSha256 { get; }

    public static RunnerProvenance Create(
        IEnumerable<string> binaryPaths,
        string? filter,
        string canonicalConfigurationPath,
        string deploymentConfigurationPath)
    {
        ArgumentNullException.ThrowIfNull(binaryPaths);
        string[] binaries = binaryPaths.ToArray();
        if (binaries.Length == 0 ||
            binaries.Any(string.IsNullOrWhiteSpace))
        {
            throw new ArgumentException(
                "At least one test binary path is required.",
                nameof(binaryPaths));
        }

        string[] binaryHashes = binaries
            .Select(ComputeFileSha256)
            .OrderBy(hash => hash, StringComparer.Ordinal)
            .ToArray();
        return new RunnerProvenance(
            Array.AsReadOnly(binaryHashes),
            RunnerCorrelationMetadata.ComputeSha256(filter ?? string.Empty),
            ComputeFileSha256(canonicalConfigurationPath),
            ComputeFileSha256(deploymentConfigurationPath));
    }

    internal static string ComputeFileSha256(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException(
                "A file path is required.",
                nameof(path));
        }

        using FileStream stream = new(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 81920,
            FileOptions.SequentialScan);
        return Convert.ToHexString(SHA256.HashData(stream));
    }
}

public sealed class RunnerArtifactLayout
{
    private RunnerArtifactLayout(
        string runRoot,
        string runnerRoot,
        string testsRoot)
    {
        RunRoot = runRoot;
        RunnerRoot = runnerRoot;
        TestsRoot = testsRoot;
        StdoutPath = Path.Combine(runnerRoot, "stdout.log");
        StderrPath = Path.Combine(runnerRoot, "stderr.log");
        BootstrapPath = Path.Combine(runnerRoot, "bootstrap.log");
        TrxPath = Path.Combine(runnerRoot, "results.trx");
    }

    public string RunRoot { get; }

    public string RunnerRoot { get; }

    public string TestsRoot { get; }

    public string StdoutPath { get; }

    public string StderrPath { get; }

    public string BootstrapPath { get; }

    public string TrxPath { get; }

    public static RunnerArtifactLayout Create(
        RunnerExecutionPlan plan,
        string sourceRoot)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentException.ThrowIfNullOrWhiteSpace(sourceRoot);
        if (!plan.IsEnabled ||
            plan.ArtifactRoot is null ||
            plan.RunRoot is null ||
            plan.BuildOutputRoot is null)
        {
            throw new InvalidOperationException(
                "Runner artifacts cannot be created while diagnostics are disabled.");
        }

        string runnerRoot = ArtifactPath.CombineUnderRoot(
            plan.RunRoot,
            "runner");
        string testsRoot = ArtifactPath.CombineUnderRoot(
            plan.RunRoot,
            "tests");
        using ArtifactStore artifactStore = ArtifactStore.Open(
            plan.ArtifactRoot,
            sourceRoot,
            plan.BuildOutputRoot);
        try
        {
            Directory.CreateDirectory(plan.RunRoot);
            ArtifactPath.EnsureNoReparsePoints(
                plan.ArtifactRoot,
                plan.RunRoot);
            Directory.CreateDirectory(runnerRoot);
            Directory.CreateDirectory(testsRoot);
            ArtifactPath.EnsureNoReparsePoints(
                plan.ArtifactRoot,
                runnerRoot);
            ArtifactPath.EnsureNoReparsePoints(
                plan.ArtifactRoot,
                testsRoot);
        }
        catch (IOException exception)
        {
            throw new RunnerEvidenceException(
                "The runner artifact layout could not be created.",
                exception);
        }
        catch (UnauthorizedAccessException exception)
        {
            throw new RunnerEvidenceException(
                "The runner artifact layout could not be created.",
                exception);
        }

        return new RunnerArtifactLayout(
            plan.RunRoot,
            runnerRoot,
            testsRoot);
    }
}

public sealed class RunnerConfigurationException : InvalidOperationException
{
    public RunnerConfigurationException(string message)
        : base(message)
    {
    }

    public RunnerConfigurationException(
        string message,
        Exception innerException)
        : base(message, innerException)
    {
    }
}

public sealed class RunnerEvidenceException : InvalidOperationException
{
    public RunnerEvidenceException(string message)
        : base(message)
    {
    }

    public RunnerEvidenceException(
        string message,
        Exception innerException)
        : base(message, innerException)
    {
    }
}

internal static class RunnerPtfPolicyReader
{
    private const string PtfNamespace =
        "http://schemas.microsoft.com/windows/ProtocolsTest/2007/07/TestConfig";

    public static bool ReadEnabled(string canonicalConfigurationPath)
    {
        string? raw = ReadSingleProperty(
            canonicalConfigurationPath,
            DiagnosticsConfigurationPropertyNames.Enabled);
        if (string.IsNullOrEmpty(raw))
        {
            return false;
        }

        if (raw.Any(char.IsControl) ||
            !bool.TryParse(raw.Trim(), out bool enabled))
        {
            throw new RunnerConfigurationException(
                "The canonical Diagnostics.Enabled value is invalid.");
        }

        return enabled;
    }

    public static string ReadArtifactRoot(
        string canonicalConfigurationPath)
    {
        string? value = ReadSingleProperty(
            canonicalConfigurationPath,
            DiagnosticsConfigurationPropertyNames.ArtifactRoot);
        if (string.IsNullOrEmpty(value))
        {
            throw new RunnerConfigurationException(
                "Enabled diagnostics require one canonical artifact root.");
        }

        return value;
    }

    public static void EnsureDeploymentHasNoDiagnosticsPolicy(
        string deploymentConfigurationPath)
    {
        try
        {
            using XmlReader reader = CreateReader(deploymentConfigurationPath);
            while (reader.Read())
            {
                if (!IsPropertyElement(reader))
                {
                    continue;
                }

                string? name = reader.GetAttribute("name");
                if (name?.StartsWith(
                        "Diagnostics.",
                        StringComparison.Ordinal) == true)
                {
                    throw new RunnerConfigurationException(
                        "The deployment PTF configuration must not define diagnostics policy.");
                }
            }
        }
        catch (XmlException exception)
        {
            throw new RunnerConfigurationException(
                "The deployment PTF configuration is malformed.",
                exception);
        }
    }

    private static string? ReadSingleProperty(
        string path,
        string propertyName)
    {
        string? value = null;
        bool found = false;
        try
        {
            using XmlReader reader = CreateReader(path);
            while (reader.Read())
            {
                if (!IsPropertyElement(reader) ||
                    !string.Equals(
                        reader.GetAttribute("name"),
                        propertyName,
                        StringComparison.Ordinal))
                {
                    continue;
                }

                if (found)
                {
                    throw new RunnerConfigurationException(
                        $"The canonical PTF configuration defines '{propertyName}' more than once.");
                }

                value = reader.GetAttribute("value");
                found = true;
            }
        }
        catch (XmlException exception)
        {
            throw new RunnerConfigurationException(
                "The canonical PTF configuration is malformed.",
                exception);
        }

        return value;
    }

    private static XmlReader CreateReader(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException(
                "A PTF configuration path is required.",
                nameof(path));
        }

        try
        {
            return XmlReader.Create(
                path,
                new XmlReaderSettings
                {
                    DtdProcessing = DtdProcessing.Prohibit,
                    IgnoreComments = true,
                    IgnoreWhitespace = true,
                    MaxCharactersInDocument = 16 * 1024 * 1024,
                    XmlResolver = null,
                });
        }
        catch (IOException exception)
        {
            throw new RunnerConfigurationException(
                "The PTF configuration could not be read.",
                exception);
        }
        catch (UnauthorizedAccessException exception)
        {
            throw new RunnerConfigurationException(
                "The PTF configuration could not be read.",
                exception);
        }
    }

    private static bool IsPropertyElement(XmlReader reader)
    {
        return reader.NodeType == XmlNodeType.Element &&
               string.Equals(
                   reader.LocalName,
                   "Property",
                   StringComparison.Ordinal) &&
               string.Equals(
                   reader.NamespaceURI,
                   PtfNamespace,
                   StringComparison.Ordinal);
    }
}
