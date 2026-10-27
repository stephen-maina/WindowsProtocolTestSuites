// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;
using Microsoft.Protocols.TestSuites.Smbd.Diagnostics.RunnerHost;

// Loaded only by the executable regression fixture, never by normal runner invocations.
public static class StartupHook
{
    public static void Initialize()
    {
        string? fault = Environment.GetEnvironmentVariable("WPTS_RUNNER_STORAGE_FAULT");
        if (fault is null) return;
        Environment.SetEnvironmentVariable("DOTNET_STARTUP_HOOKS", null);
        if (fault == "console") Console.SetError(new FailedConsole());
        if (fault == "start")
            Program.DotnetExecutable = Path.Combine(AppContext.BaseDirectory, "missing-dotnet.exe");
        else if (fault is "copy" or "flush")
            Program.DotnetExecutable = Path.Combine(AppContext.BaseDirectory,
                "Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Runner.TestSupport.exe");
        Program.EvidenceStorage = new FaultStorage(fault);
    }

    private sealed class FaultStorage(string fault) : RunnerEvidenceStorage
    {
        private string? bootstrap;
        private void Fail(string path)
        {
            string directory = path + ".fault-directory";
            Directory.CreateDirectory(directory);
            // A genuine access/I/O failure without permissions or privileged operations.
            using FileStream unused = File.OpenWrite(directory);
        }

        public override void WriteText(string path, string content)
        {
            bootstrap = path;
            if (fault == "bootstrap") Fail(path);
            base.WriteText(path, content);
        }

        public override void CreateResultsDirectory(string path)
        {
            if (fault == "result-directory") Fail(path);
            base.CreateResultsDirectory(path);
        }

        public override Stream OpenOutput(string path)
        {
            if (fault == Path.GetFileNameWithoutExtension(path) + "-open") Fail(path);
            Stream output = base.OpenOutput(path);
            return fault == "copy" ? new FailingWriteStream(output, () => Fail(path)) : output;
        }

        public override void FlushOutput(Stream stream)
        {
            if (fault == "flush") Fail(bootstrap!);
            if (fault == "copy") { stream.Flush(); return; }
            if (fault is "append" or "console")
                File.WriteAllText(Path.Combine(Path.GetDirectoryName(bootstrap!)!, "results.trx"), "<invalid");
            base.FlushOutput(stream);
        }

        internal static class ChildProcess
        {
            public static int Main()
            {
                File.AppendAllText(Environment.GetEnvironmentVariable("WPTS_CHILD_MARKER")!, "started\n");
                File.WriteAllText(Path.Combine(Environment.GetEnvironmentVariable("WPTS_CHILD_EVIDENCE")!, "child-runtime.txt"),
                    System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription);
                Console.WriteLine(new string('O', 300_000) + "CHILD-STDOUT-END");
                Console.Error.WriteLine(new string('E', 300_000) + "CHILD-STDERR-END");
                return bool.Parse(Environment.GetEnvironmentVariable("WPTS_CHILD_FAIL")!) ? 1 : 0;
            }
        }

        public override void AppendText(string path, string content)
        {
            if (fault == "append") Fail(path);
            base.AppendText(path, content);
        }
    }

    private sealed class FailedConsole : StringWriter
    {
        public override void WriteLine(string? value) => throw new IOException("Synthetic diagnostic console failure.");
    }

    private sealed class FailingWriteStream(Stream inner, Action fail) : Stream
    {
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => inner.Length;
        public override long Position { get => inner.Position; set => throw new NotSupportedException(); }
        public override void Flush() => inner.Flush();
        public override System.Threading.Tasks.Task FlushAsync(System.Threading.CancellationToken token) =>
            inner.FlushAsync(token);
        public override void Write(byte[] buffer, int offset, int count) => fail();
        public override System.Threading.Tasks.ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer, System.Threading.CancellationToken token = default)
        {
            fail();
            return System.Threading.Tasks.ValueTask.CompletedTask;
        }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { if (disposing) inner.Dispose(); base.Dispose(disposing); }
    }
}
