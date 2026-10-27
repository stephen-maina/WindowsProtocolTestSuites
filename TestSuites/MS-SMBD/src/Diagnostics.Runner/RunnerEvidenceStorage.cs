// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.IO;
using System.Runtime.CompilerServices;
using System.Text;

[assembly: InternalsVisibleTo("Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Runner.TestSupport")]

namespace Microsoft.Protocols.TestSuites.Smbd.Diagnostics.RunnerHost;

internal class RunnerEvidenceStorage
{
    public virtual void CreateResultsDirectory(string path) => Directory.CreateDirectory(path);

    public virtual void WriteText(string path, string content) =>
        File.WriteAllText(path, content, new UTF8Encoding(false));

    public virtual void AppendText(string path, string content) =>
        File.AppendAllText(path, content, new UTF8Encoding(false));

    public virtual Stream OpenOutput(string path) =>
        new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read,
            81920, FileOptions.Asynchronous | FileOptions.WriteThrough);

    public virtual void FlushOutput(Stream stream) =>
        ((FileStream)stream).Flush(flushToDisk: true);
}
