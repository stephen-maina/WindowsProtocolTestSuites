// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Protocols.TestSuites.FileSharing.SMB2Model.TestSuite
{
    /// <summary>
    /// WHAT: Shadows Microsoft.Protocols.TestTools.PtfTestClassBase for every test class in this namespace.
    /// WHY: C# resolves a type name in the enclosing namespace before using directives, so all (generated) SMB2Model
    /// test classes pick up the shared diagnostics without editing each file.
    /// SPEC: Not protocol behaviour.
    /// </summary>
    public abstract class PtfTestClassBase : Common.TestSuite.FileServerPtfTestClassBase
    {
    }
}
