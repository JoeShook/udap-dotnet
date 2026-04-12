#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigil.Vault.Hosting;

/// <summary>
/// Defines a Transit signing key to be created in Vault.
/// </summary>
/// <param name="Name">Key name in Transit, e.g. "sigil-rsa-4096"</param>
/// <param name="Type">Vault key type, e.g. "rsa-4096", "ecdsa-p384"</param>
public record TransitKeySpec(string Name, string Type);
