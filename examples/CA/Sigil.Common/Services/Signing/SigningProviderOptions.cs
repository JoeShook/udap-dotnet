#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigil.Common.Services.Signing;

/// <summary>
/// Configuration for signing provider selection.
/// </summary>
public class SigningProviderOptions
{
    /// <summary>
    /// The active signing provider: "local", "vault-transit", or "gcp-kms".
    /// </summary>
    public string Provider { get; set; } = "local";
}
