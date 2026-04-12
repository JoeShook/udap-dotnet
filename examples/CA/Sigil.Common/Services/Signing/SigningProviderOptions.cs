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
    /// The active signing provider: "local" (default) or "vault-transit".
    /// </summary>
    public string Provider { get; set; } = "local";
}

/// <summary>
/// Configuration for connecting to Vault Transit.
/// </summary>
public class VaultTransitOptions
{
    /// <summary>
    /// Vault HTTP address, e.g. "http://localhost:8200".
    /// </summary>
    public string Address { get; set; } = "http://localhost:8200";

    /// <summary>
    /// Authentication token for Vault API calls.
    /// </summary>
    public string Token { get; set; } = string.Empty;

    /// <summary>
    /// Mount path for the Transit engine. Defaults to "transit".
    /// </summary>
    public string MountPath { get; set; } = "transit";
}
