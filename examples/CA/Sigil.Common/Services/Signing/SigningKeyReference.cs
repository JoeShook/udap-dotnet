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
/// Identifies a signing key across provider boundaries.
/// </summary>
/// <param name="Provider">Provider name: "local" or "vault-transit"</param>
/// <param name="KeyIdentifier">
/// For local: a GUID referencing an in-memory key holder.
/// For Vault Transit: the Transit key name (e.g. "sigil-rsa-4096").
/// </param>
/// <param name="KeyAlgorithm">"RSA" or "ECDSA"</param>
/// <param name="KeySize">Key size in bits (2048, 4096, etc.)</param>
public record SigningKeyReference(
    string Provider,
    string KeyIdentifier,
    string KeyAlgorithm,
    int KeySize);
