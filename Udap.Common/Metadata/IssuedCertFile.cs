#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion


namespace Udap.Common.Metadata;

/// <summary>
/// Configuration model for an issued certificate file reference in the certificate store manifest.
/// </summary>
public class IssuedCertFile
{
    /// <summary>
    /// Gets or sets the file path relative to the application base directory (e.g., <c>CertStore/issued/client.pfx</c>).
    /// </summary>
    public string? FilePath { get; set; }

    /// <summary>
    /// Gets or sets the password to decrypt the PFX/PKCS#12 file. Required when the file is password-protected.
    /// </summary>
    public string? Password { get; set; }
}