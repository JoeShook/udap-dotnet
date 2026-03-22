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
/// Configuration model for a trust anchor certificate file reference in the certificate store manifest.
/// </summary>
public class AnchoFile
{
    /// <summary>
    /// Gets or sets the file path relative to the application base directory (e.g., <c>CertStore/anchors/CA.cer</c>).
    /// </summary>
    public string? FilePath { get; set; }
}