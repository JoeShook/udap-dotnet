#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Common;

/// <summary>
/// Configuration section name constants for binding UDAP settings from <c>appsettings.json</c>.
/// </summary>
public static class Constants
{
    /// <summary>
    /// Configuration section name for the file-based certificate store manifest.
    /// </summary>
    public const string UdapFileCertStoreManifestSectionName = "UdapFileCertStoreManifest";

    /// <summary>
    /// Configuration section name for UDAP metadata endpoint options.
    /// </summary>
    public const string UdapMetadataOptionsSectionName = "UdapMetadataOptions";
}
