#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion


using Udap.Common.Metadata;

namespace Udap.Common;

/// <summary>
/// Configuration model for the file-based certificate store, typically bound from
/// the <c>UdapFileCertStoreManifest</c> section in <c>appsettings.json</c>.
/// </summary>
public class UdapFileCertStoreManifest
{
    /// <summary>
    /// Gets or sets the communities, each defining trust anchors, intermediates, and issued certificates.
    /// </summary>
    public ICollection<Community> Communities { get; set; } = [];
}