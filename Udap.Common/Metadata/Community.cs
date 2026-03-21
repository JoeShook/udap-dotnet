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
/// Configuration model for a UDAP community in the file-based certificate store manifest.
/// </summary>
public class Community
{
    /// <summary>
    /// Gets or sets the community name, typically a URI (e.g., <c>udap://fhirlabs.net</c>).
    /// </summary>
    public string Name { get; set; } = "Default";

    /// <summary>
    /// Gets or sets the file paths to intermediate CA certificates, relative to the application base directory.
    /// </summary>
    public ICollection<string> Intermediates { get; set; } = [];

    /// <summary>
    /// Gets or sets the trust anchor certificate file references.
    /// </summary>
    public ICollection<AnchoFile> Anchors { get; set; } = [];

    /// <summary>
    /// Gets or sets the issued (end-entity) certificate file references with passwords.
    /// </summary>
    public ICollection<IssuedCertFile> IssuedCerts { get; set; } = [];
}