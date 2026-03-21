#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Udap.Common.Models;

namespace Udap.Common.Certificates;

/// <summary>
/// Provides access to trust anchor (root CA) certificates used to validate
/// UDAP certificate chains during discovery and registration.
/// </summary>
public interface ITrustAnchorStore
{
    /// <summary>
    /// Gets or sets the collection of trust anchor certificates. Each anchor represents
    /// a root of trust for one or more UDAP communities.
    /// </summary>
    ICollection<Anchor> AnchorCertificates { get; set; }

    /// <summary>
    /// Loads and resolves trust anchor certificates from the backing store.
    /// Must be called before accessing <see cref="AnchorCertificates"/>.
    /// </summary>
    /// <returns>The resolved trust anchor store instance.</returns>
    Task<ITrustAnchorStore> Resolve();
}