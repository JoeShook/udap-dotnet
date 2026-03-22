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
/// Provides access to both trust anchor certificates and issued (end-entity) certificates
/// used for UDAP certificate validation and signing operations.
/// </summary>
public interface ICertificateStore
{
    /// <summary>
    /// Gets or sets the collection of trust anchor certificates used to validate certificate chains.
    /// </summary>
    ICollection<Anchor> AnchorCertificates { get; set; }

    /// <summary>
    /// Gets or sets the collection of issued end-entity certificates used for signing operations.
    /// </summary>
    ICollection<IssuedCertificate> IssuedCertificates { get; set; }

    /// <summary>
    /// Loads and resolves certificates from the backing store.
    /// Must be called before accessing <see cref="AnchorCertificates"/> or <see cref="IssuedCertificates"/>.
    /// </summary>
    /// <returns>The resolved certificate store instance.</returns>
    Task<ICertificateStore> Resolve();
}
