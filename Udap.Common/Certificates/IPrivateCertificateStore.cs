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
/// Provides access to issued (end-entity) certificates with private keys,
/// used for signing UDAP metadata and software statements.
/// </summary>
public interface IPrivateCertificateStore
{
    /// <summary>
    /// Gets or sets the collection of issued certificates available for signing operations.
    /// </summary>
    ICollection<IssuedCertificate> IssuedCertificates { get; set; }

    /// <summary>
    /// Loads and resolves certificates from the backing store.
    /// Must be called before accessing <see cref="IssuedCertificates"/>.
    /// </summary>
    /// <param name="token">A cancellation token to cancel the resolve operation.</param>
    /// <returns>The resolved certificate store instance.</returns>
    Task<IPrivateCertificateStore> Resolve(CancellationToken token);
}