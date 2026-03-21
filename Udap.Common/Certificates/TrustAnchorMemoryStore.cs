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
/// In-memory implementation of <see cref="ITrustAnchorStore"/>. Anchor certificates
/// are populated directly in code rather than loaded from files.
/// </summary>
public class TrustAnchorMemoryStore : ITrustAnchorStore
{
    /// <inheritdoc />
    public ICollection<Anchor> AnchorCertificates { get; set; } = new HashSet<Anchor>();

    /// <inheritdoc />
    public Task<ITrustAnchorStore> Resolve()
    {
        return Task.FromResult(this as ITrustAnchorStore);
    }
}