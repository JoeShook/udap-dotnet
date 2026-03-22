#region (c) 2025 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Common.Models;

/// <summary>
/// Represents a client registered through UDAP Tiered OAuth, linking a downstream
/// client to an upstream Identity Provider for federated authentication.
/// </summary>
public class TieredClient
{
    /// <summary>Gets or sets the database identifier.</summary>
    public int Id { get; set; }

    /// <summary>Gets or sets the client display name.</summary>
    public string? ClientName { get; set; }

    /// <summary>Gets or sets the OAuth client identifier issued during registration.</summary>
    public string? ClientId { get; set; }

    /// <summary>Gets or sets the base URL of the upstream Identity Provider.</summary>
    public string? IdPBaseUrl { get; set; }

    /// <summary>Gets or sets the redirect URI registered with the upstream IdP.</summary>
    public string? RedirectUri { get; set; }

    /// <summary>Gets or sets the URI Subject Alternative Name from the client certificate.</summary>
    public string? ClientUriSan { get; set; }

    /// <summary>Gets or sets the community identifier this tiered client belongs to.</summary>
    public int CommunityId { get; set; }

    /// <summary>Gets or sets whether this tiered client registration is enabled.</summary>
    public bool Enabled { get; set; }

    /// <summary>Gets or sets the token endpoint URL of the upstream Identity Provider.</summary>
    public string? TokenEndpoint { get; set; }
}