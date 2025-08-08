#region (c) 2025 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Common.Models;

public class TieredClient
{
    public int Id { get; set; }
    public string? ClientName { get; set; }
    public string? ClientId { get; set; }
    public string? IdPBaseUrl { get; set; }
    public string? RedirectUri { get; set; }

    public string? ClientUriSan { get; set; }

    public int CommunityId { get; set; }
    public bool Enabled { get; set; }

    public string? TokenEndpoint { get; set; }
}