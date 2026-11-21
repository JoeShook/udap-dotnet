#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Duende.IdentityServer.Configuration;
using Duende.IdentityServer.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.DependencyInjection;

namespace Udap.Server.Validation;

/// <summary>
/// The URLs a client may have been given for one of this server's endpoints. A JWT <c>aud</c> naming that
/// endpoint must equal one of them exactly (SSRAA 2.0 and later: case-sensitive, no normalization).
/// </summary>
/// <remarks>
/// More than one value is accepted so a reverse proxy does not cause false rejections: the request URL as the
/// server sees it, the endpoint derived from Duende's <see cref="IServerUrls.BaseUrl"/> (which honours a
/// configured origin and forwarded headers, and is what the OpenID discovery document advertises), and,
/// when given, a discovery custom entry such as the <c>registration_endpoint</c> added by
/// <c>AddRegistrationEndpointToOpenIdConnectMetadata</c>. Each value is compared verbatim.
/// </remarks>
internal static class AdvertisedEndpointUris
{
    public static IReadOnlyList<string> Resolve(HttpContext? context, string routePath, string? discoveryCustomEntry = null)
    {
        var uris = new List<string>();

        if (context == null)
        {
            return uris;
        }

        uris.Add(context.Request.GetDisplayUrl());

        var services = context.RequestServices;

        var baseUrl = services?.GetService<IServerUrls>()?.BaseUrl;
        if (!string.IsNullOrEmpty(baseUrl))
        {
            uris.Add(baseUrl.TrimEnd('/') + "/" + routePath);
        }

        if (discoveryCustomEntry != null &&
            services?.GetService<IdentityServerOptions>()?.Discovery.CustomEntries
                .TryGetValue(discoveryCustomEntry, out var advertised) == true &&
            advertised is string advertisedUri &&
            !string.IsNullOrEmpty(advertisedUri))
        {
            uris.Add(advertisedUri);
        }

        return uris.Distinct(StringComparer.Ordinal).ToList();
    }
}
