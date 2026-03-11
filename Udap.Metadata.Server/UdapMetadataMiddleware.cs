#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Udap.Model;

namespace Udap.Metadata.Server;

/// <summary>
/// Middleware that dynamically handles UDAP metadata requests at any path ending
/// with .well-known/udap. This enables a single server to serve metadata for
/// multiple domains without pre-registering routes for each domain.
/// </summary>
public class UdapMetadataMiddleware<TUdapMetadataOptions, TUdapMetadata>
    where TUdapMetadataOptions : UdapMetadataOptions
    where TUdapMetadata : UdapMetadata
{
    private readonly RequestDelegate _next;

    private const string WellKnownUdap = "/" + UdapConstants.Discovery.DiscoveryEndpoint;
    private const string CommunitiesPath = "/" + UdapConstants.Discovery.DiscoveryEndpoint + "/communities";
    private const string CommunitiesAsHtmlPath = "/" + UdapConstants.Discovery.DiscoveryEndpoint + "/communities/ashtml";

    public UdapMetadataMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.PathBase.Add(context.Request.Path).Value ?? string.Empty;

        if (TryMatchSuffix(path, CommunitiesAsHtmlPath))
        {
            if (context.Request.Method == HttpMethods.Get)
            {
                var endpoint = context.RequestServices.GetRequiredService<UdapMetaDataEndpoint<TUdapMetadataOptions, TUdapMetadata>>();
                var result = endpoint.GetCommunitiesAsHtml(context);
                await result.ExecuteAsync(context);
                return;
            }

            if (context.Request.Method == HttpMethods.Options)
            {
                WriteCorsHeaders(context);
                return;
            }
        }
        else if (TryMatchSuffix(path, CommunitiesPath))
        {
            if (context.Request.Method == HttpMethods.Get)
            {
                var endpoint = context.RequestServices.GetRequiredService<UdapMetaDataEndpoint<TUdapMetadataOptions, TUdapMetadata>>();
                var result = endpoint.GetCommunities();
                await result.ExecuteAsync(context);
                return;
            }

            if (context.Request.Method == HttpMethods.Options)
            {
                WriteCorsHeaders(context);
                return;
            }
        }
        else if (TryMatchSuffix(path, WellKnownUdap))
        {
            if (context.Request.Method == HttpMethods.Get)
            {
                var community = context.Request.Query["community"].FirstOrDefault();
                var endpoint = context.RequestServices.GetRequiredService<UdapMetaDataEndpoint<TUdapMetadataOptions, TUdapMetadata>>();
                var result = await endpoint.Process(context, community, context.RequestAborted);

                if (result != null)
                {
                    await result.ExecuteAsync(context);
                }
                else
                {
                    context.Response.StatusCode = StatusCodes.Status404NotFound;
                }

                return;
            }

            if (context.Request.Method == HttpMethods.Options)
            {
                WriteCorsHeaders(context);
                return;
            }
        }

        await _next(context);
    }

    private static bool TryMatchSuffix(string path, string suffix)
    {
        return path.EndsWith(suffix, StringComparison.OrdinalIgnoreCase);
    }

    private static void WriteCorsHeaders(HttpContext context)
    {
        context.Response.Headers.Append("Allow", "GET, OPTIONS");
        context.Response.Headers.Append("Access-Control-Allow-Origin", "*");
        context.Response.Headers.Append("Access-Control-Allow-Methods", "GET, OPTIONS");
        context.Response.Headers.Append("Access-Control-Allow-Headers", "Content-Type, Authorization");
        context.Response.StatusCode = StatusCodes.Status204NoContent;
    }
}
