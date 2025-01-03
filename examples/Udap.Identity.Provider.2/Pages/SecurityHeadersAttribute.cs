// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.


using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Udap.Server;

namespace Udap.Identity.Provider.Pages;

public class SecurityHeadersAttribute : ActionFilterAttribute
{
    public override async Task OnResultExecutionAsync(ResultExecutingContext context, ResultExecutionDelegate next)
    {
        var result = context.Result;

        if (result is PageResult)
        {
            var interaction = context.HttpContext.RequestServices.GetRequiredService<IIdentityServerInteractionService>();
            var grants = await interaction.GetAllUserGrantsAsync();
            var clients = context.HttpContext.RequestServices.GetRequiredService<IClientStore>();
            var logoList = new List<string>();

            foreach (var grant in grants)
            {
                var client = await clients.FindClientByIdAsync(grant.ClientId);
                if (client != null && client.ClientSecrets.Any(s => s.Type == UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME))
                {
                    if (client.LogoUri != null)
                    {
                        logoList.Add(client.LogoUri);
                    }
                }
            }

            // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options
            if (!context.HttpContext.Response.Headers.ContainsKey("X-Content-Type-Options"))
            {
                context.HttpContext.Response.Headers["X-Content-Type-Options"] = "nosniff";
            }

            // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
            if (!context.HttpContext.Response.Headers.ContainsKey("X-Frame-Options"))
            {
                context.HttpContext.Response.Headers["X-Frame-Options"] = "SAMEORIGIN";
            }

            // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
            var csp = "default-src 'self'; object-src 'none'; frame-ancestors 'none'; sandbox allow-forms allow-same-origin allow-scripts; base-uri 'self';";
            // also consider adding upgrade-insecure-requests once you have HTTPS in place for production
            //csp += "upgrade-insecure-requests;";
            // also an example if you need client images to be displayed from twitter
            csp += $"img-src 'self' {string.Join(' ', logoList)};";

            // once for standards compliant browsers
            if (!context.HttpContext.Response.Headers.ContainsKey("Content-Security-Policy"))
            {
                context.HttpContext.Response.Headers["Content-Security-Policy"] = csp;
            }
            // and once again for IE
            if (!context.HttpContext.Response.Headers.ContainsKey("X-Content-Security-Policy"))
            {
                context.HttpContext.Response.Headers["X-Content-Security-Policy"] = csp;
            }

            // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
            if (!context.HttpContext.Response.Headers.ContainsKey("Referrer-Policy"))
            {
                context.HttpContext.Response.Headers["Referrer-Policy"] = "no-referrer";
            }
        }

        await base.OnResultExecutionAsync(context, next);
    }
}