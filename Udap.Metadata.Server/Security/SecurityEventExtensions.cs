#region (c) 2025 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.AspNetCore.Builder;

namespace Udap.Metadata.Server.Security;

public static class SecurityEventExtensions
{
    /// <summary>
    /// Adds middleware that logs structured security events for both successful and failed authentication.
    /// Should be called after <c>UseAuthentication()</c> and before <c>UseAuthorization()</c>.
    /// </summary>
    public static IApplicationBuilder UseSecurityEventLogging(this IApplicationBuilder app)
    {
        return app.UseMiddleware<SecurityEventMiddleware>();
    }
}
