#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Tefca.Server;

/// <summary>
/// Scope rules shared by the TEFCA registration and token validators.
/// </summary>
internal static class TefcaScopeRules
{
    /// <summary>
    /// SMART user-level scope prefix. TEFCA flows do not use user-level scopes.
    /// </summary>
    internal const string UserScopePrefix = "user/";

    /// <summary>
    /// Returns the <c>user/</c> scopes found in <paramref name="scopes"/>, in request order.
    /// </summary>
    internal static List<string> FindUserScopes(IEnumerable<string>? scopes)
    {
        if (scopes == null)
        {
            return [];
        }

        return scopes
            .Where(s => s.StartsWith(UserScopePrefix, StringComparison.Ordinal))
            .Distinct(StringComparer.Ordinal)
            .ToList();
    }

    /// <summary>
    /// Splits a space-delimited OAuth scope string.
    /// </summary>
    internal static IEnumerable<string> Split(string? scope)
        => string.IsNullOrWhiteSpace(scope)
            ? []
            : scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);

    internal static string Describe(IReadOnlyCollection<string> userScopes)
        => $"TEFCA does not permit user scopes: {string.Join(" ", userScopes)}";
}
