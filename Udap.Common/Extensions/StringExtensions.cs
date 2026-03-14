#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Diagnostics;

namespace Udap.Common.Extensions;

/// <summary>
/// String extension methods for URL manipulation and validation used throughout the UDAP SDK.
/// </summary>
public static class StringExtensions
{
    /// <summary>
    /// Ensures the URL ends with a trailing forward slash.
    /// </summary>
    /// <param name="url">The URL to check.</param>
    /// <returns>The URL with a guaranteed trailing slash.</returns>
    [DebuggerStepThrough]
    public static string EnsureTrailingSlash(this string url)
    {
        if (!url.EndsWith('/'))
        {
            return url + "/";
        }

        return url;
    }

    /// <summary>
    /// Ensures the path begins with a leading forward slash.
    /// Returns <see cref="string.Empty"/> if <paramref name="url"/> is <c>null</c>.
    /// </summary>
    /// <param name="url">The URL path to check.</param>
    /// <returns>The path with a guaranteed leading slash, or an empty string if null.</returns>
    [DebuggerStepThrough]
    public static string EnsureLeadingSlash(this string? url)
    {
        if (url != null && !url.StartsWith('/'))
        {
            return "/" + url;
        }

        return string.Empty;
    }

    /// <summary>
    /// Determines whether the string is not null, empty, or whitespace.
    /// </summary>
    /// <param name="value">The string to check.</param>
    /// <returns><c>true</c> if the string contains a non-whitespace value; otherwise <c>false</c>.</returns>
    [DebuggerStepThrough]
    public static bool IsPresent(this string? value)
    {
        return !string.IsNullOrWhiteSpace(value);
    }

    /// <summary>
    /// Determines whether the string is null, empty, or whitespace.
    /// </summary>
    /// <param name="value">The string to check.</param>
    /// <returns><c>true</c> if the string is null, empty, or whitespace; otherwise <c>false</c>.</returns>
    [DebuggerStepThrough]
    public static bool IsMissing(this string value)
    {
        return string.IsNullOrWhiteSpace(value);
    }

    /// <summary>
    /// Removes a trailing forward slash from the URL if present.
    /// </summary>
    /// <param name="url">The URL to trim.</param>
    /// <returns>The URL without a trailing slash.</returns>
    [DebuggerStepThrough]
    public static string RemoveTrailingSlash(this string url)
    {
        if (url.EndsWith('/'))
        {
            url = url.Substring(0, url.Length - 1);
        }

        return url;
    }

    /// <summary>
    /// Extracts the base URL from a UDAP metadata URL by stripping the
    /// <c>.well-known/udap</c> path segment.
    /// </summary>
    /// <param name="url">A UDAP metadata URL (e.g., <c>https://fhir.example.com/r4/.well-known/udap</c>).</param>
    /// <returns>The base URL (e.g., <c>https://fhir.example.com/r4</c>).</returns>
    [DebuggerStepThrough]
    public static string GetBaseUrlFromMetadataUrl(this string url)
    {
        var index = url.IndexOf(".well-known/udap", StringComparison.OrdinalIgnoreCase);
        if (index != -1)
        {
            url = url[..(index - 1)];
        }

        var uri = new Uri(url);

        return uri.OriginalString;
    }

    /// <summary>
    /// Extracts the <c>community</c> parameter value from a query string.
    /// </summary>
    /// <param name="queryPath">The query string (e.g., <c>community=udap://fhirlabs.net</c>).</param>
    /// <returns>The community value, or <c>null</c> if the parameter is not present.</returns>
    [DebuggerStepThrough]
    public static string? GetCommunityFromQueryParams(this string queryPath)
    {
        var parameters = queryPath.Split('&');

        var community = parameters.FirstOrDefault(x =>
            x.StartsWith("community=", StringComparison.OrdinalIgnoreCase));

        if (community == null)
        {
            return null;
        }

        return community.Split("=").LastOrDefault();
    }

    /// <summary>
    /// Removes all query string parameters from the URL, returning only the scheme, authority, and path.
    /// </summary>
    /// <param name="url">The URL to strip query parameters from.</param>
    /// <returns>The URL without query parameters.</returns>
    [DebuggerStepThrough]
    public static string RemoveQueryParameters(this string url)
    {
        var uri = new Uri(url);
        var path = $"{uri.Scheme}{Uri.SchemeDelimiter}{uri.Authority}{uri.AbsolutePath}";

        return path;
    }
}
