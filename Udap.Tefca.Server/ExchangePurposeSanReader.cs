#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Udap.Tefca.Model;

namespace Udap.Tefca.Server;

/// <summary>
/// Outcome of reading an exchange purpose from a SAN URI.
/// </summary>
public enum ExchangePurposeReadStatus
{
    /// <summary>A valid exchange purpose code was found.</summary>
    Valid,

    /// <summary>No exchange purpose was found at the configured location.</summary>
    Missing,

    /// <summary>A value was found at the configured location but it is not a known exchange purpose code.</summary>
    Invalid,

    /// <summary>More than one distinct exchange purpose code was found at the configured location.</summary>
    Ambiguous
}

/// <summary>
/// Result of <see cref="ExchangePurposeSanReader.Read(string?, TefcaValidationOptions)"/>.
/// </summary>
/// <param name="Status">The outcome.</param>
/// <param name="Code">The exchange purpose code when <see cref="Status"/> is <see cref="ExchangePurposeReadStatus.Valid"/>,
/// or the rejected value when it is <see cref="ExchangePurposeReadStatus.Invalid"/>.</param>
/// <param name="ErrorDescription">A human readable reason when the read did not succeed.</param>
public sealed record ExchangePurposeReadResult(
    ExchangePurposeReadStatus Status,
    string? Code,
    string? ErrorDescription)
{
    /// <summary>True when a valid exchange purpose code was found.</summary>
    public bool IsValid => Status == ExchangePurposeReadStatus.Valid;
}

/// <summary>
/// Reads the TEFCA Exchange Purpose (XP) code from a client certificate SAN URI.
/// Shared by <see cref="TefcaRegistrationValidator"/> and <see cref="TefcaTokenValidator"/>
/// so registration and token validation always agree on the client's exchange purpose.
///
/// The location is selected by <see cref="TefcaValidationOptions.ExchangePurposeLocation"/>.
/// Codes are checked against <see cref="TefcaConstants.ExchangePurposeCodes.All"/>.
///
/// <a href="https://rce.sequoiaproject.org/wp-content/uploads/2026/02/SOP-Facilitated-FHIR-Implementation-2.0-Draft-508.pdf#page=14">
/// SOP v2.0 — Section 6.11 Registration #5a</a>
/// </summary>
public static class ExchangePurposeSanReader
{
    private static readonly HashSet<string> ValidExchangePurposes = new(
        TefcaConstants.ExchangePurposeCodes.All,
        StringComparer.Ordinal);

    /// <summary>
    /// Reads the exchange purpose from <paramref name="sanUri"/> using the location configured in <paramref name="options"/>.
    /// </summary>
    public static ExchangePurposeReadResult Read(string? sanUri, TefcaValidationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        return Read(sanUri, options.ExchangePurposeLocation, options.ExchangePurposeQueryParameter);
    }

    /// <summary>
    /// Reads the exchange purpose from <paramref name="sanUri"/> at the given <paramref name="location"/>.
    /// </summary>
    /// <param name="sanUri">The client certificate SAN URI.</param>
    /// <param name="location">Where the exchange purpose is carried.</param>
    /// <param name="queryParameterName">The query parameter name, used when <paramref name="location"/>
    /// is <see cref="ExchangePurposeLocation.QueryParameter"/>.</param>
    public static ExchangePurposeReadResult Read(
        string? sanUri,
        ExchangePurposeLocation location,
        string? queryParameterName = null)
    {
        if (string.IsNullOrEmpty(sanUri))
        {
            return Missing("SAN URI is empty");
        }

        return location switch
        {
            ExchangePurposeLocation.Fragment => ReadFragment(sanUri),
            ExchangePurposeLocation.PathSegment => ReadPathSegment(sanUri),
            ExchangePurposeLocation.QueryParameter => ReadQueryParameter(sanUri, queryParameterName),
            _ => throw new ArgumentOutOfRangeException(nameof(location), location, "Unknown exchange purpose location")
        };
    }

    /// <summary>
    /// True when <paramref name="code"/> is a known exchange purpose code.
    /// </summary>
    public static bool IsValidExchangePurpose(string? code)
        => code != null && ValidExchangePurposes.Contains(code);

    private static ExchangePurposeReadResult ReadFragment(string sanUri)
    {
        var hashIndex = sanUri.LastIndexOf('#');
        if (hashIndex < 0 || hashIndex == sanUri.Length - 1)
        {
            return Missing("SAN URI must contain an exchange purpose code after '#'");
        }

        return Validate(sanUri.Substring(hashIndex + 1));
    }

    private static ExchangePurposeReadResult ReadPathSegment(string sanUri)
    {
        var path = GetPath(sanUri);
        string? found = null;

        foreach (var rawSegment in path.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            var segment = Unescape(rawSegment);
            if (!ValidExchangePurposes.Contains(segment))
            {
                continue;
            }

            if (found != null && !string.Equals(found, segment, StringComparison.Ordinal))
            {
                return new ExchangePurposeReadResult(
                    ExchangePurposeReadStatus.Ambiguous,
                    null,
                    $"SAN URI path contains more than one exchange purpose code ('{found}', '{segment}')");
            }

            found = segment;
        }

        return found != null
            ? new ExchangePurposeReadResult(ExchangePurposeReadStatus.Valid, found, null)
            : Missing("SAN URI path must contain a segment that is a valid exchange purpose code");
    }

    private static ExchangePurposeReadResult ReadQueryParameter(string sanUri, string? queryParameterName)
    {
        if (string.IsNullOrWhiteSpace(queryParameterName))
        {
            return Missing("no exchange purpose query parameter name is configured");
        }

        var query = GetQuery(sanUri);
        string? value = null;

        foreach (var pair in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var equalsIndex = pair.IndexOf('=');
            var name = UnescapeQuery(equalsIndex < 0 ? pair : pair.Substring(0, equalsIndex));
            if (!string.Equals(name, queryParameterName, StringComparison.Ordinal))
            {
                continue;
            }

            var candidate = equalsIndex < 0 ? string.Empty : UnescapeQuery(pair.Substring(equalsIndex + 1));
            if (value != null && !string.Equals(value, candidate, StringComparison.Ordinal))
            {
                return new ExchangePurposeReadResult(
                    ExchangePurposeReadStatus.Ambiguous,
                    null,
                    $"SAN URI query parameter '{queryParameterName}' is repeated with different values");
            }

            value = candidate;
        }

        if (string.IsNullOrEmpty(value))
        {
            return Missing($"SAN URI must contain an exchange purpose code in query parameter '{queryParameterName}'");
        }

        return Validate(value);
    }

    private static ExchangePurposeReadResult Validate(string code)
    {
        return ValidExchangePurposes.Contains(code)
            ? new ExchangePurposeReadResult(ExchangePurposeReadStatus.Valid, code, null)
            : new ExchangePurposeReadResult(
                ExchangePurposeReadStatus.Invalid,
                code,
                $"SAN URI contains invalid exchange purpose code '{code}'");
    }

    private static ExchangePurposeReadResult Missing(string description)
        => new(ExchangePurposeReadStatus.Missing, null, description);

    /// <summary>
    /// The URI without its fragment and query, and without its scheme and authority.
    /// For a URN (no "//" authority) this is everything after the scheme, e.g.
    /// <c>oid:2.999/T-TRTMNT</c> for <c>urn:oid:2.999/T-TRTMNT</c>.
    /// </summary>
    private static string GetPath(string sanUri)
    {
        var end = sanUri.IndexOfAny(['?', '#']);
        var withoutQuery = end < 0 ? sanUri : sanUri.Substring(0, end);

        var schemeEnd = withoutQuery.IndexOf(':');
        var rest = schemeEnd < 0 ? withoutQuery : withoutQuery.Substring(schemeEnd + 1);

        if (rest.StartsWith("//", StringComparison.Ordinal))
        {
            var pathStart = rest.IndexOf('/', 2);
            return pathStart < 0 ? string.Empty : rest.Substring(pathStart);
        }

        return rest;
    }

    private static string GetQuery(string sanUri)
    {
        var hashIndex = sanUri.IndexOf('#');
        var withoutFragment = hashIndex < 0 ? sanUri : sanUri.Substring(0, hashIndex);

        var queryIndex = withoutFragment.IndexOf('?');
        return queryIndex < 0 ? string.Empty : withoutFragment.Substring(queryIndex + 1);
    }

    private static string UnescapeQuery(string value)
        => Unescape(value.Replace('+', ' '));

    private static string Unescape(string value)
    {
        try
        {
            return Uri.UnescapeDataString(value);
        }
        catch (UriFormatException)
        {
            return value;
        }
    }
}
