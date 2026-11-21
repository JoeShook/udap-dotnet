#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using Udap.Model;
using Udap.Model.Registration;
using Udap.Server.Registration;
using Udap.Tefca.Model;

namespace Udap.Tefca.Server;

/// <summary>
/// Validates the TEFCA Basic App Certification
/// (<see cref="TefcaConstants.Certification.BasicAppCertificationUri"/>) after it passed the generic
/// UDAP certification checks:
/// <list type="bullet">
/// <item><c>certification_name</c> is <see cref="TefcaConstants.Certification.BasicAppCertificationName"/>,</item>
/// <item><c>exchange_purposes</c> is an array of exactly one exchange purpose that matches the exchange purpose
/// in the client's SAN URI (either the bare code or the code-system-qualified
/// <c>urn:oid:2.16.840.1.113883.3.7204.1.5.2.1#&lt;code&gt;</c> form), and</item>
/// <item><c>home_community_id</c> is present in <c>urn:oid:&lt;OID&gt;</c> form.</item>
/// </list>
///
/// <a href="https://rce.sequoiaproject.org/wp-content/uploads/2026/02/SOP-Facilitated-FHIR-Implementation-2.0-Draft-508.pdf#page=14">
/// SOP v2.0 — Section 6.11 Registration #6</a>
/// </summary>
public class TefcaBasicAppCertificationValidator : IUdapCertificationProfileValidator
{
    private static readonly Regex UrnOidPattern = new(
        @"^urn:oid:[0-2](\.(0|[1-9][0-9]*))+$",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly string QualifiedExchangePurposePrefix = $"urn:oid:{TefcaConstants.ExchangePurposeCodes.Oid}#";

    private readonly TefcaValidationOptions _options;

    public TefcaBasicAppCertificationValidator(IOptions<TefcaValidationOptions> options)
    {
        _options = options.Value;
    }

    /// <inheritdoc />
    public string CertificationUri => TefcaConstants.Certification.BasicAppCertificationUri;

    /// <inheritdoc />
    public bool AppliesToCommunity(string communityName)
        => _options.Communities.Contains(communityName);

    /// <inheritdoc />
    public bool IsRequiredForCommunity(string communityName)
        => _options.RequireBasicAppCertification && AppliesToCommunity(communityName);

    /// <inheritdoc />
    public Task<UdapDynamicClientRegistrationValidationResult?> ValidateAsync(
        UdapDynamicClientRegistrationContext context,
        UdapValidatedCertification certification)
    {
        using var payload = certification.GetPayload();
        var root = payload.RootElement;

        if (!root.TryGetProperty(UdapConstants.CertificationAndEndorsementDocumentValues.CertificationName, out var name) ||
            name.ValueKind != JsonValueKind.String ||
            !string.Equals(name.GetString(), TefcaConstants.Certification.BasicAppCertificationName, StringComparison.Ordinal))
        {
            return Invalid($"TEFCA Basic App Certification certification_name must be '{TefcaConstants.Certification.BasicAppCertificationName}'");
        }

        if (!root.TryGetProperty(TefcaConstants.Certification.ExchangePurposes, out var exchangePurposes) ||
            exchangePurposes.ValueKind != JsonValueKind.Array ||
            exchangePurposes.GetArrayLength() != 1 ||
            exchangePurposes[0].ValueKind != JsonValueKind.String)
        {
            return Invalid("TEFCA Basic App Certification exchange_purposes must hold exactly one exchange purpose");
        }

        var certificationXp = NormalizeExchangePurpose(exchangePurposes[0].GetString());
        var sanXp = GetSanExchangePurpose(context.Issuer);

        if (certificationXp == null || sanXp == null ||
            !string.Equals(certificationXp, sanXp, StringComparison.Ordinal))
        {
            return Invalid(
                $"TEFCA Basic App Certification exchange purpose '{exchangePurposes[0].GetString()}' does not match the exchange purpose '{sanXp}' in the client's SAN");
        }

        if (!root.TryGetProperty(TefcaConstants.Certification.HomeCommunityId, out var homeCommunityId) ||
            homeCommunityId.ValueKind != JsonValueKind.String ||
            !UrnOidPattern.IsMatch(homeCommunityId.GetString() ?? string.Empty))
        {
            return Invalid("TEFCA Basic App Certification home_community_id must be present in urn:oid:<OID> form");
        }

        return Task.FromResult<UdapDynamicClientRegistrationValidationResult?>(null);
    }

    /// <summary>
    /// Returns the exchange purpose code from either the bare code or the code-system-qualified form,
    /// or null when the value is empty or qualified with a different code system.
    /// </summary>
    internal static string? NormalizeExchangePurpose(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        if (value.StartsWith(QualifiedExchangePurposePrefix, StringComparison.Ordinal))
        {
            var code = value.Substring(QualifiedExchangePurposePrefix.Length);
            return code.Length == 0 ? null : code;
        }

        return value.Contains('#') || value.Contains(':') ? null : value;
    }

    private string? GetSanExchangePurpose(string? issuer)
    {
        if (string.IsNullOrEmpty(issuer))
        {
            return null;
        }

        var hashIndex = issuer.LastIndexOf('#');

        return hashIndex < 0 || hashIndex == issuer.Length - 1 ? null : issuer.Substring(hashIndex + 1);
    }

    private static Task<UdapDynamicClientRegistrationValidationResult?> Invalid(string description)
        => Task.FromResult<UdapDynamicClientRegistrationValidationResult?>(
            new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement,
                description));
}
