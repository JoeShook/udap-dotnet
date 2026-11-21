#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.Extensions.Options;
using Udap.Model.Registration;
using Udap.Server.Registration;
using Udap.Tefca.Model;
using Udap.Util.Extensions;

namespace Udap.Tefca.Server;

/// <summary>
/// Validates that a TEFCA community registration uses a SAN URI containing
/// a valid Exchange Purpose (XP) code from the TEFCA Exchange Purposes SOP.
/// When <see cref="TefcaValidationOptions.RequiredCertificateOrganizationalUnits"/> has an entry
/// for the community, the software statement's <c>x5c[0]</c> must also carry one of the configured
/// subject organizational units.
///
/// <a href="https://rce.sequoiaproject.org/wp-content/uploads/2026/02/SOP-Facilitated-FHIR-Implementation-2.0-Draft-508.pdf#page=14">
/// SOP v2.0 — Section 6.11 Registration #5a</a>
/// </summary>
public class TefcaRegistrationValidator : ICommunityRegistrationValidator
{
    private readonly TefcaValidationOptions _options;

    public TefcaRegistrationValidator(IOptions<TefcaValidationOptions> options)
    {
        _options = options.Value;
    }

    /// <summary>
    /// Authorized XP codes per the Exchange Purposes (XPs) SOP v5.1 Table 1, sourced from
    /// <see cref="TefcaConstants.ExchangePurposeCodes.All"/>.
    /// </summary>
    private static readonly HashSet<string> ValidExchangePurposes = new(
        TefcaConstants.ExchangePurposeCodes.All,
        StringComparer.Ordinal);

    /// <inheritdoc />
    public bool AppliesToCommunity(string communityName)
        => _options.Communities.Contains(communityName);

    /// <inheritdoc />
    public Task<UdapDynamicClientRegistrationValidationResult?> ValidateAsync(
        UdapDynamicClientRegistrationContext context)
    {
        var requiredOrganizationalUnits = _options.GetRequiredOrganizationalUnits(context.CommunityName);

        if (requiredOrganizationalUnits != null
            && (context.ClientCertificate == null
                || !context.ClientCertificate.HasSubjectOrganizationalUnit(requiredOrganizationalUnits)))
        {
            return Task.FromResult<UdapDynamicClientRegistrationValidationResult?>(
                new UdapDynamicClientRegistrationValidationResult(
                    UdapDynamicClientRegistrationErrors.UnapprovedSoftwareStatement,
                    $"TEFCA certificate subject must include an organizational unit (OU) of: {string.Join(", ", requiredOrganizationalUnits)}"));
        }

        var issuer = context.Issuer;

        if (string.IsNullOrEmpty(issuer))
        {
            return Task.FromResult<UdapDynamicClientRegistrationValidationResult?>(
                new UdapDynamicClientRegistrationValidationResult(
                    UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement,
                    "TEFCA registration requires a SAN URI with an exchange purpose"));
        }

        var hashIndex = issuer.LastIndexOf('#');
        if (hashIndex < 0 || hashIndex == issuer.Length - 1)
        {
            return Task.FromResult<UdapDynamicClientRegistrationValidationResult?>(
                new UdapDynamicClientRegistrationValidationResult(
                    UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement,
                    "TEFCA SAN URI must contain an exchange purpose code after '#'"));
        }

        var xpCode = issuer.Substring(hashIndex + 1);

        if (!ValidExchangePurposes.Contains(xpCode))
        {
            return Task.FromResult<UdapDynamicClientRegistrationValidationResult?>(
                new UdapDynamicClientRegistrationValidationResult(
                    UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement,
                    $"TEFCA SAN URI contains invalid exchange purpose code '{xpCode}'"));
        }

        return Task.FromResult<UdapDynamicClientRegistrationValidationResult?>(null);
    }
}
