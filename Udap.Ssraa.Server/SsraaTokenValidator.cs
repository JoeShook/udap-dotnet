#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.Extensions.Options;
using Udap.Server.Validation;

namespace Udap.Ssraa.Server;

/// <summary>
/// Validates standard SSRAA community token request rules:
///
/// 1. Enforces required extensions per grant type (configurable via <see cref="SsraaValidationOptions"/>).
/// 2. Validates purpose_of_use codes against the HL7 v3 PurposeOfUse value set
///    (OID: 2.16.840.1.113883.5.8).
///
/// <a href="https://terminology.hl7.org/ValueSet-v3-PurposeOfUse.html">
/// HL7 v3 PurposeOfUse Value Set</a>
/// </summary>
public class SsraaTokenValidator : ICommunityTokenValidator
{
    private readonly SsraaValidationOptions _options;

    /// <summary>
    /// HL7 v3 PurposeOfUse value set (OID: 2.16.840.1.113883.5.8).
    /// <a href="https://terminology.hl7.org/ValueSet-v3-PurposeOfUse.html">
    /// HL7 v3 PurposeOfUse Value Set</a>
    /// </summary>
    internal static readonly HashSet<string> AllHl7V3PurposeOfUseCodes = new(StringComparer.Ordinal)
    {
        "urn:oid:2.16.840.1.113883.5.8#TREAT",
        "urn:oid:2.16.840.1.113883.5.8#ETREAT",
        "urn:oid:2.16.840.1.113883.5.8#BTG",
        "urn:oid:2.16.840.1.113883.5.8#ERTREAT",
        "urn:oid:2.16.840.1.113883.5.8#COC",
        "urn:oid:2.16.840.1.113883.5.8#CLINTRL",
        "urn:oid:2.16.840.1.113883.5.8#POPHLTH",
        "urn:oid:2.16.840.1.113883.5.8#TREATDS",
        "urn:oid:2.16.840.1.113883.5.8#HPAYMT",
        "urn:oid:2.16.840.1.113883.5.8#CLMATTCH",
        "urn:oid:2.16.840.1.113883.5.8#COVAUTH",
        "urn:oid:2.16.840.1.113883.5.8#COVERAGE",
        "urn:oid:2.16.840.1.113883.5.8#ELIGDTRM",
        "urn:oid:2.16.840.1.113883.5.8#ELIGVER",
        "urn:oid:2.16.840.1.113883.5.8#ENROLLM",
        "urn:oid:2.16.840.1.113883.5.8#MILDCRG",
        "urn:oid:2.16.840.1.113883.5.8#REMITADV",
        "urn:oid:2.16.840.1.113883.5.8#PMTDS",
        "urn:oid:2.16.840.1.113883.5.8#HOPERAT",
        "urn:oid:2.16.840.1.113883.5.8#CAREMGT",
        "urn:oid:2.16.840.1.113883.5.8#DONAT",
        "urn:oid:2.16.840.1.113883.5.8#FRAUD",
        "urn:oid:2.16.840.1.113883.5.8#GOV",
        "urn:oid:2.16.840.1.113883.5.8#HACCRED",
        "urn:oid:2.16.840.1.113883.5.8#HCOMPL",
        "urn:oid:2.16.840.1.113883.5.8#HDECD",
        "urn:oid:2.16.840.1.113883.5.8#HDIRECT",
        "urn:oid:2.16.840.1.113883.5.8#HDM",
        "urn:oid:2.16.840.1.113883.5.8#HLEGAL",
        "urn:oid:2.16.840.1.113883.5.8#HOUTCOMS",
        "urn:oid:2.16.840.1.113883.5.8#HPRGRP",
        "urn:oid:2.16.840.1.113883.5.8#HQUALIMP",
        "urn:oid:2.16.840.1.113883.5.8#HSYSADMIN",
        "urn:oid:2.16.840.1.113883.5.8#LABELING",
        "urn:oid:2.16.840.1.113883.5.8#METAMGT",
        "urn:oid:2.16.840.1.113883.5.8#MEMADMIN",
        "urn:oid:2.16.840.1.113883.5.8#MILCDM",
        "urn:oid:2.16.840.1.113883.5.8#PATADMIN",
        "urn:oid:2.16.840.1.113883.5.8#PATSFTY",
        "urn:oid:2.16.840.1.113883.5.8#PERFMSR",
        "urn:oid:2.16.840.1.113883.5.8#RECORDMGT",
        "urn:oid:2.16.840.1.113883.5.8#SYSDEV",
        "urn:oid:2.16.840.1.113883.5.8#HTEST",
        "urn:oid:2.16.840.1.113883.5.8#TRAIN",
        "urn:oid:2.16.840.1.113883.5.8#MLTRAINING",
        "urn:oid:2.16.840.1.113883.5.8#HRESCH",
        "urn:oid:2.16.840.1.113883.5.8#BIORCH",
        "urn:oid:2.16.840.1.113883.5.8#CLINTRCH",
        "urn:oid:2.16.840.1.113883.5.8#CLINTRCHNPC",
        "urn:oid:2.16.840.1.113883.5.8#CLINTRCHPC",
        "urn:oid:2.16.840.1.113883.5.8#PRECLINTRCH",
        "urn:oid:2.16.840.1.113883.5.8#DSRCH",
        "urn:oid:2.16.840.1.113883.5.8#POARCH",
        "urn:oid:2.16.840.1.113883.5.8#TRANSRCH",
        "urn:oid:2.16.840.1.113883.5.8#PATRQT",
        "urn:oid:2.16.840.1.113883.5.8#FAMRQT",
        "urn:oid:2.16.840.1.113883.5.8#PWATRNY",
        "urn:oid:2.16.840.1.113883.5.8#SUPNWK",
        "urn:oid:2.16.840.1.113883.5.8#PUBHLTH",
        "urn:oid:2.16.840.1.113883.5.8#DISASTER",
        "urn:oid:2.16.840.1.113883.5.8#THREAT",
        "urn:oid:2.16.840.1.113883.5.8#HMARKT",
    };

    public SsraaTokenValidator(IOptions<SsraaValidationOptions> options)
    {
        _options = options.Value;
    }

    /// <inheritdoc />
    public bool AppliesToCommunity(string communityName)
        => _options.Communities.Contains(communityName);

    /// <summary>
    /// Returns SSRAA validation rules for the given grant type.
    /// Required extensions are configurable via <see cref="SsraaValidationOptions"/>.
    /// AllowedPurposeOfUse is the full HL7 v3 PurposeOfUse value set.
    /// </summary>
    public CommunityValidationRules? GetValidationRules(string? grantType)
    {
        var requiredExtensions = grantType switch
        {
            "client_credentials" => _options.ClientCredentialsExtensionsRequired,
            "authorization_code" => _options.AuthorizationCodeExtensionsRequired,
            _ => null
        };

        return new CommunityValidationRules
        {
            RequiredExtensions = requiredExtensions,
            AllowedPurposeOfUse = AllHl7V3PurposeOfUseCodes,
            MaxPurposeOfUseCount = null // SSRAA does not limit purpose_of_use count
        };
    }

    /// <inheritdoc />
    public Task<AuthorizationExtensionValidationResult> ValidateAsync(
        UdapAuthorizationExtensionValidationContext context)
    {
        return Task.FromResult(AuthorizationExtensionValidationResult.Success());
    }
}
