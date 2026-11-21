#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.Extensions.Options;
using Udap.Model;
using Udap.Model.Registration;
using Udap.Server.Registration;
using Udap.Tefca.Model;

namespace Udap.Tefca.Server;

/// <summary>
/// Validates that a TEFCA community registration uses a SAN URI containing
/// a valid Exchange Purpose (XP) code from the TEFCA Exchange Purposes SOP, and
/// (see <see cref="TefcaValidationOptions.RejectUserScopes"/>) that it does not
/// request <c>user/</c> scopes (Section 6.11 Registration #10).
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

        // SOP v2.0 Section 6.11 Registration #10: user scopes without a user are rejected
        // with invalid_scope rather than silently corrected.
        if (_options.RejectUserScopes)
        {
            var userScopes = TefcaScopeRules.FindUserScopes(TefcaScopeRules.Split(GetRequestedScope(context)));

            if (userScopes.Count > 0)
            {
                return Task.FromResult<UdapDynamicClientRegistrationValidationResult?>(
                    new UdapDynamicClientRegistrationValidationResult(
                        UdapDynamicClientRegistrationErrors.InvalidScope,
                        TefcaScopeRules.Describe(userScopes)));
            }
        }

        return Task.FromResult<UdapDynamicClientRegistrationValidationResult?>(null);
    }

    /// <summary>
    /// The scope as the client sent it in the software statement. The registration validator
    /// replaces <see cref="UdapDynamicClientRegistrationDocument.Scope"/> with the scopes the
    /// server resolved, dropping unknown ones, so the original JWT claim is read first.
    /// </summary>
    private static string? GetRequestedScope(UdapDynamicClientRegistrationContext context)
    {
        if (context.JsonWebToken != null
            && context.JsonWebToken.TryGetPayloadValue<string>(UdapConstants.RegistrationDocumentValues.Scope, out var scope))
        {
            return scope;
        }

        return context.Document?.Scope;
    }
}
