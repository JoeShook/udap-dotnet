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

namespace Udap.Tefca.Server;

/// <summary>
/// Validates that a TEFCA community registration uses a SAN URI containing
/// a valid Exchange Purpose (XP) code from the TEFCA Exchange Purposes SOP.
/// The code is read by <see cref="ExchangePurposeSanReader"/> from the location selected by
/// <see cref="TefcaValidationOptions.ExchangePurposeLocation"/> (URI fragment by default).
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

        var exchangePurpose = ExchangePurposeSanReader.Read(issuer, _options);

        if (!exchangePurpose.IsValid)
        {
            return Task.FromResult<UdapDynamicClientRegistrationValidationResult?>(
                new UdapDynamicClientRegistrationValidationResult(
                    UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement,
                    $"TEFCA {exchangePurpose.ErrorDescription}"));
        }

        return Task.FromResult<UdapDynamicClientRegistrationValidationResult?>(null);
    }
}
