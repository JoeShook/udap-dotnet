#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.Extensions.Logging;
using Udap.Model.UdapAuthenticationExtensions;
using Udap.Server.Storage.Stores;

namespace Udap.Server.Validation.Default;

/// <summary>
/// Default implementation of <see cref="IUdapAuthorizationExtensionValidator"/> that
/// enforces required authorization extensions via <see cref="ICommunityTokenValidator"/>
/// implementations.
///
/// Community validators provide rules via <see cref="ICommunityTokenValidator.GetValidationRules"/>
/// (required extensions, allowed POU codes, max count) and domain-specific validation
/// via <see cref="ICommunityTokenValidator.ValidateAsync"/>.
///
/// When no community validator applies, no extension or POU enforcement occurs.
/// </summary>
public class DefaultUdapAuthorizationExtensionValidator : IUdapAuthorizationExtensionValidator
{
    private readonly IUdapClientRegistrationStore _clientStore;
    private readonly IEnumerable<ICommunityTokenValidator> _communityTokenValidators;
    private readonly ILogger<DefaultUdapAuthorizationExtensionValidator> _logger;

    public DefaultUdapAuthorizationExtensionValidator(
        IUdapClientRegistrationStore clientStore,
        IEnumerable<ICommunityTokenValidator> communityTokenValidators,
        ILogger<DefaultUdapAuthorizationExtensionValidator> logger)
    {
        _clientStore = clientStore;
        _communityTokenValidators = communityTokenValidators;
        _logger = logger;
    }

    public async Task<AuthorizationExtensionValidationResult> ValidateAsync(
        UdapAuthorizationExtensionValidationContext context)
    {
        var resolved = await ResolveSettingsAsync(context.CommunityId, context.GrantType);

        var requiredExtensions = resolved.RequiredExtensions;

        if (requiredExtensions != null && requiredExtensions.Count > 0)
        {
            if (context.Extensions == null || context.Extensions.Count == 0)
            {
                _logger.LogError(
                    "Client {ClientId} did not include required authorization extensions: {Required}",
                    context.ClientId, string.Join(", ", requiredExtensions));

                return AuthorizationExtensionValidationResult.Failure(
                    "invalid_grant",
                    $"Required authorization extension(s) missing: {string.Join(", ", requiredExtensions)}");
            }

            foreach (var required in requiredExtensions)
            {
                if (!context.Extensions.ContainsKey(required))
                {
                    _logger.LogError(
                        "Client {ClientId} missing required authorization extension '{Extension}'",
                        context.ClientId, required);

                    return AuthorizationExtensionValidationResult.Failure(
                        "invalid_grant",
                        $"Required authorization extension '{required}' not found");
                }
            }
        }

        // Structural validation of extension objects
        if (context.Extensions != null)
        {
            foreach (var (key, value) in context.Extensions)
            {
                var errors = ValidateExtensionObject(key, value);

                if (errors.Count > 0)
                {
                    _logger.LogError(
                        "Client {ClientId} authorization extension '{Extension}' validation failed: {Errors}",
                        context.ClientId, key, string.Join("; ", errors));

                    return AuthorizationExtensionValidationResult.Failure(
                        "invalid_grant",
                        $"Authorization extension '{key}' validation failed: {string.Join("; ", errors)}");
                }

                var pouResult = ValidatePurposeOfUse(
                    key, value, resolved.AllowedPurposeOfUse, resolved.MaxPurposeOfUseCount,
                    context.ClientId);

                if (!pouResult.IsValid)
                {
                    return pouResult;
                }
            }
        }

        // Community-specific token validation — always runs regardless of whether
        // extensions are required, so community validators can enforce additional
        // rules (e.g., TEFCA purpose_of_use matching against registered SAN URI).
        if (!string.IsNullOrEmpty(resolved.CommunityName))
        {
            context.CommunityName = resolved.CommunityName;

            foreach (var communityValidator in _communityTokenValidators)
            {
                if (communityValidator.AppliesToCommunity(resolved.CommunityName))
                {
                    var communityResult = await communityValidator.ValidateAsync(context);
                    if (!communityResult.IsValid)
                    {
                        return communityResult;
                    }
                }
            }
        }

        return AuthorizationExtensionValidationResult.Success();
    }

    private async Task<ResolvedSettings> ResolveSettingsAsync(string? communityId, string? grantType)
    {
        string? communityName = null;

        // Resolve community name from store
        if (communityId != null)
        {
            communityName = await _clientStore.GetCommunityName(communityId);
        }

        // Check if a community validator provides rules for this community
        if (communityName != null)
        {
            foreach (var validator in _communityTokenValidators)
            {
                if (validator.AppliesToCommunity(communityName))
                {
                    var rules = validator.GetValidationRules(grantType);
                    if (rules != null)
                    {
                        return new ResolvedSettings
                        {
                            CommunityName = communityName,
                            RequiredExtensions = rules.RequiredExtensions,
                            AllowedPurposeOfUse = rules.AllowedPurposeOfUse,
                            MaxPurposeOfUseCount = rules.MaxPurposeOfUseCount
                        };
                    }
                }
            }
        }

        // No community validator matched — no extension or POU enforcement
        return new ResolvedSettings
        {
            CommunityName = communityName
        };
    }

    private AuthorizationExtensionValidationResult ValidatePurposeOfUse(
        string extensionKey,
        object extensionValue,
        HashSet<string>? allowedCodes,
        int? maxCount,
        string clientId)
    {
        var purposeOfUse = GetPurposeOfUse(extensionKey, extensionValue);

        if (purposeOfUse == null)
        {
            return AuthorizationExtensionValidationResult.Success();
        }

        if (maxCount.HasValue && purposeOfUse.Count > maxCount.Value)
        {
            _logger.LogError(
                "Client {ClientId} extension '{Extension}' purpose_of_use has {Count} entries, maximum allowed is {Max}",
                clientId, extensionKey, purposeOfUse.Count, maxCount.Value);

            return AuthorizationExtensionValidationResult.Failure(
                "invalid_grant",
                $"Extension '{extensionKey}' purpose_of_use has {purposeOfUse.Count} entries; maximum allowed is {maxCount.Value}");
        }

        if (allowedCodes == null)
        {
            return AuthorizationExtensionValidationResult.Success();
        }

        foreach (var code in purposeOfUse)
        {
            if (!allowedCodes.Contains(code))
            {
                _logger.LogError(
                    "Client {ClientId} extension '{Extension}' contains disallowed purpose_of_use code '{Code}'",
                    clientId, extensionKey, code);

                return AuthorizationExtensionValidationResult.Failure(
                    "invalid_grant",
                    $"Extension '{extensionKey}' contains disallowed purpose_of_use code '{code}'");
            }
        }

        return AuthorizationExtensionValidationResult.Success();
    }

    private static ICollection<string>? GetPurposeOfUse(string key, object value)
    {
        if (value is IAuthorizationExtensionObject extensionObject)
        {
            return extensionObject.GetPurposeOfUse();
        }

        return null;
    }

    private static List<string> ValidateExtensionObject(string key, object value)
    {
        if (value is IAuthorizationExtensionObject extensionObject)
        {
            return extensionObject.Validate();
        }

        return [];
    }

    private class ResolvedSettings
    {
        public string? CommunityName { get; init; }
        public HashSet<string>? RequiredExtensions { get; init; }
        public HashSet<string>? AllowedPurposeOfUse { get; init; }
        public int? MaxPurposeOfUseCount { get; init; }
    }
}
