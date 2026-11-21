#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Udap.Common.Certificates;
using Udap.Common.Extensions;
using Udap.Common.Models;
using Udap.Model;
using Udap.Model.Registration;
using Udap.Server.Configuration;
using Udap.Server.Storage.Stores;
using Udap.Util.Extensions;

namespace Udap.Server.Registration;

/// <summary>
/// Enforces the certifications a community requires at registration.
///
/// The required certification URIs for a community come from
/// <see cref="ServerSettings.CommunityCertificationsRequired"/> and from every registered
/// <see cref="IUdapCertificationProfileValidator"/> whose <see cref="IUdapCertificationProfileValidator.IsRequiredForCommunity"/>
/// returns true. When neither names a URI for the client's community this validator does not apply,
/// so registrations are unaffected unless a deployment opts in.
///
/// For each required URI the request's <c>certifications</c> array must hold a certification that
/// <list type="bullet">
/// <item>verifies with the key of <c>cert1</c> in its <c>x5c</c> header,</item>
/// <item>has an <c>iss</c> matching a uniformResourceIdentifier SAN of that certificate,</item>
/// <item>has a <c>sub</c> equal to the client's identifying URI (the software statement <c>iss</c>),</item>
/// <item>has an <c>aud</c>, when present, that names this registration endpoint,</item>
/// <item>carries an unexpired <c>exp</c>,</item>
/// <item>lists the URI in <c>certification_uris</c>, and</item>
/// <item>chains to a trust anchor of the client's community.</item>
/// </list>
/// The certification is then handed to each <see cref="IUdapCertificationProfileValidator"/> for that URI whose
/// <see cref="IUdapCertificationProfileValidator.AppliesToCommunity"/> returns true for the client's community.
///
/// <a href="https://www.udap.org/udap-certifications-and-endorsements-stu1.html#section-6">UDAP Certifications and Endorsements section 6</a>
/// </summary>
public class UdapCertificationsRequiredValidator : ICommunityRegistrationValidator
{
    /// <summary>
    /// Key in <see cref="UdapDynamicClientRegistrationContext.Items"/> under which the accepted certifications
    /// are stored, as an <c>IReadOnlyList&lt;UdapValidatedCertification&gt;</c>.
    /// </summary>
    public const string ValidatedCertificationsItemKey = "UdapValidatedCertifications";

    private readonly ServerSettings _serverSettings;
    private readonly IEnumerable<IUdapCertificationProfileValidator> _profileValidators;
    private readonly IUdapClientRegistrationStore _store;
    private readonly TrustChainValidator _trustChainValidator;
    private readonly ILogger<UdapCertificationsRequiredValidator> _logger;

    public UdapCertificationsRequiredValidator(
        ServerSettings serverSettings,
        IEnumerable<IUdapCertificationProfileValidator> profileValidators,
        IUdapClientRegistrationStore store,
        TrustChainValidator trustChainValidator,
        ILogger<UdapCertificationsRequiredValidator> logger)
    {
        _serverSettings = serverSettings;
        _profileValidators = profileValidators;
        _store = store;
        _trustChainValidator = trustChainValidator;
        _logger = logger;
    }

    /// <summary>
    /// The certification URIs required for <paramref name="communityName"/>.
    /// </summary>
    public IReadOnlyCollection<string> GetRequiredCertificationUris(string communityName)
    {
        var required = new List<string>();

        foreach (var requirement in _serverSettings.CommunityCertificationsRequired)
        {
            if (string.Equals(requirement.Community, communityName, StringComparison.Ordinal))
            {
                required.AddRange(requirement.CertificationUris.Where(u => !string.IsNullOrWhiteSpace(u)));
            }
        }

        foreach (var profileValidator in _profileValidators)
        {
            if (profileValidator.IsRequiredForCommunity(communityName))
            {
                required.Add(profileValidator.CertificationUri);
            }
        }

        return required.Distinct(StringComparer.Ordinal).ToList();
    }

    /// <inheritdoc />
    public bool AppliesToCommunity(string communityName)
        => GetRequiredCertificationUris(communityName).Count > 0;

    /// <inheritdoc />
    public async Task<UdapDynamicClientRegistrationValidationResult?> ValidateAsync(
        UdapDynamicClientRegistrationContext context)
    {
        if (string.IsNullOrEmpty(context.CommunityName))
        {
            return null;
        }

        var requiredUris = GetRequiredCertificationUris(context.CommunityName);

        if (requiredUris.Count == 0)
        {
            return null;
        }

        var certifications = context.Request.Certifications?
            .Where(c => !string.IsNullOrWhiteSpace(c))
            .ToArray() ?? [];

        // The community's anchors; a certifier must chain to one of them.
        var anchorCertificates = await _store.GetAnchorsCertificates(context.CommunityName) ?? new X509Certificate2Collection();
        var anchors = (await _store.GetAnchors(context.CommunityName)).ToList();
        var intermediateCertificates = await _store.GetIntermediateCertificates();

        var results = new Dictionary<string, CertificationValidation>(StringComparer.Ordinal);
        var accepted = new List<UdapValidatedCertification>();

        foreach (var requiredUri in requiredUris)
        {
            UdapValidatedCertification? match = null;
            UdapDynamicClientRegistrationValidationResult? firstFailure = null;

            foreach (var certification in certifications)
            {
                if (!results.TryGetValue(certification, out var validation))
                {
                    validation = await ValidateCertificationAsync(
                        context, certification, intermediateCertificates, anchorCertificates, anchors);
                    results[certification] = validation;
                }

                if (!validation.DeclaredUris.Contains(requiredUri, StringComparer.Ordinal))
                {
                    continue;
                }

                if (validation.Certification != null)
                {
                    match = validation.Certification;
                    break;
                }

                firstFailure ??= validation.Error;
            }

            if (match == null)
            {
                if (firstFailure != null)
                {
                    return firstFailure;
                }

                _logger.LogWarning("{Error}::Registration in community {Community} requires a certification for {CertificationUri}",
                    UdapDynamicClientRegistrationErrors.UnapprovedSoftwareStatement,
                    context.CommunityName,
                    requiredUri);

                return new UdapDynamicClientRegistrationValidationResult(
                    UdapDynamicClientRegistrationErrors.UnapprovedSoftwareStatement,
                    $"Registration requires a valid certification for {requiredUri}");
            }

            foreach (var profileValidator in _profileValidators.Where(p =>
                         string.Equals(p.CertificationUri, requiredUri, StringComparison.Ordinal) &&
                         p.AppliesToCommunity(context.CommunityName)))
            {
                var profileResult = await profileValidator.ValidateAsync(context, match);

                if (profileResult is { IsError: true })
                {
                    _logger.LogWarning("{Error}::{Description}", profileResult.Error, profileResult.ErrorDescription);
                    return profileResult;
                }
            }

            if (!accepted.Contains(match))
            {
                accepted.Add(match);
            }
        }

        context.Items[ValidatedCertificationsItemKey] = (IReadOnlyList<UdapValidatedCertification>)accepted;

        return null;
    }

    /// <summary>
    /// Applies the generic UDAP Certifications and Endorsements checks to one certification.
    /// </summary>
    protected virtual async Task<CertificationValidation> ValidateCertificationAsync(
        UdapDynamicClientRegistrationContext context,
        string certification,
        X509Certificate2Collection? intermediateCertificates,
        X509Certificate2Collection anchorCertificates,
        IEnumerable<Anchor> anchors)
    {
        var tokenHandler = new JsonWebTokenHandler();
        JsonWebToken jsonWebToken;

        try
        {
            jsonWebToken = tokenHandler.ReadJsonWebToken(certification);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Certification is not a JWT");
            return CertificationValidation.Failed([], Invalid("Certification is not a valid JWT"));
        }

        var declaredUris = jsonWebToken.Claims
            .Where(c => c.Type == UdapConstants.CertificationAndEndorsementDocumentValues.CertificationUris)
            .Select(c => c.Value)
            .ToList();

        var x5c = GetX5c(jsonWebToken);

        if (x5c == null || x5c.Length == 0)
        {
            return CertificationValidation.Failed(declaredUris,
                Invalid("Certification is missing the x5c header"));
        }

        X509Certificate2 certifierCertificate;
        var chainCertificates = new X509Certificate2Collection();

        try
        {
            certifierCertificate = LoadCertificate(x5c[0]);

            foreach (var additional in x5c.Skip(1))
            {
                chainCertificates.Add(LoadCertificate(additional));
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Certification x5c header cannot be parsed");
            return CertificationValidation.Failed(declaredUris,
                Invalid("Certification x5c header cannot be parsed"));
        }

        var subAltNames = certifierCertificate
            .GetSubjectAltNames(n => n.TagNo == (int)X509Extensions.GeneralNameType.URI)
            .Select(san => san.Item2)
            .ToArray();

        SecurityKey signingKey;
        var rsaPublicKey = certifierCertificate.PublicKey.GetRSAPublicKey();

        if (rsaPublicKey != null)
        {
            signingKey = new X509SecurityKey(certifierCertificate);
        }
        else
        {
            var ecdsaPublicKey = certifierCertificate.PublicKey.GetECDsaPublicKey();

            if (ecdsaPublicKey == null)
            {
                return CertificationValidation.Failed(declaredUris,
                    Invalid("Certification signing certificate key type is not supported"));
            }

            signingKey = new ECDsaSecurityKey(ecdsaPublicKey);
        }

        var validatedToken = await tokenHandler.ValidateTokenAsync(certification,
            new TokenValidationParameters
            {
                RequireSignedTokens = true,
                ValidateIssuer = true,
                ValidIssuers = subAltNames,
                ValidateAudience = false, // checked below; aud is optional for a certification
                ValidateLifetime = true,
                RequireExpirationTime = true,
                IssuerSigningKey = signingKey,
                ValidateIssuerSigningKey = true,
                ValidAlgorithms = [jsonWebToken.Alg],
            });

        if (!validatedToken.IsValid)
        {
            var description = validatedToken.Exception switch
            {
                SecurityTokenNoExpirationException => "Certification exp is missing",
                SecurityTokenExpiredException => "Certification is expired",
                SecurityTokenInvalidIssuerException => "Certification iss does not match a uriName SAN of the certifier's certificate",
                _ => "Certification signature cannot be validated"
            };

            _logger.LogWarning(validatedToken.Exception, "Certification rejected: {Description}", description);

            return CertificationValidation.Failed(declaredUris, Invalid(description));
        }

        if (!string.Equals(jsonWebToken.Subject, context.Issuer, StringComparison.Ordinal))
        {
            return CertificationValidation.Failed(declaredUris,
                Invalid("Certification sub does not match the client's identifying URI"));
        }

        var audiences = jsonWebToken.Audiences.ToList();
        var registrationEndpoint = context.Document?.Audience;

        if (audiences.Count > 0 &&
            Uri.TryCreate(registrationEndpoint, UriKind.Absolute, out var endpoint) &&
            !audiences.Any(a => Uri.TryCreate(a, UriKind.Absolute, out var aud) &&
                                Uri.Compare(endpoint, aud,
                                    UriComponents.Host | UriComponents.PathAndQuery | UriComponents.Port,
                                    UriFormat.SafeUnescaped, StringComparison.OrdinalIgnoreCase) == 0))
        {
            return CertificationValidation.Failed(declaredUris,
                Invalid("Certification aud does not contain this registration endpoint"));
        }

        if (declaredUris.Count == 0)
        {
            return CertificationValidation.Failed(declaredUris,
                Invalid("Certification certification_uris is missing"));
        }

        var intermediates = new X509Certificate2Collection(chainCertificates);

        if (intermediateCertificates != null)
        {
            intermediates.AddRange(intermediateCertificates);
        }

        var chainResult = await _trustChainValidator.IsTrustedCertificateAsync(
            jsonWebToken.Issuer,
            certifierCertificate,
            intermediates,
            anchorCertificates,
            anchors);

        if (!chainResult.IsValid ||
            (chainResult.CommunityName != null &&
             !string.Equals(chainResult.CommunityName, context.CommunityName, StringComparison.Ordinal)))
        {
            _logger.LogWarning("Certification signing certificate {Thumbprint} does not chain to an anchor of community {Community}",
                certifierCertificate.Thumbprint,
                context.CommunityName);

            return CertificationValidation.Failed(declaredUris,
                new UdapDynamicClientRegistrationValidationResult(
                    UdapDynamicClientRegistrationErrors.UnapprovedSoftwareStatement,
                    "Certification signing certificate is not trusted"));
        }

        return CertificationValidation.Succeeded(new UdapValidatedCertification(
            certification, jsonWebToken, certifierCertificate, declaredUris));
    }

    private static UdapDynamicClientRegistrationValidationResult Invalid(string description)
        => new(UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement, description);

    private static X509Certificate2 LoadCertificate(string base64)
    {
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadCertificate(Convert.FromBase64String(base64));
#else
        return new X509Certificate2(Convert.FromBase64String(base64));
#endif
    }

    private static string[]? GetX5c(JsonWebToken jsonWebToken)
    {
        var jwtHeader = JwtHeader.Base64UrlDeserialize(jsonWebToken.EncodedHeader);

        if (jwtHeader["x5c"] is not List<object> certificates)
        {
            return null;
        }

        return certificates.Select(c => c.ToString()!).ToArray();
    }

    /// <summary>
    /// The outcome of the generic checks on one certification.
    /// </summary>
    protected sealed class CertificationValidation
    {
        private CertificationValidation(
            IReadOnlyCollection<string> declaredUris,
            UdapValidatedCertification? certification,
            UdapDynamicClientRegistrationValidationResult? error)
        {
            DeclaredUris = declaredUris;
            Certification = certification;
            Error = error;
        }

        /// <summary>The <c>certification_uris</c> the certification declares, whether or not it is valid.</summary>
        public IReadOnlyCollection<string> DeclaredUris { get; }

        /// <summary>The accepted certification, or null when rejected.</summary>
        public UdapValidatedCertification? Certification { get; }

        /// <summary>The rejection, or null when accepted.</summary>
        public UdapDynamicClientRegistrationValidationResult? Error { get; }

        /// <summary>An accepted certification.</summary>
        public static CertificationValidation Succeeded(UdapValidatedCertification certification)
            => new(certification.CertificationUris, certification, null);

        /// <summary>A rejected certification.</summary>
        public static CertificationValidation Failed(
            IReadOnlyCollection<string> declaredUris,
            UdapDynamicClientRegistrationValidationResult error)
            => new(declaredUris, null, error);
    }
}
