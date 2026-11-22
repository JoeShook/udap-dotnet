#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Udap.Server.Registration;

/// <summary>
/// A certification from a registration request's <c>certifications</c> array that passed the generic
/// UDAP Certifications and Endorsements checks.
/// </summary>
public class UdapValidatedCertification
{
    /// <summary>
    /// Creates a validated certification.
    /// </summary>
    public UdapValidatedCertification(
        string certification,
        JsonWebToken jsonWebToken,
        X509Certificate2 certifierCertificate,
        IReadOnlyCollection<string> certificationUris)
    {
        Certification = certification;
        JsonWebToken = jsonWebToken;
        CertifierCertificate = certifierCertificate;
        CertificationUris = certificationUris;
    }

    /// <summary>
    /// The certification as submitted (JWS compact serialization).
    /// </summary>
    public string Certification { get; }

    /// <summary>
    /// The parsed certification JWT.
    /// </summary>
    public JsonWebToken JsonWebToken { get; }

    /// <summary>
    /// The Certifier's certificate (<c>cert1</c> of the <c>x5c</c> header).
    /// </summary>
    public X509Certificate2 CertifierCertificate { get; }

    /// <summary>
    /// The <c>certification_uris</c> claim values.
    /// </summary>
    public IReadOnlyCollection<string> CertificationUris { get; }

    /// <summary>
    /// The JWT payload as a JSON document, for claims whose JSON shape matters (for example a claim
    /// that must be an array). The caller owns the returned document.
    /// </summary>
    public JsonDocument GetPayload()
    {
        return JsonDocument.Parse(Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(JsonWebToken.EncodedPayload)));
    }
}
