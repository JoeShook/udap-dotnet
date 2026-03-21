#region (c) 2025 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.JsonWebTokens;
using Udap.Model.Registration;

namespace Udap.Server.Registration;

/// <summary>
/// Carries state through the UDAP Dynamic Client Registration pipeline.
/// Populated by the validator, consumed by the processor.
/// Inspired by Duende's DynamicClientRegistrationContext pattern.
/// </summary>
public class UdapDynamicClientRegistrationContext
{
    // -- Input --

    /// <summary>
    /// The original registration request.
    /// </summary>
    public required UdapRegisterRequest Request { get; init; }

    // -- Populated by validator --

    /// <summary>
    /// The parsed and validated software statement document.
    /// </summary>
    public UdapDynamicClientRegistrationDocument? Document { get; set; }

    /// <summary>
    /// The validated JWT from the software statement.
    /// </summary>
    public JsonWebToken? JsonWebToken { get; set; }

    /// <summary>
    /// The parsed JWT header (needed for x5c extraction).
    /// </summary>
    public JwtHeader? JwtHeader { get; set; }

    /// <summary>
    /// The end-entity certificate from the x5c chain.
    /// </summary>
    public X509Certificate2? ClientCertificate { get; set; }

    /// <summary>
    /// The issuer URI from the certificate SAN.
    /// </summary>
    public string? Issuer { get; set; }

    /// <summary>
    /// The community ID resolved during chain validation.
    /// </summary>
    public long? CommunityId { get; set; }

    /// <summary>
    /// Certificate expiration from the validated chain.
    /// </summary>
    public DateTime? CertificateExpiration { get; set; }

    /// <summary>
    /// Organization identifier from the registration endpoint query parameters.
    /// </summary>
    public string? Organization { get; set; }

    /// <summary>
    /// Data holder identifier from the registration endpoint query parameters.
    /// </summary>
    public string? DataHolder { get; set; }

    // -- Populated by processor --

    /// <summary>
    /// The Duende IdentityServer Client model, created by the processor.
    /// </summary>
    public Duende.IdentityServer.Models.Client? Client { get; set; }

    // -- Extensibility --

    /// <summary>
    /// Arbitrary state for cross-step communication. Mirrors Duende's Items pattern.
    /// </summary>
    public Dictionary<string, object> Items { get; set; } = new();
}
