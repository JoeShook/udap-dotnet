// UdapModel is modeled after IdentityModel. See https://github.com/IdentityModel/IdentityModel
// 
// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Duende.IdentityModel.Client;
using Udap.Model;

namespace Udap.Client;

/// <summary>
/// Security policy for retrieving a discovery document
/// </summary>
public class DiscoveryPolicy
{
    public static DiscoveryPolicy DefaultMetadataServerPolicy()
    {
        return new DiscoveryPolicy
        {
            ValidateEndpoints = false // Authority endpoints are not hosted on same domain as resource server.
        };
    }

    internal static readonly IAuthorityValidationStrategy DefaultAuthorityValidationStrategy = new StringComparisonAuthorityValidationStrategy();

    /// <summary>
    /// Gets or sets the Authority on which the policy checks will be based on
    /// </summary>
    public string Authority { get; set; } = string.Empty;

    /// <summary>
    /// The path of the discovery document. Defaults to /.well-known/openid-configuration.
    /// </summary>
    public string DiscoveryDocumentPath { get; set; } = UdapConstants.Discovery.DiscoveryEndpoint;

    /// <summary>
    /// Strategy used to validate issuer name and endpoints based on expected authority.
    /// Defaults to <see cref="AuthorityUrlValidationStrategy"/>.
    /// </summary>
    public IAuthorityValidationStrategy AuthorityValidationStrategy { get; set; } = DefaultAuthorityValidationStrategy;

    /// <summary>
    /// Specifies if HTTPS is enforced on all endpoints. Defaults to true.
    /// </summary>
    public bool RequireHttps { get; set; } = true;

    /// <summary>
    /// Specifies if HTTP is allowed on loopback addresses. Defaults to true.
    /// </summary>
    public bool AllowHttpOnLoopback { get; set; } = true;

    /// <summary>
    /// Specifies valid loopback addresses, defaults to localhost and 127.0.0.1
    /// </summary>
    public ICollection<string> LoopbackAddresses = new HashSet<string> { "localhost", "127.0.0.1" };

    /// <summary>
    /// Specifies if all endpoints are checked to belong to the authority. Defaults to true.
    /// </summary>
    public bool ValidateEndpoints { get; set; } = true;

    /// <summary>
    /// Specifies a list of endpoints that should be excluded from validation
    /// </summary>
    public ICollection<string> EndpointValidationExcludeList { get; set; } = new HashSet<string>();

    /// <summary>
    /// Specifies a list of additional base addresses that should be allowed for endpoints
    /// </summary>
    public ICollection<string> AdditionalEndpointBaseAddresses { get; set; } = new HashSet<string>();

    /// <summary>
    /// Specifies if a key set is required. Defaults to true.
    /// </summary>
    public bool RequireKeySet { get; set; } = true;

    /// <summary>
    /// Optional certificate policy binding for the server's metadata signing certificate, keyed by community.
    /// When the <c>community</c> passed to discovery has a non-empty entry, <c>x5c[0]</c> of the signed metadata
    /// must carry at least one subject <c>organizationalUnitName</c> equal to one of that entry's values
    /// (compared case-insensitively), or discovery fails. Discoveries for other communities, or without a
    /// community, are not checked. Empty by default (no check). For example, a TEFCA client maps the TEFCA
    /// community to <c>RCE-FHIR</c> in production and <c>RCE-FHIR-TEST</c> in validation environments.
    /// </summary>
    public IDictionary<string, ICollection<string>> RequiredSigningCertificateOrganizationalUnits { get; set; } =
        new Dictionary<string, ICollection<string>>(StringComparer.Ordinal);

    /// <summary>
    /// The organizational units the metadata signing certificate must carry (one is enough) for
    /// <paramref name="community"/>, or <c>null</c> when that community has no OU policy.
    /// </summary>
    public ICollection<string>? GetRequiredSigningCertificateOrganizationalUnits(string? community)
    {
        if (community == null
            || RequiredSigningCertificateOrganizationalUnits == null
            || !RequiredSigningCertificateOrganizationalUnits.TryGetValue(community, out var units)
            || units == null
            || units.Count == 0)
        {
            return null;
        }

        return units;
    }
}