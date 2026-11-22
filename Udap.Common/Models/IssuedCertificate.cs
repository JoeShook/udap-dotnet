#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Udap.Model.Statement;
using Udap.Util.Extensions;

namespace Udap.Common.Models;

/// <summary>
/// Represents an issued end-entity certificate with its community association and
/// Subject Alternative Name metadata. Used for signing UDAP metadata and software statements.
/// </summary>
public class IssuedCertificate : IEquatable<IssuedCertificate>
{
#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider adding the 'required' modifier or declaring as nullable.
    /// <summary>
    /// Initializes a new empty instance. Required for serialization.
    /// </summary>
    public IssuedCertificate(){} // do not remove
#pragma warning restore CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider adding the 'required' modifier or declaring as nullable.

    /// <summary>
    /// Initializes a new instance from an X.509 certificate.
    /// </summary>
    /// <param name="certificate">The issued end-entity certificate.</param>
    /// <param name="community">The UDAP community this certificate belongs to.</param>
    public IssuedCertificate(X509Certificate2 certificate, string community = "")
    {
        Certificate = certificate;
        Community = community;
        Thumbprint = certificate.Thumbprint;
        SubjectAltNames = certificate
            .GetSubjectAltNames(n => n.TagNo == (int)X509Extensions.GeneralNameType.URI)
            .Select(s => s.Item2)
            .ToList();
    }

    /// <summary>Gets the UDAP community name this certificate belongs to.</summary>
    public string Community { get; }

    /// <summary>Gets the X.509 certificate.</summary>
    public X509Certificate2 Certificate { get; }

    /// <summary>Gets the SHA-1 thumbprint of the certificate.</summary>
    public string Thumbprint { get; }

    /// <summary>Gets the URI-type Subject Alternative Names from the certificate.</summary>
    public IReadOnlyList<string> SubjectAltNames { get; } = [];

    /// <summary>
    /// Initializes a new instance from an X.509 certificate and the CA certificates available alongside it.
    /// </summary>
    /// <param name="certificate">The issued end-entity certificate.</param>
    /// <param name="community">The UDAP community this certificate belongs to.</param>
    /// <param name="intermediates">CA certificates loaded with the certificate, for example the other certificates
    /// in its PKCS#12 file. Only those in the certificate's issuing chain are kept; self-signed roots are dropped.</param>
    public IssuedCertificate(X509Certificate2 certificate, string community, IEnumerable<X509Certificate2>? intermediates)
        : this(certificate, community)
    {
        Intermediates = X5cChain.Build(certificate, intermediates).Skip(1).ToList();
    }

    /// <summary>
    /// Gets the intermediate certificates of this certificate's issuing chain, nearest issuer first.
    /// Empty when no issuing intermediate was available from the certificate store.
    /// </summary>
    public IReadOnlyList<X509Certificate2> Intermediates { get; } = [];

    /// <summary>
    /// Gets the certificates to place in a JWT <c>x5c</c> header: <see cref="Certificate"/> followed by
    /// its issuing <see cref="Intermediates"/>. Pass the result to the list overloads of the UDAP builders,
    /// for example <c>UdapDcrBuilderForClientCredentials.Create(List&lt;X509Certificate2&gt;)</c>.
    /// </summary>
    public List<X509Certificate2> GetX5cCertificates()
    {
        return [Certificate, .. Intermediates];
    }

    /// <summary>Serves as the default hash function.</summary>
    /// <returns>A hash code for the current object.</returns>
    public override int GetHashCode()
    {
        return HashCode.Combine(Thumbprint, Community);
    }

    /// <summary>Indicates whether the current object is equal to another object of the same type.</summary>
    /// <param name="other">An object to compare with this object.</param>
    /// <returns>
    /// <see langword="true" /> if the current object is equal to the <paramref name="other" /> parameter; otherwise, <see langword="false" />.</returns>
    public bool Equals(IssuedCertificate? other)
    {
        if (other == null) return false;
        return other.Thumbprint == this.Thumbprint &&
               other.Community == this.Community;
    }

    /// <summary>Determines whether the specified object is equal to the current object.</summary>
    /// <param name="obj">The object to compare with the current object.</param>
    /// <returns>
    /// <see langword="true" /> if the specified object  is equal to the current object; otherwise, <see langword="false" />.</returns>
    public override bool Equals(object? obj)
    {
        if (obj is IssuedCertificate issued) return Equals(issued);
        return false;
    }
}