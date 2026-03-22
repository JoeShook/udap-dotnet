using System.Security.Cryptography.X509Certificates;
using Udap.Util.Extensions;

namespace Udap.Common.Models;

/// <summary>
/// Represents an intermediate CA certificate in the UDAP trust framework.
/// Intermediate certificates bridge between a trust anchor and end-entity certificates.
/// </summary>
public class Intermediate : IEquatable<Intermediate>
{
    /// <summary>
    /// Initializes a new empty instance. Required for serialization and EF Core materialization.
    /// </summary>
    public Intermediate() { }

    /// <summary>
    /// Initializes a new instance from an X.509 certificate.
    /// </summary>
    /// <param name="cert">The intermediate CA certificate.</param>
    /// <param name="name">A display name for the intermediate. Defaults to the certificate subject.</param>
    public Intermediate(X509Certificate2 cert, string? name = null)
    {
        Certificate = cert.ToPemFormat();
        BeginDate = cert.NotBefore;
        EndDate = cert.NotAfter;
        Thumbprint = cert.Thumbprint;
        Name = name ?? cert.Subject;
    }

    /// <summary>Gets or sets the database identifier.</summary>
    public long Id { get; set; }

    /// <summary>Gets or sets the foreign key to the parent <see cref="Models.Anchor"/>.</summary>
    public long AnchorId { get; set; }

    /// <summary>Gets or sets whether this intermediate is enabled for validation.</summary>
    public bool Enabled { get; set; }

    /// <summary>Gets or sets the display name, typically the certificate subject.</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>Gets or sets the PEM-encoded certificate data.</summary>
    public string Certificate { get; set; } = string.Empty;

    /// <summary>Gets or sets the SHA-1 thumbprint of the certificate.</summary>
    public string Thumbprint { get; set; } = string.Empty;

    /// <summary>Gets or sets the certificate's NotBefore date.</summary>
    public DateTime BeginDate { get; set; }

    /// <summary>Gets or sets the certificate's NotAfter date.</summary>
    public DateTime EndDate { get; set; }

    /// <summary>Gets or sets the parent trust anchor this intermediate belongs to.</summary>
    public virtual Anchor Anchor { get; set; } = default!;

    /// <summary>Returns a string that represents the current object.</summary>
    /// <returns>A string that represents the current object.</returns>
    public override string ToString()
    {
        return $"Thumbprint {Thumbprint} | Name {Name}";
    }

    /// <summary>Serves as the default hash function.</summary>
    /// <returns>A hash code for the current object.</returns>
    public override int GetHashCode()
    {
        return Thumbprint.GetHashCode();
    }

    /// <summary>Indicates whether the current object is equal to another object of the same type.</summary>
    /// <param name="other">An object to compare with this object.</param>
    /// <returns>
    /// <see langword="true" /> if the current object is equal to the <paramref name="other" /> parameter; otherwise, <see langword="false" />.</returns>
    public bool Equals(Intermediate? other)
    {
        if (other == null) return false;
        return other.Thumbprint == this.Thumbprint;
    }

    /// <summary>Determines whether the specified object is equal to the current object.</summary>
    /// <param name="obj">The object to compare with the current object.</param>
    /// <returns>
    /// <see langword="true" /> if the specified object  is equal to the current object; otherwise, <see langword="false" />.</returns>
    public override bool Equals(object? obj)
    {
        if (obj is Intermediate intermediate) return Equals(intermediate);
        return false;
    }
}