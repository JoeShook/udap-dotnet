namespace Sigil.Common.Data.Entities;

public class Community
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool Enabled { get; set; } = true;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public ICollection<CaCertificate> CaCertificates { get; set; } = new List<CaCertificate>();
}
