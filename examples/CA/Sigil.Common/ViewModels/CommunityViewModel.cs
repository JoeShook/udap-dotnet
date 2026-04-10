namespace Sigil.Common.ViewModels;

public class CommunityViewModel
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool Enabled { get; set; } = true;
    public int RootCaCount { get; set; }
    public int TotalCertCount { get; set; }
    public DateTime CreatedAt { get; set; }
}
