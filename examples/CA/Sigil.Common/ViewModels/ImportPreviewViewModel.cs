namespace Sigil.Common.ViewModels;

public class ImportPreviewViewModel
{
    public string CommunityName { get; set; } = string.Empty;
    public string DirectoryPath { get; set; } = string.Empty;
    public int RootCaCount { get; set; }
    public int IntermediateCount { get; set; }
    public int IssuedCertCount { get; set; }
    public int CrlCount { get; set; }
    public List<string> Errors { get; set; } = new();
    public bool IsValid => Errors.Count == 0;
}
