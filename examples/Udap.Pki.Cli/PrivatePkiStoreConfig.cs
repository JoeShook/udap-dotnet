namespace Udap.Pki.Cli;

class PrivatePkiStoreConfig
{
    public string CaBucket { get; set; } = string.Empty;
    public string CaP12Path { get; set; } = string.Empty;
    public string SubCaP12Path { get; set; } = string.Empty;
    public string CaCrlPath { get; set; } = string.Empty;
    public string SubCaCrlPath { get; set; } = string.Empty;
    public string CrlHistoryPath { get; set; } = string.Empty;
}