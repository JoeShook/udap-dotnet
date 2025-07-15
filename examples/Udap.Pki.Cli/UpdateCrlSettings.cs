using System.ComponentModel;
using Spectre.Console.Cli;

namespace Udap.Pki.Cli;

public class UpdateCrlSettings : CommandSettings
{
    [CommandOption("-t|--type <TYPE>")]
    [Description("The type of CRL to update: CA or SubCA")]
    public CrlType Type { get; set; }

    [CommandOption("--days")]
    [Description("Set number of days before the CRL next update.")]
    public int Days { get; set; } = 7;

    [CommandOption("--prod")]
    [Description("Run in production mode (default is test mode)")]
    public bool IsProduction { get; set; }
}