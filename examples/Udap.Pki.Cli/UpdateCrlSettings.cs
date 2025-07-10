using System.ComponentModel;
using Spectre.Console.Cli;

namespace Udap.Pki.Cli;

public class UpdateCrlSettings : CommandSettings
{
    [CommandOption("-t|--type <TYPE>")]
    [Description("The type of CRL to update: CA or SubCA")]
    public CrlType Type { get; set; }

    [CommandOption("--prod")]
    [Description("Run in production mode (default is test mode)")]
    public bool IsProduction { get; set; }
}