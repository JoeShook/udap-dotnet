using Spectre.Console;
using Spectre.Console.Cli;

namespace Udap.Pki.Cli;

public class UpdateCrlAllCommand : AsyncCommand<UpdateCrlSettings>
{
    public override async Task<int> ExecuteAsync(CommandContext context, UpdateCrlSettings settings, CancellationToken cancellationToken)
    {
        var password = UpdateCrlCommand.ResolvePassword(settings);

        AnsiConsole.MarkupLine("[bold]Updating CA CRL...[/]");
        var caResult = await UpdateCrlCommand.UpdateCrl(CrlType.CA, password, settings.IsProduction, settings.Days);
        if (caResult != 0)
        {
            AnsiConsole.MarkupLine("[red]CA CRL update failed.[/]");
            return caResult;
        }

        AnsiConsole.MarkupLine("[bold]Updating SubCA CRL...[/]");
        var subCaResult = await UpdateCrlCommand.UpdateCrl(CrlType.SubCA, password, settings.IsProduction, settings.Days);
        if (subCaResult != 0)
        {
            AnsiConsole.MarkupLine("[red]SubCA CRL update failed.[/]");
            return subCaResult;
        }

        AnsiConsole.MarkupLine("[bold green]Both CA and SubCA CRLs updated successfully.[/]");
        return 0;
    }
}
