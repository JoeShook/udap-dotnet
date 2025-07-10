using Spectre.Console.Cli;

namespace Udap.Pki.Cli;

class Program
{
    public static async Task<int> Main(string[] args)
    {
        var app = new CommandApp();
        app.Configure(config =>
        {
            config.SetApplicationName("udap-pki-cli");
            config.AddCommand<UpdateCrlCommand>("crl-update")
                .WithDescription("Update the CRL for CA or SubCA")
                .WithExample(new[] { "crl-update", "--type", "CA", "--prod" });
        });

        return await app.RunAsync(args);
    }
}