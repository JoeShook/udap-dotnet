using Microsoft.Extensions.FileProviders;
using Serilog;
using Serilog.Events;
using Serilog.Sinks.SystemConsole.Themes;

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateBootstrapLogger();

Log.Information("Starting up");

try
{
    var builder = WebApplication.CreateBuilder(args);

    builder.Host.UseSerilog((ctx, lc) => lc
        .WriteTo.Console(
            outputTemplate:
            "[{Timestamp:HH:mm:ss} {Level}][{ThreadId:d}] {SourceContext} {Message:lj}{NewLine}{Exception}",
            theme: AnsiConsoleTheme.Code)
        .MinimumLevel.Information()
        .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
        .MinimumLevel.Override("Microsoft.AspNetCore.HttpLogging.HttpLoggingMiddleware", LogEventLevel.Information)
        .MinimumLevel.Override("Microsoft.Hosting.Lifetime", LogEventLevel.Information)
        .MinimumLevel.Override("System", LogEventLevel.Warning)
        .Enrich.FromLogContext()
        .Enrich.WithThreadId());

    // Add services to the container.

    var provider = new Microsoft.AspNetCore.StaticFiles.FileExtensionContentTypeProvider();
    // NOTE: Add new mappings
    provider.Mappings[".cer"] = "application/x-x509-ca-cert"; // NOTE: add the extension (with period) and its type

    builder.Services.AddDirectoryBrowser();

    var app = builder.Build();

    app.UseSerilogRequestLogging();

    // Configure the HTTP request pipeline.
    app.UseStaticFiles(new StaticFileOptions
    {
        ContentTypeProvider = provider
    });

    app.UseDirectoryBrowser(new DirectoryBrowserOptions
    {
        FileProvider = new PhysicalFileProvider(Path.Combine(builder.Environment.WebRootPath))
    });

    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Unhandled exception");
}
finally
{
    Log.CloseAndFlush();
}
