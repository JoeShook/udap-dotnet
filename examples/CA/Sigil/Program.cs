using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.FluentUI.AspNetCore.Components;
using Serilog;
using Sigil.Components;
using Sigil.Common.Data;
using Sigil.Common.Services;

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateBootstrapLogger();

try
{
    var builder = WebApplication.CreateBuilder(args);

    // Serilog
    builder.Host.UseSerilog((context, config) => config
        .ReadFrom.Configuration(context.Configuration)
        .WriteTo.Console());

    // PostgreSQL
    builder.Services.AddDbContextFactory<SigilDbContext>(options =>
        options.UseNpgsql(builder.Configuration.GetConnectionString("SigilDb")));

    // Services
    builder.Services.AddScoped<CertificateImportService>();
    builder.Services.AddScoped<CertificateParsingService>();
    builder.Services.AddScoped<Asn1ParsingService>();
    builder.Services.AddScoped<CrlImportService>();
    builder.Services.AddScoped<ChainValidationService>();
    builder.Services.AddHttpClient("SigilCrl");
    builder.Services.AddHttpClient();

    // Blazor Server + Fluent UI
    builder.Services.AddRazorComponents()
        .AddInteractiveServerComponents();
    builder.Services.AddFluentUIComponents();

    var app = builder.Build();

    // Run migrations
    using (var scope = app.Services.CreateScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<SigilDbContext>();
        await db.Database.MigrateAsync();
    }

    app.UseSerilogRequestLogging(options =>
    {
        options.GetLevel = (httpContext, elapsed, ex) =>
        {
            var path = httpContext.Request.Path.Value ?? "";
            if (path.StartsWith("/_blazor") ||
                path.StartsWith("/_framework") ||
                path.StartsWith("/_content") ||
                path.StartsWith("/css") ||
                path == "/favicon.ico")
            {
                return Serilog.Events.LogEventLevel.Debug;
            }

            return Serilog.Events.LogEventLevel.Information;
        };
    });

    app.UseStaticFiles();
    app.MapStaticAssets();
    app.UseAntiforgery();

    app.MapRazorComponents<App>()
        .AddInteractiveServerRenderMode()
        .AddAdditionalAssemblies(
            typeof(FluentButton).Assembly,
            typeof(Sigil.UI.Components.Pages.Home).Assembly);

    // Download endpoints
    app.MapGet("/api/ca/{id}/download/cer", async (int id, IDbContextFactory<SigilDbContext> dbFactory) =>
    {
        await using var db = await dbFactory.CreateDbContextAsync();
        var ca = await db.CaCertificates.FindAsync(id);
        if (ca == null) return Results.NotFound();

        var cerBytes = Encoding.UTF8.GetBytes(ca.X509CertificatePem);
        return Results.File(cerBytes, "application/x-pem-file", $"{ca.Name}.cer");
    });

    app.MapGet("/api/ca/{id}/download/pfx", async (int id, IDbContextFactory<SigilDbContext> dbFactory) =>
    {
        await using var db = await dbFactory.CreateDbContextAsync();
        var ca = await db.CaCertificates.FindAsync(id);
        if (ca?.EncryptedPfxBytes == null) return Results.NotFound("No private key available");

        return Results.File(ca.EncryptedPfxBytes, "application/x-pkcs12", $"{ca.Name}.pfx");
    });

    app.MapGet("/api/issued/{id}/download/cer", async (int id, IDbContextFactory<SigilDbContext> dbFactory) =>
    {
        await using var db = await dbFactory.CreateDbContextAsync();
        var cert = await db.IssuedCertificates.FindAsync(id);
        if (cert == null) return Results.NotFound();

        var cerBytes = Encoding.UTF8.GetBytes(cert.X509CertificatePem);
        return Results.File(cerBytes, "application/x-pem-file", $"{cert.Name}.cer");
    });

    app.MapGet("/api/issued/{id}/download/pfx", async (int id, IDbContextFactory<SigilDbContext> dbFactory) =>
    {
        await using var db = await dbFactory.CreateDbContextAsync();
        var cert = await db.IssuedCertificates.FindAsync(id);
        if (cert?.EncryptedPfxBytes == null) return Results.NotFound("No private key available");

        return Results.File(cert.EncryptedPfxBytes, "application/x-pkcs12", $"{cert.Name}.pfx");
    });

    app.MapGet("/api/crl/{id}/download", async (int id, IDbContextFactory<SigilDbContext> dbFactory) =>
    {
        await using var db = await dbFactory.CreateDbContextAsync();
        var crl = await db.Crls.FindAsync(id);
        if (crl == null) return Results.NotFound();

        var fileName = crl.FileName ?? $"crl-{crl.CrlNumber}.crl";
        return Results.File(crl.RawBytes, "application/pkix-crl", fileName);
    });

    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Application terminated unexpectedly");
}
finally
{
    Log.CloseAndFlush();
}
