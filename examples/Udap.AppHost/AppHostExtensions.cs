#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Udap.AppHost;

internal static class AppHostExtensions
{
    /// <summary>
    /// pgAdmin as a plain persistent container rather than <c>WithPgAdmin()</c>.
    /// </summary>
    /// <remarks>
    /// <c>WithPgAdmin()</c> writes this AppHost's own server list into the container spec, so another AppHost
    /// sharing the same pgAdmin would recreate it on every start. This spec depends only on configuration:
    /// give two AppHosts the same container name, volume and servers file and they share one pgAdmin.
    /// The server list is imported once, when the volume is new.
    /// </remarks>
    public static IResourceBuilder<ContainerResource> AddSharedPgAdmin(
        this IDistributedApplicationBuilder builder,
        IConfigurationSection config,
        IResourceBuilder<PostgresServerResource> postgres)
    {
        // Normalized, because the path is part of the container spec two AppHosts must agree on.
        var serversFile = Path.GetFullPath(ExpandHome(config["ServersFile"] ?? "~/.udap-dotnet/pgadmin-servers.json"));
        if (!File.Exists(serversFile))
        {
            // The Postgres container answers to its container name on the network Aspire puts both containers on.
            var host = postgres.Resource.Annotations.OfType<ContainerNameAnnotation>().LastOrDefault()?.Name
                       ?? postgres.Resource.Name;
            Directory.CreateDirectory(Path.GetDirectoryName(serversFile)!);
            File.WriteAllText(serversFile, JsonSerializer.Serialize(new
            {
                Servers = new Dictionary<string, object>
                {
                    ["1"] = new
                    {
                        Name = host,
                        Group = "Servers",
                        Host = host,
                        Port = 5432,
                        Username = "postgres",
                        SSLMode = "prefer",
                        MaintenanceDB = "postgres"
                    }
                }
            }, new JsonSerializerOptions { WriteIndented = true }));
        }

        return builder.AddContainer("pgadmin", "dpage/pgadmin4", config["ImageTag"] ?? "9.15.0")
            .WithContainerName(config["ContainerName"] ?? "udap-pgadmin")
            .WithLifetime(ContainerLifetime.Persistent)
            .WithVolume(config["DataVolume"] ?? "udap-pgadmin-data", "/var/lib/pgadmin")
            .WithBindMount(serversFile, "/pgadmin4/shared-servers.json", isReadOnly: true)
            .WithEnvironment("PGADMIN_SERVER_JSON_FILE", "/pgadmin4/shared-servers.json")
            .WithEnvironment("PGADMIN_DEFAULT_EMAIL", "admin@domain.com")
            .WithEnvironment("PGADMIN_DEFAULT_PASSWORD", "admin")
            .WithEnvironment("PGADMIN_CONFIG_SERVER_MODE", "False")
            .WithEnvironment("PGADMIN_CONFIG_MASTER_PASSWORD_REQUIRED", "False")
            // Identity server cookies for every *.localhost app share one browser cookie jar and can overflow
            // gunicorn's 8190-byte header limit, which pgAdmin answers with 431.
            .WithEnvironment("GUNICORN_LIMIT_REQUEST_FIELD_SIZE", "32768")
            .WithHttpEndpoint(port: config.GetValue("Port", 5050), targetPort: 80, isProxied: false);
    }

    /// <summary>
    /// One run of migrations/UdapDb.Postgres: applies the schema to <paramref name="database"/>, seeds it,
    /// and exits. <paramref name="connectionName"/> is the ConnStrName the launch profile selects.
    /// </summary>
    public static IResourceBuilder<ProjectResource> AddUdapDbSeeder(
        this IDistributedApplicationBuilder builder,
        string name,
        string launchProfileName,
        IResourceBuilder<PostgresDatabaseResource> database,
        string connectionName)
    {
        return builder.AddProject<Projects.UdapDb_Postgres>(name, launchProfileName)
            .WithParentRelationship(database)
            .WithReference(database, connectionName)
            .WaitFor(database)
            // A web host that stops itself after seeding; any free port keeps the three runs from colliding.
            .WithEnvironment("ASPNETCORE_URLS", "http://127.0.0.1:0");
    }

    /// <summary>
    /// The resource answers to <paramref name="host"/> (a *.dev.localhost name) rather than localhost.
    /// </summary>
    /// <remarks>
    /// Points the dashboard links at that name, since the UDAP metadata, issuers and redirects all use it.
    /// Also checks at startup that the name resolves to loopback. Windows and browsers resolve *.localhost
    /// themselves, but some resolvers (a VPN, macOS) do not; then the app starts and every call to it fails
    /// with "No such host is known". The log says how to fix that.
    /// </remarks>
    public static IResourceBuilder<T> WithDevHost<T>(this IResourceBuilder<T> resource, string host)
        where T : IResourceWithEndpoints
    {
        resource.ApplicationBuilder.Eventing.Subscribe<BeforeStartEvent>(async (@event, ct) =>
        {
            IPAddress[] addresses;
            try
            {
                addresses = await Dns.GetHostAddressesAsync(host, ct);
            }
            catch (SocketException)
            {
                addresses = [];
            }

            if (!addresses.Any(IPAddress.IsLoopback))
            {
                @event.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Udap.AppHost").LogError(
                    "{Host} does not resolve to this machine, so {Resource} cannot be reached by its name. " +
                    "Add this line to your hosts file: 127.0.0.1 {Host}",
                    host, resource.Resource.Name, host);
            }
        });

        return resource.WithUrls(context =>
        {
            foreach (var url in context.Urls)
            {
                if (Uri.TryCreate(url.Url, UriKind.Absolute, out var absolute) && absolute.IsLoopback)
                {
                    url.Url = new UriBuilder(absolute) { Host = host }.Uri.ToString();
                }
            }
        });
    }

    private static string ExpandHome(string path) =>
        path.StartsWith('~')
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), path[1..].TrimStart('/', '\\'))
            : path;
}
