#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Blazored.LocalStorage;
using BQuery;
using MudBlazor.Services;
using Serilog;
using Serilog.Events;
using Serilog.Sinks.SystemConsole.Themes;
using Udap.Client.Authentication;
using Udap.Client.Client;
using Udap.Client.Rest;
using Udap.Common.Certificates;
using UdapEd.Server.Authentication;
using UdapEd.Server.Extensions;
using UdapEd.Server.Rest;
using UdapEd.Server.Services;


var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Host.UseSerilog((ctx, lc) => lc
    .MinimumLevel.Information()
    .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
    .MinimumLevel.Override("Microsoft.Hosting.Lifetime", LogEventLevel.Information)
    .MinimumLevel.Override("Microsoft.AspNetCore.Authentication", LogEventLevel.Information)
    .MinimumLevel.Override("IdentityModel", LogEventLevel.Debug)
    .MinimumLevel.Override("Duende.Bff", LogEventLevel.Debug)
    .Enrich.FromLogContext()
    .WriteTo.Console(
        outputTemplate:
        "[{Timestamp:HH:mm:ss} {Level}] {SourceContext}{NewLine}{Message:lj}{NewLine}{Exception}{NewLine}",
        theme: AnsiConsoleTheme.Code));

builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(60);
    options.Cookie.Name = ".FhirLabs.UdapEd";
    options.Cookie.IsEssential = true;
});

//
// builder.Services.AddControllersWithViews();

builder.Services.AddRazorPages();
builder.Services.AddServerSideBlazor();




builder.Services.AddScoped(sp => new HttpClient
{
    BaseAddress = new Uri("https://localhost:7041")//Todo remove after migrated from WebAssembly to server
});

builder.Services.AddMudServices();
builder.Services.AddBlazoredLocalStorage(config =>
    config.JsonSerializerOptions.WriteIndented = true
);

builder.Services.AddScoped<UdapClientState>(); //Singleton in Blazor wasm and Scoped in Blazor Server
builder.Services.AddScoped<RegisterService>();
builder.Services.AddScoped<DiscoveryService>();
builder.Services.AddScoped<AccessService>();
builder.Services.AddScoped<FhirService>();


// builder.Services.AddBff();

//
// builder.Services.AddAuthentication(options =>
//     {
//         options.DefaultScheme = "cookie";
//         options.DefaultChallengeScheme = "oidc";
//         options.DefaultSignOutScheme = "oidc";
//     })
//     .AddCookie("cookie", options =>
//     {
//         options.Cookie.Name = "__UdapClientBackend";
//         options.Cookie.SameSite = SameSiteMode.Strict;
//     })
//     .AddOpenIdConnect("oidc", options =>
//     {
//         options.Authority = "https://loclahost:5002";
//
//         // Udap Authorization code flow
//         options.ClientId = "interactive.confidential";  //TODO Dynamic
//         options.ClientSecret = "secret";
//         options.ResponseType = "code";
//         options.ResponseMode = "query";
//
//         options.MapInboundClaims = false;
//         options.GetClaimsFromUserInfoEndpoint = true;
//         options.SaveTokens = true;
//
//         // request scopes + refresh tokens
//         options.Scope.Clear();
//         options.Scope.Add("openid");
//         options.Scope.Add("profile");
//         options.Scope.Add("api");
//         options.Scope.Add("offline_access");
//
//     });

builder.Services.AddScoped<TrustChainValidator>();
builder.Services.AddHttpClient<IUdapClient, UdapClient>();

builder.Services.AddScoped<IBaseUrlProvider, BaseUrlProvider>();
builder.Services.AddScoped<IAccessTokenProvider, AccessTokenProvider>();
builder.Services.AddHttpClient<FhirClientWithUrlProvider>((sp, httpClient) =>
{ })
    .AddHttpMessageHandler(x => new AuthTokenHttpMessageHandler(x.GetRequiredService<IAccessTokenProvider>()));

builder.Services.AddHttpContextAccessor();

builder.AddRateLimiting();

// Configure OpenTelemetry
builder.AddOpenTelemetry();

builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.Cookie.IsEssential = true;
});

var app = builder.Build();

app.UseSession();
app.UseSerilogRequestLogging();


// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

// app.UseHttpsRedirection();

// app.UseBlazorFrameworkFiles();
app.UseStaticFiles();

//begin Set() hack
// https://stackoverflow.com/a/71446689/6115838
app.Use(async delegate (HttpContext Context, Func<Task> Next)
{
    //this throwaway session variable will "prime" the Set() method
    //to allow it to be called after the response has started
    var TempKey = Guid.NewGuid().ToString(); //create a random key
    Context.Session.Set(TempKey, Array.Empty<byte>()); //set the throwaway session variable
    Context.Session.Remove(TempKey); //remove the throwaway session variable
    await Next(); //continue on with the request
});
//end Set() hack


app.UseRouting();


app.MapBlazorHub();
app.MapFallbackToPage("/_Host");

app.UseRateLimiter(); //after routing

// app.MapRazorPages(); // todo do I need this

app.UseBQuery();

app.Run();
