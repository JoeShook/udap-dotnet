#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Duende.IdentityModel;
using Firely.Fhir.Packages;
using Google.Apis.Auth.OAuth2;
using Hl7.Fhir.Model;
using Hl7.Fhir.Model.CdsHooks;
using Hl7.Fhir.Serialization;
using Hl7.Fhir.Specification.Source;
using Hl7.Fhir.Specification.Terminology;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Serialization;
using Firely.Fhir.Validation;
using Udap.CdsHooks.Model;
using Udap.Common;
using Udap.Proxy.Server;
using Udap.Proxy.Server.IDIPatientMatch;
using Udap.Proxy.Server.Services;
using Udap.Smart.Model;
using Udap.Util.Extensions;
using Yarp.ReverseProxy.Transforms;
using ZiggyCreatures.Caching.Fusion;
using Constants = Udap.Common.Constants;

var builder = WebApplication.CreateBuilder(args);

Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Configuration)
    .CreateLogger();

builder.Host.UseSerilog();

// Mount Cloud Secrets
builder.Configuration.AddJsonFile("/secret/udapproxyserverappsettings", true, false);
builder.Configuration.AddJsonFile("/secret/metadata/udap.proxy.server.metadata.options.json", true, false);

// Add services to the container.
builder.Services.AddControllersWithViews();

builder.Services.Configure<JsonOptions>(options =>
{
    options.JsonSerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
    options.JsonSerializerOptions.PropertyNameCaseInsensitive = true;
    options.JsonSerializerOptions.Converters.Add(new FhirResourceConverter());
});

builder.Services.Configure<CdsServices>(builder.Configuration.GetRequiredSection("CdsServices"));
builder.Services.Configure<SmartMetadata>(builder.Configuration.GetRequiredSection("SmartMetadata"));
builder.Services.Configure<UdapFileCertStoreManifest>(builder.Configuration.GetSection(Constants.UDAP_FILE_STORE_MANIFEST));

builder.Services.AddCdsServices();
builder.Services.AddSmartMetadata();
builder.Services.AddUdapMetadataServer(builder.Configuration);
builder.Services.AddFusionCache()
    .WithDefaultEntryOptions(new FusionCacheEntryOptions
    {
        Duration = TimeSpan.FromMinutes(10),
        FactorySoftTimeout = TimeSpan.FromMilliseconds(100),
        AllowTimedOutFactoryBackgroundCompletion = true,
        FailSafeMaxDuration = TimeSpan.FromHours(12)
    });

builder.Services.AddAuthentication(OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer)

    .AddJwtBearer(OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer, options =>
    {
        options.Authority = builder.Configuration["Jwt:Authority"];
        options.RequireHttpsMetadata = bool.Parse(builder.Configuration["Jwt:RequireHttpsMetadata"] ?? "true");

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = false
        };
    });

builder.Services.AddCors(options =>
{
    options.AddPolicy("DefaultPolicy", builder =>
    {
        builder.AllowAnyOrigin()
            .AllowAnyMethod()
            .AllowAnyHeader();
    });
});

builder.Services.AddAuthorizationBuilder()
    .AddPolicy("udapPolicy", policy =>
        policy.RequireAuthenticatedUser());

builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .ConfigureHttpClient((_, handler) =>
    {
        // Enable automatic decompression for gzip, deflate, and brotli
        handler.AutomaticDecompression = System.Net.DecompressionMethods.GZip |
                                          System.Net.DecompressionMethods.Deflate |
                                          System.Net.DecompressionMethods.Brotli;
    })
    .AddTransforms(builderContext =>
    {
        // Always forward encoding headers for all routes
        builderContext.AddRequestTransform(context =>
        {
            ForwardEncodingHeaders(context.HttpContext, context.ProxyRequest);
            return ValueTask.CompletedTask;
        });

        // Conditionally add a transform for routes that require auth.
        if (builderContext.Route.Metadata != null &&
            (builderContext.Route.Metadata.ContainsKey("GCPKeyResolve") || builderContext.Route.Metadata.ContainsKey("AccessToken")))
        {
            builderContext.AddRequestTransform(async context =>
            {
                var accessTokenService = context.HttpContext.RequestServices.GetRequiredService<IAccessTokenService>();
                var resolveAccessToken = await accessTokenService.ResolveAccessTokenAsync(
                    builderContext.Route.Metadata, 
                    context.HttpContext.RequestServices.GetRequiredService<ILogger<AccessTokenService>>(), 
                    cancellationToken: context.HttpContext.RequestAborted);
                context.ProxyRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", resolveAccessToken);
                SetProxyHeaders(context);
            });
        }

        // Use the default credentials.  Primary usage: running in Cloud Run under a specific service account
        if (builderContext.Route.Metadata != null && (builderContext.Route.Metadata.TryGetValue("ADC", out string? adc)))
        {
            if (adc.Equals("True", StringComparison.OrdinalIgnoreCase))
            {
                builderContext.AddRequestTransform(async context =>
                {
                    var googleCredentials = GoogleCredential.GetApplicationDefault();
                    string accessToken = await googleCredentials.UnderlyingCredential.GetAccessTokenForRequestAsync();
                    context.ProxyRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                    SetProxyHeaders(context);
                });
            }
        }

        builderContext.AddResponseTransform(async responseContext =>
        {
            if (responseContext.HttpContext.Request.Path == "/fhir/r4/metadata")
            {
                responseContext.SuppressResponseBody = true;
                var cache = responseContext.HttpContext.RequestServices.GetRequiredService<IFusionCache>();
                var bytes = await cache.GetOrSetAsync("metadata", _ => GetFhirMetadata(responseContext, builder));
                
                // Change Content-Length to match the modified body, or remove it.
                responseContext.HttpContext.Response.ContentLength = bytes?.Length;
                
                // Response headers are copied before transforms are invoked, update any needed headers on the HttpContext.Response.
                await responseContext.HttpContext.Response.Body.WriteAsync(bytes);
            }

            //
            // Rewrite resource URLs
            //
            else if (responseContext.HttpContext.Request.Path.HasValue && 
                     responseContext.HttpContext.Request.Path.Value.StartsWith("/fhir/r4/", StringComparison.OrdinalIgnoreCase))
            {
                responseContext.SuppressResponseBody = true;
                var stream = await responseContext.ProxyResponse!.Content.ReadAsStreamAsync();

                Console.WriteLine($"RESPONSE CODE: {responseContext.ProxyResponse.StatusCode}");
                
                
                using var reader = new StreamReader(stream);
                // TODO: size limits, timeouts
                var body = await reader.ReadToEndAsync();

                var finalBytes = Encoding.UTF8.GetBytes(body.Replace($"\"url\": \"{builder.Configuration["FhirUrlProxy:Back"]}",
                    $"\"url\": \"{builder.Configuration["FhirUrlProxy:Front"]}"));
                responseContext.HttpContext.Response.ContentLength = finalBytes.Length;
                
                await responseContext.HttpContext.Response.Body.WriteAsync(finalBytes);
            }
        });
    });

var disableCompression = Environment.GetEnvironmentVariable("ASPNETCORE_RESPONSE_COMPRESSION_DISSABLED");
if (!string.Equals(disableCompression, "true", StringComparison.OrdinalIgnoreCase))
{
    builder.Services.AddResponseCompression(options =>
    {
        options.EnableForHttps = true;
        options.MimeTypes = ResponseCompressionDefaults.MimeTypes.Concat([
            "application/fhir+xml",
            "application/fhir+json"
        ]);
    });
}

builder.Services.AddHttpClient();
builder.Services.AddSingleton<IAccessTokenService, AccessTokenService>();

//
// IDI Patient Match Operations
//
builder.Services.AddSingleton<IFhirOperation, OpMatch>();
builder.Services.AddSingleton<IFhirOperation, OpIdiMatch>();
builder.Services.AddSingleton<IIdiPatientRules, IdiPatientRules>();
builder.Services.AddSingleton<IIdiPatientMatchInValidator, IdiPatientMatchInValidator>();


builder.Services.AddSingleton<Validator>(sp =>
{
    IAsyncResourceResolver packageSource = new FhirPackageSource(ModelInfo.ModelInspector, @"IDIPatientMatch/packages/hl7.fhir.r4b.core-4.3.0.tgz");
    var coreSource = new CachedResolver(packageSource);
    var coreSnapshot = new SnapshotSource(coreSource);
    var terminologySource = new LocalTerminologyService(coreSnapshot);
    IAsyncResourceResolver idiSource = new FhirPackageSource(ModelInfo.ModelInspector, @"IDIPatientMatch/packages/hl7.fhir.us.identity-matching-2.0.0-ballot.tgz");
    var source = new MultiResolver(idiSource, coreSnapshot);
    var settings = new ValidationSettings { ConformanceResourceResolver = source };
    return new Validator(source, terminologySource, null, settings);

});

var app = builder.Build();

// Configure the HTTP request pipeline.
app.UseCors("DefaultPolicy");

if (!string.Equals(disableCompression, "true", StringComparison.OrdinalIgnoreCase))
{
    app.UseResponseCompression();
}

app.UseDefaultFiles();
app.UseStaticFiles();

// Write streamlined request completion events, instead of the more verbose ones from the framework.
// To use the default framework request logging instead, remove this line and set the "Microsoft"
// level in appsettings.json to "Information".
app.UseSerilogRequestLogging();
    
app.UseAuthentication();
app.UseAuthorization();

//
// IDI Patient Match Operations
//
app.UseMiddleware<OperationMiddleware>();


app.UseMiddleware<RouteLoggingMiddleware>();
app.MapReverseProxy();

app.UseCdsServices("fhir/r4");
app.UseSmartMetadata("fhir/r4");
app.UseUdapMetadataServer("fhir/r4"); // Ensure metadata can only be called from this base URL.

app.Run();


async Task<byte[]?> GetFhirMetadata(ResponseTransformContext responseTransformContext,
    WebApplicationBuilder webApplicationBuilder)
{
    var stream = responseTransformContext.ProxyResponse?.Content != null
        ? await responseTransformContext.ProxyResponse.Content.ReadAsStreamAsync()
        : Stream.Null;

    using var reader = new StreamReader(stream);
    var body = await reader.ReadToEndAsync();

    if (!string.IsNullOrEmpty(body))
    {
        var capStatement = await new FhirJsonParser().ParseAsync<CapabilityStatement>(body);
        var securityComponent = new CapabilityStatement.SecurityComponent();

        securityComponent.Service.Add(
            new CodeableConcept("http://fhir.udap.org/CodeSystem/capability-rest-security-service",
                "UDAP",
                "OAuth2 using UDAP profile (see http://www.udap.org)"));

        //
        // https://build.fhir.org/ig/HL7/fhir-extensions/StructureDefinition-oauth-uris.html
        //
        var oauthUrlExtensions = new Extension();
        var securityExtension = new Extension("http://fhir-registry.smarthealthit.org/StructureDefinition/oauth-uris", oauthUrlExtensions);
        securityExtension.Extension.Add(new Extension() { Url = "token", Value = new FhirUri(webApplicationBuilder.Configuration["Jwt:Token"]) });
        securityExtension.Extension.Add(new Extension() { Url = "authorize", Value = new FhirUri(webApplicationBuilder.Configuration["Jwt:Authorize"]) });
        securityExtension.Extension.Add(new Extension() { Url = "register", Value = new FhirUri(webApplicationBuilder.Configuration["Jwt:Register"]) });
        securityExtension.Extension.Add(new Extension() { Url = "manage", Value = new FhirUri(webApplicationBuilder.Configuration["Jwt:Manage"]) });
        securityComponent.Extension.Add(securityExtension);
        capStatement.Rest.First().Security = securityComponent;

        body = new FhirJsonSerializer().SerializeToString(capStatement);
        var bytes = Encoding.UTF8.GetBytes(body);
        
        return bytes;
    }

    return null;
}

void SetProxyHeaders(RequestTransformContext requestTransformContext)
{
    if (requestTransformContext.HttpContext.Request.Headers.Authorization.Count == 0)
    {
        return;
    }

    var bearerToken = requestTransformContext.HttpContext.Request.Headers.Authorization.First();
    
    if (bearerToken == null)
    {
        return;
    }

    foreach (var requestHeader in requestTransformContext.HttpContext.Request.Headers)
    {
        Console.WriteLine(requestHeader.Value);
    }

    var tokenHandler = new JwtSecurityTokenHandler();
    var jsonToken = tokenHandler.ReadJwtToken(requestTransformContext.HttpContext.Request.Headers.Authorization.First()?.Replace("Bearer", "").Trim());
    var scopes = jsonToken.Claims.Where(c => c.Type == "scope");
    var iss = jsonToken.Claims.Where(c => c.Type == "iss");
    // var sub = jsonToken.Claims.Where(c => c.Type == "sub"); // figure out what subject should be for GCP

    //TODO:  This should be capable of introspection calls, because the token may not be a jwt.
    // Never let the requester set this header.
    requestTransformContext.ProxyRequest.Headers.Remove("X-Authorization-Scope");
    requestTransformContext.ProxyRequest.Headers.Remove("X-Authorization-Issuer");
 
    // Google Cloud way of passing scopes to the Fhir Server
    var spaceSeparatedString = scopes.Select(s => s.Value)
        .Where(s => s != "udap") //gcp doesn't know udap  Need better filter to block unknown scopes
        .ToSpaceSeparatedString();
    
    requestTransformContext.ProxyRequest.Headers.Add("X-Authorization-Scope", spaceSeparatedString);
    requestTransformContext.ProxyRequest.Headers.Add("X-Authorization-Issuer", iss.SingleOrDefault()?.Value);
    // context.ProxyRequest.Headers.Add("X-Authorization-Subject", sub.SingleOrDefault().Value);
}

void ForwardEncodingHeaders(HttpContext httpContext, HttpRequestMessage proxyRequest)
{
    // Forward Accept-Encoding from client to backend
    if (httpContext.Request.Headers.TryGetValue("Accept-Encoding", out var encodings))
    {
        proxyRequest.Headers.Remove("Accept-Encoding");
        proxyRequest.Headers.Add("Accept-Encoding", encodings.ToArray());
    }
    // Forward Content-Encoding if present
    if (httpContext.Request.Headers.TryGetValue("Content-Encoding", out var contentEncodings))
    {
        proxyRequest.Headers.Remove("Content-Encoding");
        proxyRequest.Headers.Add("Content-Encoding", contentEncodings.ToArray());
    }
}