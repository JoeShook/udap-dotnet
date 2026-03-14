#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Diagnostics;

namespace Udap.Common;

/// <summary>
/// Provides OpenTelemetry <see cref="ActivitySource"/> instances and trace property constants
/// for instrumenting UDAP server operations.
/// </summary>
public static class Tracing
{
    /// <summary>The validation trace name.</summary>
    public static readonly string Validation = TraceNames.Validation;

    private static readonly Version AssemblyVersion = typeof(Tracing).Assembly.GetName().Version!;

    /// <summary>
    /// <see cref="ActivitySource"/> for certificate store operations.
    /// </summary>
    public static ActivitySource StoreActivitySource { get; } = new(
        TraceNames.Store,
        ServiceVersion);

    /// <summary>
    /// <see cref="ActivitySource"/> for certificate chain validation operations.
    /// </summary>
    public static ActivitySource ValidationActivitySource { get; } = new(
        TraceNames.Validation,
        ServiceVersion);

    /// <summary>
    /// <see cref="ActivitySource"/> for UDAP discovery endpoint operations.
    /// </summary>
    public static ActivitySource DiscoveryEndpointActivitySource { get; } = new(
        TraceNames.Endpoints,
        ServiceVersion);

    /// <summary>
    /// Gets the assembly version in <c>Major.Minor.Build</c> format for trace source versioning.
    /// </summary>
    public static string ServiceVersion => $"{AssemblyVersion.Major}.{AssemblyVersion.Minor}.{AssemblyVersion.Build}";

    /// <summary>
    /// Trace source name constants used to create <see cref="ActivitySource"/> instances.
    /// </summary>
    public static class TraceNames
    {
        /// <summary>
        /// Service name for base traces
        /// </summary>
        public static string Basic => "Udap.Server";

        /// <summary>
        /// Service name for store traces
        /// </summary>
        public static string Store => Basic + ".Stores";


        /// <summary>
        /// Service name for detailed validation traces
        /// </summary>
        public static string Validation => Basic + ".Validation";

        /// <summary>
        /// Service name for discovery endpoint traces
        /// </summary>
        public static string Endpoints => Basic + ".Endpoints";
    }

    /// <summary>
    /// Tag/property name constants used when adding attributes to <see cref="Activity"/> spans.
    /// </summary>
    public static class Properties
    {
        /// <summary>The type of endpoint being traced.</summary>
        public const string EndpointType = "endpoint_type";
        /// <summary>The OAuth client identifier.</summary>
        public const string ClientId = "client_id";
        /// <summary>The Identity Provider base URL.</summary>
        public const string IdPBaseUrl = "idp_base_url";
        /// <summary>The OAuth grant type.</summary>
        public const string GrantType = "grant_type";
        /// <summary>The requested OAuth scope.</summary>
        public const string Scope = "scope";
        /// <summary>The target FHIR resource.</summary>
        public const string Resource = "resource";
        /// <summary>The request origin.</summary>
        public const string Origin = "origin";
        /// <summary>The authentication scheme.</summary>
        public const string Scheme = "scheme";
        /// <summary>The entity type.</summary>
        public const string Type = "type";
        /// <summary>The entity identifier.</summary>
        public const string Id = "id";
        /// <summary>The scope names.</summary>
        public const string ScopeNames = "scope_names";
        /// <summary>The API resource names.</summary>
        public const string ApiResourceNames = "api_resource_names";
        /// <summary>The UDAP community name.</summary>
        public const string Community = "Community_Name";
        /// <summary>The UDAP community identifier.</summary>
        public const string CommunityId = "CommunityId";
        /// <summary>The trust anchor certificate.</summary>
        public const string AnchorCertificate = "anchor_certificate";
        /// <summary>The root certificate.</summary>
        public const string RootCertificate = "root_certificate";
    }
}