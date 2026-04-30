# UDAP Proxy Server

Built on dotnet [YARP](https://microsoft.github.io/reverse-proxy/) (Yet Another Reverse Proxy) and ASP.NET Core.

The proxy server sits in front of an existing FHIR server and provides UDAP metadata and SMART on FHIR metadata endpoints. The [Udap.Metadata.Server](https://www.nuget.org/packages/Udap.Metadata.Server) and [Udap.Smart.Metadata](https://www.nuget.org/packages/Udap.Smart.Metadata) packages are used to generate the metadata. YARP routes and clusters are configured in appsettings.

For a TEFCA-specific variant with exchange purpose validation and GCP integration, see [Tefca.Proxy.Server](../Tefca.Proxy.Server/).

## Important Concepts

The proxy has anonymous routes and UDAP secured routes. To access FHIR resources, the client must follow UDAP Dynamic Client Registration and obtain an access token. All other routes are anonymous.

### Bearer Token

In this proxy scenario your FHIR server is secured by some mechanism, most likely a standard bearer access token. The code implements a GCP ADC technique based on a GCP service account. There is also a simple AccessToken technique — set `ReverseProxy:Routes:Metadata:AccessToken` to the name of an environment variable supplying your access token. Or write your own.

### Transforms

URLs in FHIR resources (e.g., paging links) must be transformed from backend URLs to proxy-facing URLs.

![Logical Diagram](./docs/udap-proxy-logical.svg)

You will need to configure for your FHIR server. This example does not include an accessible FHIR Server, although it is the FHIR server used by fhirlabs.net and includes all the bits to deploy to a GCP Cloud Run application.
