<!-- Source: https://www.udap.org/udap-server-metadata.html -->
<!-- Downloaded: 2026-04-01 -->

# **UDAP Server Metadata**

**Version STU 1**

The UDAP profiles support the availability of server metadata at a well-known URL, however the specific metadata to require is left to the community based on the profiles and workflows supported. In general, if a community defines all required elements and workflows and does NOT include any optional elements or workflows, the metadata required to support this is limited. However, when optionality is permitted on the Authorization Server side, inclusion of the corresponding metadata is RECOMMENDED. For example, if the profile allows optional support for certain signing algorithms, then it would generally be beneficial to include these algorithms as a required metadata element for Authorization Servers. 

Metadata elements that reflect general OAuth 2.0 concepts SHALL be understood apply to the actor’s UDAP functionality, and SHALL be preferred by other actors over other metadata published by the same actor for other non-UDAP OAuth 2.0 workflows. Additionally, several of the concepts are only relevant to actors in the role of Authorization Server, and some are only relevant when certain profiles are supported. Thus, the metadata requirements for actors in the client and server roles MAY be (and typically will be) different.

In some cases, some metadata elements may be available via another mechanism supported by the community; such communities are encouraged to include this metadata in the UDAP metadata, as well.

When a key is included in the metadata with a value listing a set of supported parameters, i.e. the metadata key name ends in “_supported”, other actors MAY assume that, at least for UDAP workflows, the publisher of the metadata does NOT support other parameter values for this key. To communicate that optional functionality represented by a metadata key with an array value is NOT supported, the metadata publisher SHOULD include the key with an empty array value. If a metadata key is omitted, a client application SHOULD NOT make any assumptions regarding the parameter values supported by the metadata publisher, if any. The metadata publisher SHALL NOT publish parameter values supported only for other non-UDAP workflows in its UDAP metadata. Actors MAY ignore unrecognized keys in metadata obtained from other actors. 

This profile allows for the digital signing of endpoint URLs used for OAuth 2.0 transactions, including the authorization, token, and registration endpoints, to allow for Client applications to validate this information before redirecting a user to a server’s authorization endpoint or submitting data to the server’s token or registration endpoint. The primary use case for validation is for a client application to verify the authenticity of these OAuth 2.0 endpoints before initiating a transaction by confirming the metadata is signed by the expected organization. This is analogous to how an Authorization Server validates client-submitted information during UDAP Dynamic Client Registration or JWT-Based Client Authentication transactions. Additionally, for Client apps that utilize the authorization code flow, the inclusion of signed endpoints allows the Client app to display the validated information about the signing organization to the end user for confirmation before redirecting the user to the authorization endpoint, which will generally be more informative and/or granular than the attributes of a server’s TLS certificate.

1 Supported metadata elements

The list of supported metadata elements that a community may include are listed below:

x5c: an array of one or more certificates represented as strings containing the Base64 encoding of the DER representation of the certificate; the first certificate in the array is used by the UDAP actor to sign JWTs and/or to decrypt JWTs; the remaining certificates form a certificate chain, i.e. the subject of the certificate is the issuer of the preceding certificate in the chain.

udap_versions_supported: an array of strings containing the supported UDAP versions. Currently, the only defined version is “1”. UDAP versions are case-insensitive strings.

udap_profiles_supported: an array of one or more strings identifying the core UDAP profiles that this actor supports. Values: “udap_dcr” for UDAP Dynamic Client Registration, “udap_authn” for UDAP JWT-Based Client Authentication, “udap_authz” for UDAP Client Authorization, and “udap_to” for UDAP Tiered OAuth. At least one profile SHALL be supported.

udap_certifications_supported: an array of zero or more strings each containing a URI corresponding to a value recognized by the metadata publisher as an acceptable value in the certification_uris array. The meaning of the value is defined by the publishers of the profiles for the certification or endorsement referenced by each URI.

udap_certifications_required: an array of one or more strings each containing a URI corresponding to a value recognized by the metadata publisher as a required value in the certification_uris array. The meaning of the value is defined by the publishers of the profiles for the certification or endorsement referenced by each URI.

udap_authorization_extensions_supported: an array of zero or more recognized key names for authorization extension objects included in the extensions element of an authentication and/or authorization JWT submitted to the token endpoint. The key names are defined by the publishers of the profiles for the corresponding authorization extension objects.

udap_authorization_extensions_required: an array of one or more recognized key names for authorization extension objects included in the extensions element of an authentication and/or authorization JWT submitted to the token endpoint. The key names are defined by the publishers of the profiles for the corresponding authorization extension objects.

grant_types_supported: an array of one or more grant types supported by this actor for the UDAP workflows. At least one grant type SHALL be supported.

scopes_supported: an array of one or more strings supported by this actor for the UDAP workflows. A metadata publisher MAY support a subset of these scopes for different client types or entities.

authorization_endpoint, token_endpoint, registration_endpoint: a string containing the URI to access the corresponding endpoint.

signed_endpoints: a signed JWT containing the URI(s) of the authorization_endpoint, token_endpoint, and/or registration_endpoint, as detailed further in section 2.

token_endpoint_auth_methods_supported: an array on one or more authentication methods supported by the metadata publisher for UDAP workflows. At least one authentication method SHALL be supported. Generally, this array will have a single element: “private_key_jwt”.

token_endpoint_auth_signing_alg_values_supported: an array of one or more JWA algorithm identifiers supported by the metadata publisher for validation of signed JWTs submitted to the token endpoint for UDAP workflows. At least one signing algorithm SHALL be supported.

registration_endpoint_jwt_signing_alg_values_supported: an array of one or more JWA algorithm identifiers supported by the metadata publisher for validation of signed software statements, certifications, and endorsements submitted to the registration endpoint. At least one signing algorithm SHALL be supported. It is RECOMMENDED that all Authorization Servers support the “RS256” algorithm.

Some metadata keys or values only apply in the context of certain supported workflows. Metadata publishers SHOULD NOT include keys or values that are inconsistent with its other published metadata values. For example, if an Authorization Server does not support authorization code flow, the authorization endpoint is not used and the authorization_endpoint key SHOULD NOT be included in the metadata and “authorization_code” SHOULD NOT be included as a supported grant type. 

2 Signed endpoints

If the server includes an authorization endpoint, token endpoint, or registration endpoint element its metadata, then it SHOULD also include the signed_endpoints element as a signed JWT containing the following claims:

iss: Server’s unique identifying URI (identifying the holder of the private key, also servers as the base URI for UDAP metadata including lookup of certificates)  
sub: same as iss  
exp: number, expiration time (may be long-lived, e.g. 1 year)  
iat: number, issued at time  
jti: string, unique token identifier used to identify token replay  
authorization_endpoint: URI of authorization endpoint (if included in unsigned metadata)  
token_endpoint: URI of token endpoint (if included in unsigned metadata)  
registration_endpoint: URI of registration endpoint (if included in unsigned metadata)

The JOSE Header for the signed_endpoints JWT contains the following key/value pairs:

alg : "RS256"  
x5c : [cert1, cert2, …] (cert1 is required; remainder of chain is optional)  
x5u : valid URI (optional)

The x5c claim contains the Server’s UDAP certificate chain as an array of one or more elements, each containing a base64 encoded representation of the DER encoded X.509 certificate. The leaf certificate (cert1) contains the public key corresponding to the private signing key used by the Server to digitally sign the signed_endpoints JWT. The JWT is signed and assembled using JWS compact serialization as per RFC 7515.

3 Client validation of signed endpoints

If the server metadata contains the signed_endpoints element, then the client application SHALL validate this metadata element as follows:

3.1 The client app validates the digital signature on the signed_endpoints JWT using the public key extracted from cert1 in the x5c parameter of the JOSE header. If the signature cannot be validated, the request is denied.

3.2 The Client app attempts to construct a valid certificate chain from the Server’s certificate (cert1) to an anchor certificate trusted by the Client app using conventional X.509 chain building techniques and path validation, including certificate validity and revocation status checking. The Server MAY provide a complete certificate chain in the x5c element. The Client app MAY use additional certificates not included by the Server to construct a chain (e.g. from its own certificate cache or discovered via the X.509 AIA mechanism). Client apps SHOULD support the X.509 AIA mechanism for chain building. If a trusted chain cannot be built and validated by the Client app, the signed_endpoints JWT is rejected.

3.3 The Client app validates the iss, sub, exp, iat, and jti values in the signed_endpoints JWT. The iss value MUST match a uriName entry in the Subject Alternative Names extension of the Server’s certificate. Typically, this will be the base URL of the resource server providing the metadata. The sub value MUST match the iss value, and the JWT MUST be unexpired.

3.4 The Client app validates that the endpoint URLs in the unsigned metadata match the values in the signed_endpoints JWT claims. If an endpoint does not match, or an endpoint in the unsigned metadata is not included in the claims, the JWT is rejected.

3.5 If the Client app rejects the signed_endpoints JWT for any reason, the Client app SHOULD NOT proceed, and, if applicable, SHOULD alert the end user that the server’s endpoint metadata could not be validated.

4 Authors

Luis C. Maas III, EMR Direct  
Julie Maas, EMR Direct

5 Notices

Copyright ©2020-2025 UDAP.org and the persons identified as the document authors. All rights reserved.

UDAP.org grants to any interested party a non-exclusive, royalty-free, worldwide right and license to reproduce, publish, distribute and display this Specification, in full and without modification, solely for the purpose of implementing the technology described in this Specification, provided that attribution is made to UDAP.org as the source of the material and that such attribution does not indicate an endorsement by UDAP.org.

All Specifications, and the information contained therein, are provided on an “AS IS” basis and the authors, the organizations they represent, and UDAP.org make no (and hereby expressly disclaim any) warranties, express, implied, or otherwise, including but not limited to any warranty that the use of the information therein will not infringe any rights or any implied warranties of merchantability or fitness for a particular purpose, and the entire risk as to implementing this specification is assumed by the implementer. Additionally, UDAP.org takes no position regarding the validity or scope of any intellectual property or other rights that might be claimed to pertain to the implementation or use of the technology described in this document or the extent to which any license under such rights might or might not be available, nor does it represent that it has made any independent effort to identify any such rights.

 

#### About UDAP

The Unified Data Access Profiles (UDAP™) published by UDAP.org increase confidence in open API transactions through the use of trusted identities and verified attributes. UDAP use cases support standards-based security, privacy and scalable interoperability through reusable identities, leveraging dynamic client registration, JWT-based client authentication and Tiered OAuth.   
  
