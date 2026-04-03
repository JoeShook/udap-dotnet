<!-- Source: https://www.udap.org/udap-tls-client-auth.html -->
<!-- Downloaded: 2026-04-01 -->

# **UDAP Mutual TLS Client Authentication**

**Version STU 1**

Client authentication using TLS has been deployed broadly in the field and provides an opportunity to leverage existing trust communities to help scale the use of APIs in use cases where authentication of client applications is required, such as in cross-organizational queries. OAuth 2.0 is commonly used as an authorization framework for such use cases.

UDAP implements TLS client authentication as an extension to the OAuth 2.0 authorization framework defined in RFC 6749. Use of this extension is requested by Client Apps by transmitting a client certificate during the TLS handshake with the token endpoint. This client authentication protocol can be used with any OAuth 2.0 grant mechanism where a Client App authenticates to the Authorization Server’s token endpoint in order to obtain an access token, including authorization code flow, client credentials flow, or other extension grant flows utilizing the token endpoint.

This protocol is based upon standard mutual TLS session initiation and Public Key Infrastructure tools. Before granting an access token, the Authorization Server validates the digital signature on the certificate used by the Client App during the handshake, and evaluates the trust chain for this certificate. The access token is granted only if the Client App’s certificate is valid and trusted. This protocol MAY be used only by Client Apps that are able to protect the private key corresponding to public key included in the Client App’s X.509 certificate, e.g. confidential clients and certain native device apps.

The use of mutual TLS authentication by the Client App at the authorization endpoint is not part of this protocol. In fact, the user agent connecting to the authorization endpoint would generally not have access to the Client App’s private key. Additionally, although this document describes the presentation and validation of client certificates, it refers to mutual TLS because client authentication is in addition to the server authentication that is already required by RFC 6749.

Note: The HTTP request and response examples presented below are _non-normative_. For readability purposes, line wraps have been added to some HTTP headers and request bodies, some headers have been omitted, and some parameters have not been URL encoded. 

The following steps define the workflow:

1\. The Client App checks that the Authorization Server supports UDAP federation by retrieving the Authorization Server’s UDAP metadata from a well-known URL.

GET /.well-known/udap HTTP/1.1  
Host: as.example.com  
  


Response:

HTTP/1.1 200 OK  
Content-Type: application/json  
  
{   
“x5c” : [“{_cert1_}”, “{_cert2_}”, …]  
}

If the Authorization Server returns an error code, then the Authorization Server does not support the UDAP Mutual TLS client authentication protocol and the Client App should abort this workflow.

2\. The Client App must be registered with the Authorization Server to use TLS client authentication to connect to the token endpoint. If the Authorization Server supports UDAP Dynamic Client Registration, the Client App MAY register with the Authorization Server using that protocol, and request TLS client authentication by including the token_endpoint_auth_method registration parameter with a value of tls_client_auth. If the Authorization Server does not support this dynamic registration protocol, it SHOULD supply another method for Client Apps to register their certificates and obtain a client ID.

3\. The Client App MUST perform any steps required for the grant type it is using before making its request to the Authorization Server’s token endpoint. These steps occur prior to client authentication. For example, when using the authorization code flow, the Client App would first direct the end user to the Authorization Server’s authorization endpoint in order to receive an authorization code via the Client App’s redirection endpoint, as in this example:

GET /authorize?  
response_type=code&  
state=client_random_state&  
client_id=clientIDforResourceHolder&  
scope= resource_scope1+resource_scope2&  
redirect_uri=https://client.example.net/clientredirect HTTP/1.1  
Host: as.example.com  
  


If the end user authorizes the Client App to access the requested resources, the Authorization Server will return an authorization code to the Client App by redirecting the user’s browser to the Client App’s redirection endpoint:

HTTP/1.1 302 Found  
Location: https://client.example.net/clientredirect?  
code=authz_code_from_resource_holder&  
state=client_random_state

4\. The Client App connects to the Authorization Server’s token endpoint and completes the TLS handshake with the Authorization Server. The Client App MUST select a suitable client authentication certificate issued by one of the acceptable issuers identified by the Authorization Server during the handshake.

5\. If the handshake succeeds, the client requests a token from the Authorization Server’s token endpoint. An additional extension parameter “udap” is also included with a string value of “1” to signal to the Authorization Server that version 1 of this protocol is being used. The Client App MUST NOT use HTTP Basic authentication, i.e. an Authorization header MUST NOT appear in the request headers. The client ID MUST be included as a request parameter. Continuing the previous example using the authorization code flow, the Client App also submits the authorization code obtained following user authorization:

POST /token HTTP/1.1  
Host: as.example.com  
Content-type: application/x-www-form-urlencoded  
  
grant_type=authorization_code&  
code=authz_code_from_resource_holder&  
client_id=clientIDforResourceHolder &  
udap=1

If the client is using the client credentials flow, the client will immediately connect to the token endpoint, i.e. the authorization endpoint is not used, as in the following example:

POST /token HTTP/1.1  
Host: as.example.com  
Content-type: application/x-www-form-urlencoded  
  
grant_type=client_credentials&  
client_id=clientIDforResourceHolder &  
udap=1

6\. Authorization Server validates request

6.1 The Authorization Server validates that a client certificate has been presented during the TLS handshake between the Client App and the Authorization Server. The Client MUST present its own certificate during the handshake. If a client authentication certificate has not been presented, then this workflow has not been requested by the Client App.

6.2 The Authorization Server attempts to construct a valid certificate chain from the Client’s certificate presented during the handshake to an anchor certificate trusted by the Authorization Server using conventional X.509 chain building techniques and path validation, including certificate validity and revocation status checking. The Authorization Server MAY use additional certificates not presented by the Client to construct a chain (e.g. from its own certificate cache or discovered via the X.509 AIA mechanism). If a trusted chain cannot be built and validated by the Authorization Server, the request is denied. Note that the Authorization Server MAY perform this trust chain validation during the TLS handshake and MAY terminate the handshake by signaling an appropriate error if trust chain validation fails.

6.3 The Authorization Server validates that the Subject Distinguished Name and Subject Alternative Names listed in the client’s certificate match the values associated with the client_id presented in the token request. The Subject DN and/or SAN values required to establish a successful match MUST be defined in the corresponding trust community’s certificate profile. If this validation fails, the request is denied.

6.4 The Authorization Server validates any other parameters in the request as per the requirements of the grant mechanism identified by the grant_type value. If a parameter is invalid or a required parameter is missing, the request is denied.

7\. Authorization server responds to request

7.1 If the request is approved, the Authorization Server returns a token response as per Section 5.1 of RFC 6749. For example:

HTTP/1.1 200 OK  
Content-Type: application/json  
  
{  
“access_token”:“example_access_token_issued_by_AS”,  
“token_type”:”Bearer”,  
“expires_in”:3600  
}

The Authorization Server MAY also return a refresh_token in its response.

7.2 If the request is denied, the Authorization Server returns an error as per Section 5.2 of RFC 6749. Denials related to trust validation or client validation SHOULD use the “invalid_client” code. Denials related to invalid signatures should use the “invalid_request” code. The Authorization Server MAY include an error_description parameter. For example:

HTTP/1.1 400 Bad Request  
Content-Type: application/json  
  
{  
“error”: “invalid_client”,  
“error_description”:”The submitted authentication token has expired”  
}

8 Alternative workflows using Client TLS authentication directly to Resource Server

8.1 When the identity and privileges of a Client App can be fully determined by a Resource server based on the attributes in a presented client authentication certificate, a Resource Server may elect to support mutual TLS at its resource endpoints, independent of the Authorization Server and OAuth 2.0 flows, as an alternative to client_credentials grants. In such cases, the Resource Server MUST validate the client authentication certificate as per Sections 6.1 and 6.2 prior to fulfilling the resource request. If the Client App’s certificate is invalid or untrusted, or the certificate attributes cannot be matched to an authorized client application, then the Resource Server SHOULD return a 403 error response with an error parameter value of invalid_client.

8.2 A Resource Server MAY also require TLS client authentication in conjunction with a conventional Bearer access token in the HTTP Authorization header as a mechanism to constrain the use of an access token to a specific client. In such cases, the Authorization Server MUST communicate the public key or certificate attributes of the authorized Client App to the Resource Server, and the Resource Server, in addition to validating the client authentication certificate as per Section 8.1, MUST validate that th certificate presented by the Client App during the TLS handshake matches those attributes. The Authorization Server may communicate this information to the Resource Server within the access token itself, e.g. when JWTs are used as access tokens, or via its introspection endpoint. If the information does not match, the Resource Server SHOULD return a 403 error response with an error parameter of invalid_grant. 

8.3 This specification does not restrict how the Authorization Server and/or Resource Server communicate to the Client App that the workflows in 8.1 or 8.2 should be used.

9 References

Cooper, D., et al. “Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile”, RFC 5280, RFC Editor, May 2008.  
Hardt, D., Ed., “The OAuth 2.0 Authorization Framework”, RFC 6749, RFC Editor, October 2012.  
Sheffer, Y., et al. “Recommendations for Secure Use of Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS)”, BCP 195, RFC 7525, RFC Editor, May 2015.

10 Authors

Luis C. Maas III, EMR Direct

11 Notices

Copyright ©2016-2025 UDAP.org and the persons identified as the document authors. All rights reserved.

UDAP.org grants to any interested party a non-exclusive, royalty-free, worldwide right and license to reproduce, publish, distribute and display this Specification, in full and without modification, solely for the purpose of implementing the technology described in this Specification, provided that attribution is made to UDAP.org as the source of the material and that such attribution does not indicate an endorsement by UDAP.org.

All Specifications, and the information contained therein, are provided on an “AS IS” basis and the authors, the organizations they represent, and UDAP.org make no (and hereby expressly disclaim any) warranties, express, implied, or otherwise, including but not limited to any warranty that the use of the information therein will not infringe any rights or any implied warranties of merchantability or fitness for a particular purpose, and the entire risk as to implementing this specification is assumed by the implementer. Additionally, UDAP.org takes no position regarding the validity or scope of any intellectual property or other rights that might be claimed to pertain to the implementation or use of the technology described in this document or the extent to which any license under such rights might or might not be available, nor does it represent that it has made any independent effort to identify any such rights.

 

#### About UDAP

The Unified Data Access Profiles (UDAP™) published by UDAP.org increase confidence in open API transactions through the use of trusted identities and verified attributes. UDAP use cases support standards-based security, privacy and scalable interoperability through reusable identities, leveraging dynamic client registration, JWT-based client authentication and Tiered OAuth.   
  
