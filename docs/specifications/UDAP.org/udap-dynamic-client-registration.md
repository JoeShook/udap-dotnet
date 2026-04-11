<!-- Source: https://www.udap.org/udap-dynamic-client-registration.html -->
<!-- Downloaded: 2026-04-01 -->

# **UDAP Dynamic Client Registration**

**Version STU 1**

Registration with an Authorization Server is typically required before a Client Application can access protected resources using the OAuth 2.0 authorization framework. For larger ecosystems with numerous clients and authorization servers, manual client registration requiring one-off enrollments or pairwise key exchange presents a significant barrier. Such communities can leverage a distributed system of authoritative information through the use of digital certificates to enable a scalable dynamic solution to client registration, allowing real-time trust assessment, validation of identifying attributes, and support for revocation of certificates.

UDAP implements dynamic client registration using digital certificates as an extension to the OAuth 2.0 dynamic client registration protocol defined in RFC 7591. Use of this extension is requested by Client Apps by including a digitally signed software statement in their requests to the registration endpoint, where the signature is backed by an X.509 certificate. This framework also allows Client Apps to submit digitally signed certifications and endorsements provided by third parties as part of their registration request, either of which can be independently validated by the Authorization Server prior to allowing the registration of a Client App.

This protocol is based upon standard Public Key Infrastructure tools. Before granting registration, the Authorization Server validates the digital signature on the software statement submitted by the Client App, and evaluates the trust chain for the Client App’s certificate. Client registration is permitted only if the software statement is valid and the Client App’s certificate is trusted. This protocol MAY be used only by Client Apps that are able to protect the private key used to sign software statements, e.g. confidential clients and certain native device apps.

Note: The HTTP request and response examples presented below are _non-normative_. For readability purposes, line wraps have been added to some HTTP headers and request bodies, some headers have been omitted, and some parameters have not been URL encoded. 

Sections 1 through 5 define the steps of the workflow. Section 6 defines how previous registrations may be modified or cancelled.

1\. The Client App checks that the Authorization Server supports UDAP by retrieving the Authorization Server’s UDAP metadata from a well-known URL.

GET /.well-known/udap HTTP/1.1  
Host: resourceholder.example.com  
  


Response:

HTTP/1.1 200 OK  
Content-Type: application/json  
  
{   
"x5c" : ["{_cert1_}", "{_cert2_}", …]  
}

If the Authorization Server returns an error code, then the Authorization Server does not support UDAP Dynamic Client Registration and the Client App should abort this workflow.

2\. The Client App prepares a software statement for submission. The software statement serves three purposes: it provides the necessary metadata for registration, it establishes the Client App’s control of a private key, and it provides the digital certificate needed to validate the signature and establish trust. 

The software statement is a signed JWT containing the following claims:

iss: Client App Operator’s unique identifying URI (identifying the holder of private key, also serves as the base URI for UDAP metadata including lookup of certificates)  
sub: same as iss   
aud: string, the Authorization Server’s registration endpoint URL  
exp: number, expiration time (should be short-lived, max 5 minutes from iat)  
iat: number, issued at time  
jti: string, unique token identifier used to identify token replay  
client_name: string  
redirect_uris: array of URIs (required if grant_types includes authorization_code)  
grant_types: array of strings, e.g. authorization_code, refresh_token, client_credentials  
response_types: array of strings, e.g. code (omit for client_credentials)  
token_endpoint_auth_method: string, fixed value: private_key_jwt  
scope: string, space delimited list of requested scopes (optional)  
  
The Client MAY also include other optional parameters from section 2 of RFC 7591.

The JOSE Header for the software statement contains the following key/value pairs:

alg : "RS256"  
x5c : [cert1, cert2, …] (cert1 is required; remainder of chain is optional)  
x5u : valid URI (optional)

The x5c claim contains the Client App’s certificate chain as an array of one or more elements, each containing a base64 encoded representation of the DER encoded X.509 certificate. The leaf certificate (cert1) contains the public key corresponding to the private signing key used by the Client App to digitally sign the software statement. The software statement is signed and assembled using JWS compact serialization as per RFC 7515.

3\. The client requests registration by submitting the signed software statement to the Authorization Server’s registration endpoint. The additional extension parameter “udap” is also included with a string value of “1” to signal to the Authorization Server that version 1 of this protocol is being used, and that the included software statement conforms to this profile. Optionally, the Client App MAY submit certifications or endorsements provided by third parties by including the optional extension parameter “certifications” with a value of an array of one or more signed JWTs, each representing a separate certification or endorsement:

POST /register HTTP/1.1  
Host: as.example.com  
Content-type: application/json  
  
{  
"software_statement" : "{_signed software statement_}",  
"certifications" : [_array of one or more signed JWTs_],  
"udap" : "1"  
}

The client SHOULD include all requested registration parameters in the signed software statement, i.e. additional registration parameters SHOULD NOT appear at the top level of the submitted JSON object. If the client does include the same registration parameter twice, once at the top level and again in the signed software statement, then the Authorization Server MUST ignore the parameter included at the top level and process only the parameter included in the software statement. 

4\. Authorization Server validates request

4.1 The Authorization Server validates the digital signature on the software statement using the public key extracted from cert1 in the x5c parameter of the JOSE header. If the signature cannot be validated, the request is denied.

4.2 The Authorization Server attempts to construct a valid certificate chain from the Client’s certificate (cert1) to an anchor certificate trusted by the Authorization Server using conventional X.509 chain building techniques and path validation, including certificate validity and revocation status checking. The Client MAY submit a complete certificate chain in its request. The Authorization Server MAY use additional certificates not included by the Client to construct a chain (e.g. from its own certificate cache or discovered via the X.509 AIA mechanism). Authorization Servers SHOULD support the X.509 AIA mechanism for chain building. If a trusted chain cannot be built and validated by the Authorization Server, the request is denied.

4.3 The Authorization Server validates the iss, sub, aud, exp, iat, and jti values in the software statement. The iss value MUST match a uriName entry in the Subject Alternative Names extension of the Client’s certificate. The sub value MUST match the iss value. The aud value MUST contain the Authorization Server’s registration endpoint URL, and the software statement MUST be unexpired. A maximum software statement lifetime of 5 minutes is RECOMMENDED. The Authorization Server MAY deny a request if the same software statement (as determined by the jti value) has been used in a previous registration request.

4.4 The Authorization Server validates the registration parameters in the software statement. If a parameter is invalid or a required parameter is missing, the request is denied.

4.5 If there has been a previous registration granted by the Authorization Server linked to the public key submitted by the Client for the requested grant type, the Authorization Server MAY cancel the previous registration. See section 6 for additional details.

5\. Authorization Server responds to request

5.1 If the request is granted, the Authorization Server returns a registration response as per Section 3.2.1 of RFC 7591. The top-level elements of the response SHALL include the client_id issued by the Authorization Server for use by the Client App, the software statement as submitted by the Client App, and all of the registration related parameters that were included in the software statement:

HTTP/1.1 201 Created  
Content-Type: application/json  
  
{  
"client_id": "example_client_id_issued_by_AS",  
"software_statement": "{_the software statement as submitted by the client_}",   
"client_name": string,  
"redirect_uris": [_array of URIs_],  
"grant_types": ["authorization_code"],  
"response_types": ["code"],  
"token_endpoint_auth_method": "private_key_jwt"  
}

In addition, the Authorization Server MUST store the certificate provided by the Client for use to validate subsequent client authentication attempts.

5.2 If the request is denied, the Authorization Server returns an error as per Section 3.2.2 of RFC 7591. Denials related to trust validation SHOULD use the “unapproved_software_statement” code. Denials related to invalid signatures SHOULD use the “invalid_software_statement” code. The Authorization Server MAY include an error_description parameter. For example:

HTTP/1.1 400 Bad Request  
Content-Type: application/json  
  
{  
"error": "unapproved_software_statement"  
}

Note: if the Client App receives an error code from the Authorization Server, then the Client App MAY attempt registration again by generating a new software statement specifying a different client certificate. For example, if the Client App has been issued two certificates corresponding to two trust communities, it MAY attempt registration using the second certificate if the registration using the first certificate is denied. The Client App SHOULD NOT attempt registration again with the same certificate if an unapproved_software_statement error is returned.

6 Modifying or Cancelling previous registrations 

The client URI in the Subject Alternative Name of an X.509 certificate and in the 'iss' field of the software statement uniquely identifies a single application and its operator over time. Thus, a Client App operator MAY request a modification or cancellation of its previous registration with an Authorization Server by submitting another registration request using the same 'iss' value, as discussed below. The Authorization Server SHALL validate such requests in the same manner as a new registration request, following the procedure defined in Section 4 above. Note that registration modification or cancellation requests may not always include the same client certificate as previous registration requests by the same Client App operator, such as in the case of a renewal or re-key of the previous certificate, however the client URI will be the same.

To modify a previous registration, the Client App operator SHALL submit a valid registration request with a software statement containing the same 'iss' value as an earlier registration but with a different set of claims or claim values, or with a different (possibly empty) set of optional certifications and endorsements. The server SHALL treat this as a request to replace all information from the previous registration request with the information included in the new request. For example, a Client App operator may use this mechanism to update a redirection URI or to add, remove, or update a certification or endorsement. If the registration modification request is accepted, the Authorization Server SHALL return a registration response as per Section 5.1, reflecting the updated registration parameters. The response SHOULD include the same client_id as the previous registration response. If the Authorization Server returns a different client_id, it SHALL cancel the registration associated with the previous client_id, and the client application SHALL use only the new client_id in subsequent transactions with the Authorization Server.

To cancel a previous registration, the Client App operator SHALL submit a valid registration request with a software statement containing the same 'iss' value as an earlier registration but with an empty grant_types array. The server SHOULD treat this as a request to cancel the previous registration. A client application SHALL interpret a registration response that contains an empty grant_types array as a confirmation that the registration for the client_id listed in the response has been cancelled by the Authorization Server.

The Authorization Server SHOULD return an HTTP 200 response code (instead of a 201 response code) for successful registration modification and cancellation requests.

7 References

Cooper, D., et al. “Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile”, RFC 5280, RFC Editor, May 2008.  
Hardt, D., Ed., “The OAuth 2.0 Authorization Framework”, RFC 6749, RFC Editor, October 2012.  
Jones, M., et al, “JSON Web Token (JWT)”, RFC 7519, RFC Editor, May 2015.  
Richer, J., Ed., “OAuth 2.0 Dynamic Client Registration Protocol”, RFC 7591, RFC Editor, July 2015.

8 Authors

Luis C. Maas III, EMR Direct

9 Acknowledgements

The author would like to thank the following individuals for their valuable feedback during the development of this document: Julie Maas and Grahame Grieve.

10 Notices

Copyright ©2016-2025 UDAP.org and the persons identified as the document authors. All rights reserved.

UDAP.org grants to any interested party a non-exclusive, royalty-free, worldwide right and license to reproduce, publish, distribute and display this Specification, in full and without modification, solely for the purpose of implementing the technology described in this Specification, provided that attribution is made to UDAP.org as the source of the material and that such attribution does not indicate an endorsement by UDAP.org.

All Specifications, and the information contained therein, are provided on an “AS IS” basis and the authors, the organizations they represent, and UDAP.org make no (and hereby expressly disclaim any) warranties, express, implied, or otherwise, including but not limited to any warranty that the use of the information therein will not infringe any rights or any implied warranties of merchantability or fitness for a particular purpose, and the entire risk as to implementing this specification is assumed by the implementer. Additionally, UDAP.org takes no position regarding the validity or scope of any intellectual property or other rights that might be claimed to pertain to the implementation or use of the technology described in this document or the extent to which any license under such rights might or might not be available, nor does it represent that it has made any independent effort to identify any such rights.

 

 

#### About UDAP

The Unified Data Access Profiles (UDAP™) published by UDAP.org increase confidence in open API transactions through the use of trusted identities and verified attributes. UDAP use cases support standards-based security, privacy and scalable interoperability through reusable identities, leveraging dynamic client registration, JWT-based client authentication and Tiered OAuth.   
  
