<!-- Source: https://www.udap.org/udap-certifications-and-endorsements.html -->
<!-- Downloaded: 2026-04-01 -->

# **UDAP Certifications and Endorsements for Client Applications**

**Version STU 1**

UDAP supports portable electronic client certifications that can be used by a Certifier to express verified attributes about a client application developer or a specific client application. A Certification can also be used to express an endorsement of a client application developer or application. Certifications can be signed by third parties that certify or endorse developers or applications, or signed by the developer of a client application to self-declare conformance to a set of published criteria.

A client application developer can provide one or more certifications to an OAuth Server when registering its client application. This includes both manual and dynamic client registration processes. The OAuth Server can use the information in the certifications to determine whether or not to accept a client registration request. For authorization flows that interact with client app end users, the OAuth Server can also use the information in the certifications to inform the end user about the client.

Certifications are constructed as signed JWTs. These JWTs allow authentication of a Certifier using standard PKIX tools. Before accepting a certification, the Authorization Server validates the digital signature on the certification, and evaluates the trust chain for the Certifier’s X.509 certificate used to perform this validation. The certification is accepted only if the certification is valid and the Certifier’s certificate is trusted.

The following steps define the workflow for a Certifier to generate a signed certification JWT:

1\. The Certifier prepares a certification for submission. The certification serves three purposes: it provides the necessary metadata for registration, it establishes the Certifier’s control of a private key, and it provides the digital certificate needed to validate the signature on a certification and establish trust. The certification is a signed JWT containing the following claims:

iss |  string, Certifier’s unique identifying URI  
---|---  
sub |  string, client’s unique identifying URI (binds to SAN:uniformResourceIdentifier in Client App certificate). For self-signed certifications, this is the same as the iss value.  
aud |  string, registration endpoint URL of Authorization Server (optional, single valued or array). If absent, this certification is intended for all audiences.  
exp |  number, expiration time (max 3 years, must not expire after certificate)  
iat |  number, issued at time  
jti |  string, token identifier that uniquely identifies this JWT until the expiration time  
certification_issuer |  string; the entity that operates the certification program (required if certification is not self-signed, omit if self-signed)  
certification_name |  string; short name for certification (required)  
certification_logo |  string (optional); URL pointing to logo for this certification, e.g. seal  
certification_description |  string; longer description of what this certification entails (optional)  
certification_uris |  array of strings; each URI identifies a certification program or set of criteria. This should be a resolvable URL where more information can be obtained. (optional; required if certification is self-signed)  
certification_status_endpoint |  string (optional); URL of status endpoint operated by the Certifier (see section 8); omit if self-signed  
is_endorsement |  boolean (optional, default: false); true if this certification represents an endorsement of the Client App by the issuer.  
developer_name |  string (optional)  
developer_address |  JSON object, as per OIDC Core 1.0 Section 5.1.1  
client_name |  string, as per RFC 7591  
software_id |  string, as per RFC 7591 (recommended)  
software_version |  string, as per RFC 7591 (optional)  
client_uri |  string, as per RFC 7591  
logo_uri |  string, as per RFC 7591  
tos_uri |  string, as per RFC 7591  
policy_uri |  string, as per RFC 7591  
contacts |  array of strings, as per RFC 7591, further constrained as follows: each array element MUST be a valid URI with mailto or https scheme so that AS operator can contact client app developer  
launch_uri |  string, for SMART app launch with EHR launch flow, requires scope includes launch  
redirect_uris |  array of strings, as per RFC 7591, except as noted; an array of fully specified redirection URIs for the client (conditional). MUST be absent if grant_types = client_credentials. Note: To support the RFC 8252 requirement that a native mobile app use a different redirection URI for every Authorization Server, the Certifier may include the special character * in the URI as a wildcard for a single path component or query parameter value, e.g. https://app.example.com/redirect/* or https://app.example.com/redirect?server=*. For URIs that contain literal asterisk characters, these characters should be URL-encoded as “%2A”; the Authorization Server MUST NOT interpret such a URL-encoded asterisk as a wildcard symbol. For a given Authorization Server, the client MUST register one or more complete redirection URIs with the Authorization Server that match this pattern; each registered redirect_uri MUST be fully specified and MUST NOT contain any wildcard symbols, even if the certification includes a wildcard symbol.  
ip_allowed |  array of strings of the form ip, ip1-ip2, or ip/CIDR (optional); origin IP to connect to token endpoint, e.g. ["198.51.100.0/24", "203.0.113.55"]  
grant_types |  array of strings, as per RFC 7591; e.g. authorization_code, refresh_token, client_credentials (optional)  
response_types |  array of strings, as per RFC 7591; code (omit for client_credentials) (optional)  
scope |  string containing space separate list of permitted scopes, as per RFC 7591; optional  
token_endpoint_auth_method |  string, as per RFC 7591 (optional); RFC 7591 defines the values: none, client_secret_post, and client_secret_basic. The additional value private_key_jwt may also be used.  
jwks |  string, as per RFC 7591 (optional); locks this certification to a specific client key or keys. Note that jwks_uri MUST NOT be used. The client must prove possession of this key during registration and during authentication. To facilitate key rollover, binding using the sub claim URI is preferable to binding to a specific key.  
  
 

Inclusion of one or more of the optional client application parameters indicates that the Certifier wishes to limit this certification to the Client app for certain software ID and/or version, certain redirection URIs, grant types, response types, and/or endpoint authorization methods. When the restriction parameter is an array, a client registration requesting a subset of the array values would also be permitted. For example if the grant_types array in a certification contains two grant types, a Client App registration requesting only one of those grant types would also match the restrictions of that certification.

2\. The JOSE Header for the certification contains the following key/value pairs:

{  
"alg" : "rs256",  
"x5c" : [cert1, cert2, …], (cert1 is required; remainder of chain is optional)  
"x5u" : valid URI (optional)  
}

The x5c claim contains the Certifier’s certificate chain as an array of one or more elements, each containing a Base64 encoded representation of the DER encoded X.509 certificate. The leaf certificate (cert1) contains the public key corresponding to the private signing key used by the Certifier to digitally sign the certification. 

The certification is signed and assembled using JWS compact serialization as per RFC 7515.

3\. Example Third Party App Certification. Certain information about the example app and its developer has been validated by a third party:

{  
"iss": "http://identityprovider.example.org/certifications",  
"sub": "http://appdeveloper.example.com/apps/superapp/v1",  
"exp": 1562961473,  
"iat": 1531425447,  
"jti": "C0hlwc7r+3/t0qoK1G4G/B0hsyE7xR4PGiRfWQBZXY7e",  
"certification_issuer": "Some Sample Verification Company",  
"certification_name": "ID Validated Developer - Silver",  
"certification_logo": "https://identityprovider.example.org/images/id-verified.jpg",  
"certification_description": "The identity of the app developer has been verified at the Silver level. ",  
"certification_uris": ["https://acme.example.org/programs/id-verify"],  
"certification_status_endpoint": "https://identityprovider.example.org/status",  
"is_endorsement": false,  
"developer_name": "AppDeveloper Company",  
"client_name": "SuperApp v.1",  
"redirect_uris": ["https://appdeveloper.example.com/apps/superapp/redirect"],  
"grant_types": ["authorization_code"],  
"response_types": ["code"]  
}

In this example, the issuer is limiting this certification to the setting where the Client App requests registration using the client app parameters listed in the final four elements of the JWT.

4\. Example Declaration of Conformance by an app developer. The app developer is declaring conformance of its app to a set of published security and privacy criteria:

{  
"iss": "http://appdeveloper.example.com/apps/superapp/v1",  
"sub": "http://appdeveloper.example.com/apps/superapp/v1",  
"exp": 1562961584,  
"iat": 1531425558,  
"jti": "0hsyE7xR4PGiRfWQBZXY7e C0hlwc7r+3/t0qoK1G4G/S",  
"certification_name": "ABCD Application Security & Privacy Self-Declaration",  
"certification_uris": ["https://abcd.example.org/criteria/security-2019.1",  
"https://abcd.example.org/criteria/privacy-2019.1"],  
"policy_uri": "https://appdeveloper.example.com/privacy-policy.html",  
"contacts": ["mailto:support@example.com"],  
"grant_types": ["authorization_code"]  
}

In this example, the developer is limiting its declaration of conformance to the workflow where its app uses the authorization code flow to obtain access. In this example, the criteria are published by a different example organization (ABCD) that has established a certification program intended for this purpose. These criteria could take the form of simple checklists, or more complex self-assessments. The publisher of the criteria SHOULD define the specific conditions under which an app developer can assert a particular certification URI, e.g. minimum requirements or percent of criteria met, other parameters that must be included such as policy_uri, developer contact email address, etc.

5\. Example Third Party “Endorsement” Certification. This example app has earned the “ACME Seal of Approval” certification and is endorsed by ACME for use by its members:

{  
"iss": "http://acme.example.org/certifications",  
"sub": "http://appdeveloper.example.com/apps/superapp/v1",  
"exp": 1562961473,  
"iat": 1531425447,  
"jti": "mQtC0hlwc7r+3/t0qoK1G4G/B0hsyE7xR4PGiRfWQBZX",  
"certification_issuer": "ACME",  
"certification_name": "Seal of Approval",  
"certification_logo": "https://acme.example.org/images/seal-of-approval.jpg",  
"certification_description": "ACME has evaluated this software and recommends it use by its members.",  
"certification_uris": ["https://acme.example.org/programs/acme-certification"],  
"is_endorsement": true,  
"client_name": "AppDeveloper SuperApp v.1",  
"redirect_uris": ["https://appdeveloper.example.com/apps/redirect"],  
"grant_types": ["authorization_code", "refresh_token"],  
"response_types": ["code"]  
}

In this example, the issuer is limiting this endorsement to the setting where the Client App requests registration using the client app parameters listed in the final four elements of the JWT.

6\. Processing of Certifications and Endorsements

This section describes the processing of certifications and endorsements submitted by a Client App as part of a dynamic registration request, such as with the UDAP Dynamic Client Registration profile. For each certification object included by the client in the certifications array of the registration request, the Authorization Server SHALL validate each certification as per steps 1-5 of the following procedure. If a certification is rejected for any of the reasons listed below, the Authorization server MAY continue processing any remaining certifications or MAY deny the registration request.

6.1 For each certification, the Authorization server first validates the digital signature for the certification using the public key extracted from cert1 in the x5c parameter of the JOSE header of that certification. Note that cert1 is the certificate issued to the Certifier. If the signature for the certification cannot be validated, the certification is rejected.

6.2 The Authorization Server MAY evaluate the certification_uris array to determine if the certification is acceptable. How the Authorization Server determines which certification_uris are acceptable is a matter of local policy. For example, the Authorization Server may choose to accept all certifications from a given certification Certifier, accept only certifications from Certifiers with certificates issued from a set of trusted certificate issuers, or accept only those certifications that include a specific URI in the certification_uris array. If the certification is not acceptable, the certification is rejected.

6.3 The Authorization Server validates the iss, sub, aud, exp, iat, and jti values in the certification. The iss value MUST match a uriName entry in the Subject Alternative Names extension of the Certifier’s certificate. The sub value MUST match the Client’s identifying URI submitted by the Client in the registration request. The aud value, if present, MUST contain the Authorization Server’s registration endpoint URL, and the certification MUST be unexpired. A maximum certification lifetime of 3 years is RECOMMENDED. If these parameters cannot be validated by the Authorization Server, the certification is rejected.

6.4 The Authorization Server attempts to construct a valid certificate chain from the Certifier’s certificate (cert1) to an anchor certificate trusted by the Authorization Server using standard X.509 chain building techniques and path validation as defined in RFC 5280, including certificate validity and revocation status checking. To assist the Authorization Server, the Certifier MAY submit a complete certificate chain in the x5c parameter of the JOSE header of the certification. The Authorization Server MAY use additional certificates that were not included by the Certifier to construct a trusted chain (e.g. from its own certificate cache or discovered via the X.509 AIA mechanism). If a trusted chain cannot be built and validated by the Authorization Server, the certification is rejected.

6.5 The Authorization Server validates that the registration parameters requested by the Client in the registration request match the registration parameters included in the certification. If the certification includes a registration parameter, and the registration parameters requested by the Client do not match the values in the certification, the certification is rejected.

6.6 After processing of all certifications is completed, the Authorization server MAY reject the registration request if one or more of the requested registration parameters has not been included in at least one accepted certification.

6.7 If the registration request is granted, the Authorization Server MUST include a certifications parameter in the response with a value of an array containing the accepted certifications. Certifications that were rejected MUST NOT be included in this array.

6.8 If the registration request is denied because one or more certifications was rejected, the Authorization Server MUST return an appropriate error code in the registration response as per section 3.2.2 RFC 7591\. Rejections related to trust validation SHOULD use the code “unapproved_certification”. Rejections related to invalid signatures SHOULD use the code “invalid_certification”. The Authorization server MAY include an error_description parameter.

7 Inclusion in Dynamic Client Registration requests

Clients can submit one or more certifications in a Dynamic Client Registration request as per RFC 7591 by including the extension parameter “certifications” in the registration request with its value equal to an array of certification JWTs, and the extension parameter “udap” with a value of “1”.

8 Revocation of Certifications

An issuer of certifications MAY support status checking of certification by relying parties. The Certifier indicates this support by enabling a status endpoint and including the URL of this endpoint in the certification_status_endpoint parameter. If this parameter is included, the Certifier MUST respond to status requests submitted to this endpoint. The endpoint MUST be TLS protected. To request the status of a certification, the relying party makes an HTTP GET request to the endpoint and includes the URL-encoded value of the “jti” parameter and the value of the “exp” parameter included in the certification. To reduce unnecessary traffic, the relying party SHOULD NOT request the status of certifications that are expired, untrusted, or otherwise unacceptable to the relying party.

For example, to request the status of the sample certification shown in Section 3 of this document, a relying party would make the following request:

GET /status?jti=C0hlwc7r%2B3%2Ft0qoK1G4G%2FB0hsyE7xR4PGiRfWQBZXY7e&exp=1562961473 HTTP/1.1  
Host: identityprovider.example.org  
  


The Certifier MUST return a JSON object with a single key of “valid” and a boolean value. The value of true MUST be returned if and only if the Certifier issued a certification matching the jti and exp values submitted and the Certifier has determined the certification is still valid. If the certification has been revoked, has expired, or is deemed unacceptable or invalid by the issuer for any other reason, a value of FALSE must be returned. If the certification status endpoint is unreachable or an error code is returned, the relying party MUST NOT assume that the certification is still acceptable.

Example response indicating that the certification is still acceptable:

HTTP/1.1 200 OK  
Content-Type: application/json  
  
{ "valid": true }  
  


9 References

Denniss, W., Bradley, J., “OAuth 2.0 for Native Apps”, BCP 212, RFC 8252, RFC Editor, October 2017.  
Hardt, D., Ed., “The OAuth 2.0 Authorization Framework”, RFC 6749, RFC Editor, October 2012.  
Jones, M., et al., “JSON Web Signature (JWS)”, RFC 7515, RFC Editor, May 2015.  
Jones, M., et al., “JSON Web Token (JWT)”, RFC 7519, RFC Editor, May 2015.  
Richer, J., Ed., “OAuth 2.0 Dynamic Client Registration Protocol”, RFC 7591, RFC Editor, July 2015.  
Sakimura, N, et al. “OpenID Connect Core 1.0 incorporating errata set 1”, The OpenID Foundation, November 2014.

10 Authors

Luis C. Maas III, EMR Direct  
Julie Maas, EMR Direct

11 Acknowledgements

The authors would like to thank the following individuals for their valuable feedback during the development of this document: Mark Scrimshire, Alan Viars, and David Gage.

12 Notices

Copyright ©2016-2025 UDAP.org and the persons identified as the document authors. All rights reserved.

UDAP.org grants to any interested party a non-exclusive, royalty-free, worldwide right and license to reproduce, publish, distribute and display this Specification, in full and without modification, solely for the purpose of implementing the technology described in this Specification, provided that attribution is made to UDAP.org as the source of the material and that such attribution does not indicate an endorsement by UDAP.org.

All Specifications, and the information contained therein, are provided on an “AS IS” basis and the authors, the organizations they represent, and UDAP.org make no (and hereby expressly disclaim any) warranties, express, implied, or otherwise, including but not limited to any warranty that the use of the information therein will not infringe any rights or any implied warranties of merchantability or fitness for a particular purpose, and the entire risk as to implementing this specification is assumed by the implementer. Additionally, UDAP.org takes no position regarding the validity or scope of any intellectual property or other rights that might be claimed to pertain to the implementation or use of the technology described in this document or the extent to which any license under such rights might or might not be available, nor does it represent that it has made any independent effort to identify any such rights.

 

 

#### About UDAP

The Unified Data Access Profiles (UDAP™) published by UDAP.org increase confidence in open API transactions through the use of trusted identities and verified attributes. UDAP use cases support standards-based security, privacy and scalable interoperability through reusable identities, leveraging dynamic client registration, JWT-based client authentication and Tiered OAuth.   
  
