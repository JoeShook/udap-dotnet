<!-- Source: https://www.udap.org/udap-user-auth.html -->
<!-- Downloaded: 2026-04-01 -->

# **UDAP Tiered OAuth for User Authentication**

**Version STU 1**

Growing use of open APIs has resulted in demand for richer authentication options, such that Resource Holders can leverage a trusted network of Identity Providers to authenticate users and obtain information about them in order to make an authorization decision. This distributed framework allows the reuse of existing user credentials and improves security by providing user data directly to the Resource Holder rather than passing it through a third party such as a client application. 

UDAP Tiered OAuth for User Authentication implements user authentication as an extension to the OAuth 2.0 authorization and OpenID Connect authentication processes. Use of this extension is requested by Client Apps and Resource Holders by including the “udap” scope in their requests to the upstream authorization endpoint.

This protocol implements tiered authorization and authentication requests. First the Client App requests authorization (and possibly authentication) from the Resource Holder’s Authorization Server, then the Resource Holder requests user authentication from a trusted upstream Identity Provider (IdP). The Resource Holder evaluates the authentication response and, optionally, additional user details obtained from the IdP before responding to the Client App’s authorization request. Because the Resource Holder obtains the user data directly from the IdP that has authenticated the user instead of from the Client App or other third party, the risk of information leakage or assertion substitution is substantially reduced.

Note: The HTTP request and response examples presented below are _non-normative_. For readability purposes, line wraps have been added to some HTTP headers and request bodies, some headers have been omitted, and some parameters have not been URL encoded. 

The following steps define the workflow:

1\. The Client App checks that the Resource Holder supports UDAP by retrieving the Resource Holder’s UDAP metadata from a well-known URL.

GET /.well-known/udap HTTP/1.1  
Host: resourceholder.example.com  
  


Response:

HTTP/1.1 200 OK  
Content-Type: application/json  
  
{   
"x5c" : ["{_cert1_}", "{_cert2_}", …]  
}

If the Resource Holder’s server returns an error code, then the Resource Holder does not support UDAP Tiered OAuth for User Authentication and the Client App should abort this workflow.

2\. The Client App directs the user’s browser to the Resource Holder’s authorization endpoint, including as a “hint” the preferred IdP’s URI as the value of the idp parameter of the request. The Client App also includes the scope “udap” in its request to signal to the Resource Holder that UDAP Tiered OAuth for User Authentication is being requested. If this scope is omitted, the behavior of the Resource Holder is unspecified and the UDAP Tiered OAuth for User Authentication workflow defined in this document might not be supported. It is assumed that the Client App has previously registered with the Resource Holder and possesses a client_id issued by the Resource Holder. If not, the Client App MAY first attempt to register with the Resource Holder’s Authorization Server using UDAP Dynamic Client Registration or another registration method. 

The client MAY use either the authorization code or implicit grant flow (if implicit flow is supported by the Resource Holder). The authorization code grant flow is used for this example:

GET /authorize?  
response_type=code&  
state=client_random_state&  
client_id=clientIDforResourceHolder&  
scope=udap+resource_scope1+resource_scope2&  
idp=https://idp.example.com/optionalpath&  
redirect_uri=https://client.example.net/clientredirect HTTP/1.1  
Host: resourceholder.example.com  
  


3\. Resource Holder interaction with IdP

3.1 The Resource Holder determines if the IdP is trusted or not trusted by retrieving the IdP’s UDAP metadata from https://idp.example.com/optionalpath/.well-known/udap and evaluating the IdP’s certificate against the Resource Holder’s local trust policies.

3.2 If the Resource Holder trusts the IdP and does not have a client_id for use with the IdP, then the Resource Holder SHOULD attempt dynamic client registration as a confidential client as per UDAP Dynamic Client Registration.

3.3 If the Resource Holder does not trust the IdP or cannot obtain a client_id for use with the IdP, then the Resource Holder MAY attempt to authenticate the user with a different IdP. The Resource Holder MAY interact with the user to determine a suitable alternative, such as providing a list of alternative IdP’s to the user. To proceed with a different IdP, the Resource Holder returns to step 3.1 above for the new IdP. Otherwise, the Resource Holder terminates this workflow by redirecting the user’s browser to the Client App’s redirection URI with an error code of “invalid_idp” as per standard OAuth 2.0 error flow, as in this example for a Client using the authorization code flow:

HTTP/1.1 302 Found  
Location: https://client.example.net/clientredirect?  
error=invalid_idp&  
state=client_random_state

Note: if the Client App receives such an error code from the Resource Holder, then the Client App MAY attempt to obtain authorization again by specifying a different IdP.

3.4 If the Resource Holder trusts the IdP and has successfully obtained a client_id from the IdP, then the Resource Holder requests authentication of the user and authorization to access the user’s identity data from the IdP by redirecting the user to the IdP’s authorization endpoint. The Resource Holder’s Authorization Server MAY interact with the user before initiating the redirection, e.g. to inform the user that they will be redirected to the IdP for the purpose of authentication.

Note that the Resource Holder is acting as a client application when interacting with the IdP. In this tiered relationship, the original Client Application does not interact directly with the IdP. The Resource Holder includes the scopes “openid” and “udap” in its request to signal to the IdP that UDAP Tiered OAuth for User Authentication is being requested. If this scope is omitted, the behavior of the IdP is entirely unspecified and the IdP SHOULD NOT proceed with the UDAP Tiered OAuth for User Authentication workflow. The Resource Holder MUST use the authorization code flow when redirecting the user to the IdP’s authorization endpoint (even if the Client App requested a different grant type when connecting to the Resource Holder’s authorization endpoint):

HTTP/1.1 302 Found  
Location: https://idp.example.com/optionalpath/authorize?  
response_type=code&  
state=resource_holder_random_state&  
client_id=resourceHolderClientIDforIdP&  
scope=openid+udap&  
nonce=resource_holder_nonce&  
redirect_uri=https://resourceholder.example.net/redirect HTTP/1.1

The use of the nonce parameter is RECOMMENDED. The Resource Holder MUST generate its own random value for the state parameter and MUST NOT reuse the value provided by the Client App in Step 2. Note: if the Resource Holder interacts with the user prior to the redirection to the IdP, then the Resource Holder MAY alternatively cause the user’s browser to be directed to the IdP’s authorization endpoint as the result of clicking on a hyperlink or other user action that results in the browser generating a new GET request rather than using the 302 redirection method described above.

4\. IdP interaction with the user

4.1 The IdP interacts with the user to authenticate the user, if not already logged in, and confirms the user’s authorization to provide the user’s identity or other information to the Resource Holder, if such authorization is needed, following the standard OpenID Connect user authentication process. If successful, the IdP returns an authorization code to the Resource Holder via the redirect URI, e.g.:

HTTP/1.1 302 Found  
Location: https://resourceholder.example.net/redirect?  
code=authz_code_from_idp&  
state=resource_holder_random_state

The Resource Holder MUST validate that the value of the state parameter in the query string matches the value generated in Step 3.4. If it does NOT match, the Resource Holder MUST terminate this workflow by redirecting the user’s browser to the Client App’s redirection URI with an error code of “server_error” as per standard OAuth 2.0 error flow.

4.2 If the IdP cannot authenticate the user, or the user does not authorize the IdP to share the user’s authentication status with the Resource Holder, or another error condition occurs, then the IdP signals an error to the Resource Holder by redirecting the user’s browser to the Resource Holder’s redirection URI with an appropriate error code as per standard OAuth 2.0 flow, e.g.:

HTTP/1.1 302 Found  
Location: https://resourceholder.example.net/redirect?  
error=access_denied&  
state=resource_holder_random_state

If the Resource Holder receives such an error response from the IdP, the Resource Holder MUST first validate the value of the state parameter as described in Step 4.1. If the state value is valid, the Resource Holder MUST terminate this workflow by redirecting the user’s browser to the Client App’s redirection URI with an error code of “access_denied” as per standard OAuth 2.0 error flow, as in this example for a Client App using the authorization code flow:

HTTP/1.1 302 Found  
Location: https://client.example.com/redirect?  
error=access_denied&  
state=client_random_state

The Client App MUST validate the value of the state parameter returned by the Resource Holder as per RFC 6749.

4.3 If the Resource Holder receives an authorization code from the IdP and the state value is valid, the Resource Holder then connects to the IDP’s token endpoint on the back-end to retrieve an ID token and access token for use with the IdP’s UserInfo endpoint. The Resource Holder MUST authenticate to the IdP’s token endpoint as detailed in Section 5 of UDAP JWT-based Client Authentication:

POST /optionalpath/token HTTP/1.1  
Host: idp.example.com  
Content-type: application/x-www-form-urlencoded  
  
grant_type=authorization_code&  
code=authz_code_from_idp &  
client_assertion_type=urn:ietf:params:oauth:grant-type:jwt-bearer&  
client_assertion=eyJh[…remainder of AnT omitted for brevity…]&  
udap=1

Example Response:

HTTP/1.1 200 OK  
Content-Type: application/json  
  
{   
"access_token": "tokenForResourceHolder",  
"token_type": "Bearer",  
"expires_in": 300  
"id_token": "{_jwt containing claims listed below_}",  
etc.  
}

The IdP MUST NOT issue a refresh token. The access token is intended for immediate use and SHALL have a maximum lifetime of 5 minutes. The ID token includes the IdP’s subject identifier for the end user and information about the user’s most recent authentication event. The Resource Holder MUST validate the ID token as per the standard OpenID Connect validation process.

The ID Token MUST contain the following claims:

iss: IdP’s unique identifying URI (matches idp parameter from Step 2)  
sub: unique identifier for user in namespace of issuer, i.e. iss + sub is globally unique  
aud: client_id of Resource Holder (matches client_id in Resource Holder request in Step 3.4)  
exp: expire time (should be short-lived)  
iat: issued at time  
auth_time: time that user last authenticated (optional)  
nonce: when included in Resource Holder’s request, must match nonce value from Step 3.4  
acr: http://udap.org/[ial1-3|loa1-4]  
amr: http://udap.org/[aal1-3|loa1-4]

4.4 If the subject identifier included in the ID token has not been previously mapped to a local user or role, then the Resource Holder MAY request the user’s identity details from the IdP’s UserInfo endpoint using the access token supplied in the response from the IdP’s token endpoint:

GET /optionalpath/userinfo HTTP/1.1  
Host: idp.example.com  
Authorization: Bearer tokenForResourceHolder  
  


Example Response:

HTTP/1.1 200 OK  
Content-Type: application/json  
  
{  
"iss": {_same as in ID Token_}  
"sub": {_same as in ID Token_}  
"last_name": {_subject’s last_ name}  
...more claims…  
}

Note: The organization operating the upstream IdP MAY make additional resources available to the Resource Holder to support the authentication or refine the scope of authorization of the user, such as when access to resources held by the Resource Holder should be limited based on additional information provided by the upstream IdP’s system. How the IdP communicates the availability of such resources to the Resource Holder is not defined in this specification.

4.5 The Resource Holder processes the authenticated identity information (for example, by mapping the authenticated user to a local user or role). The Resource Holder MAY interact with the user to resolve the authenticated user’s identity. If the Resource Holder can map the subject to a local user or role, then the Resource Holder MUST also interact with the user to obtain authorization for the Client App to access resources held by the Resource Holder, if such authorization is required. The Resource Holder MAY store this binding for reuse if the same subject identifier is returned in response to a future authentication request.

4.5.1 If the authentication and authorization steps are successful, the Resource Holder returns an authorization code or access token as appropriate for the response type that was requested by the Client App in Step 2. In this example for a Client App using the authorization code flow, an authorization code is returned:

HTTP/1.1 302 Found  
Location: https://client.example.com/clientredirect?  
code=authz_code_from_resource_holder&  
state=client_random_state

The Client App then proceeds with the appropriate step of OAuth 2.0 authorization code flow or implicit grant flow.

4.5.2 If the Resource Holder cannot map the authenticated identity information provided by the IdP to a local user or role, or the local user does not authorize the Client App to access the resources held by the Resource Holder, then the Resource Holder terminates this workflow by redirecting the user’s browser to the Client App’s redirection URI with an error code of “access_denied” as per standard OAuth 2.0 error flow, as in this example for a Client App using the authorization code flow:

HTTP/1.1 302 Found  
Location: https://client.example.com/clientredirect?  
error=access_denied&  
state=client_random_state

The Client App then proceeds with the standard OAuth 2.0 authorization code flow or implicit grant flow, as appropriate.

5 References

Cooper, D., et al. “Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile”, RFC 5280, RFC Editor, May 2008.  
Grassi, P., et al. “Digital Identity Guidelines, Federation and Assertions”, NIST Special Publication 800-63C, National Institute of Standards and Technology, June 2017.  
Hardt, D., Ed., “The OAuth 2.0 Authorization Framework”, RFC 6749, RFC Editor, October 2012.  
Sakimura, N, et al. “OpenID Connect Core 1.0 incorporating errata set 1”, The OpenID Foundation, November 2014.

6 Authors

Luis C. Maas III, EMR Direct  
Julie W. Maas, EMR Direct

7 Notices

Copyright ©2016-2025 UDAP.org and the persons identified as the document authors. All rights reserved.

UDAP.org grants to any interested party a non-exclusive, royalty-free, worldwide right and license to reproduce, publish, distribute and display this Specification, in full and without modification, solely for the purpose of implementing the technology described in this Specification, provided that attribution is made to UDAP.org as the source of the material and that such attribution does not indicate an endorsement by UDAP.org.

All Specifications, and the information contained therein, are provided on an “AS IS” basis and the authors, the organizations they represent, and UDAP.org make no (and hereby expressly disclaim any) warranties, express, implied, or otherwise, including but not limited to any warranty that the use of the information therein will not infringe any rights or any implied warranties of merchantability or fitness for a particular purpose, and the entire risk as to implementing this specification is assumed by the implementer. Additionally, UDAP.org takes no position regarding the validity or scope of any intellectual property or other rights that might be claimed to pertain to the implementation or use of the technology described in this document or the extent to which any license under such rights might or might not be available, nor does it represent that it has made any independent effort to identify any such rights.

 

#### About UDAP

The Unified Data Access Profiles (UDAP™) published by UDAP.org increase confidence in open API transactions through the use of trusted identities and verified attributes. UDAP use cases support standards-based security, privacy and scalable interoperability through reusable identities, leveraging dynamic client registration, JWT-based client authentication and Tiered OAuth.   
  
