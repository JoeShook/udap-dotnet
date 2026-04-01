# UDAP Tiered OAuth for User Authentication

**Version:** STU 1
**Source:** https://www.udap.org/udap-user-auth.html
**Authors:** Luis C. Maas III, EMR Direct; Julie W. Maas, EMR Direct
**Copyright:** 2016-2025 UDAP.org

---

## Overview

This specification describes a distributed authentication framework enabling Resource Holders to leverage trusted Identity Providers for user authentication. As stated in the document: "Resource Holders can leverage a trusted network of Identity Providers to authenticate users and obtain information about them in order to make an authorization decision."

## Core Concept

The protocol implements a tiered authorization model where Client Apps request access from Resource Holders, who then request user authentication from upstream Identity Providers. This architecture reduces information leakage risks by having Resource Holders obtain user data directly from authenticating IdPs rather than through intermediaries.

## Workflow Steps

### Step 1: UDAP Capability Discovery

Client Apps verify Resource Holder support by querying the well-known UDAP metadata endpoint:

```
GET /.well-known/udap HTTP/1.1
Host: resourceholder.example.com
```

Response includes the Resource Holder's certificate chain in the x5c parameter.

### Step 2: Client Authorization Request

The Client App directs the user to the Resource Holder's authorization endpoint, including:
- The "udap" scope to signal UDAP usage
- An "idp" parameter specifying the preferred Identity Provider URI
- Standard OAuth parameters (response_type, client_id, state, redirect_uri)

```
GET /authorize?
  response_type=code&
  state=client_random_state&
  client_id=clientIDforResourceHolder&
  scope=udap+resource_scope1+resource_scope2&
  idp=https://idp.example.com/optionalpath&
  redirect_uri=https://client.example.net/clientredirect HTTP/1.1
Host: resourceholder.example.com
```

### Step 3: Resource Holder-IdP Interaction

**Step 3.1: Trust Evaluation**
The Resource Holder retrieves the IdP's UDAP metadata and evaluates the IdP's certificate against local trust policies.

**Step 3.2: Client Registration**
If the Resource Holder lacks a client_id for the IdP, it should attempt dynamic client registration as a confidential client per UDAP Dynamic Client Registration specifications.

**Step 3.3: Error Handling**
If the Resource Holder doesn't trust the IdP or cannot obtain a client_id, it may:
- Attempt authentication with an alternative IdP
- Interact with the user to determine a suitable alternative
- Terminate by returning an "invalid_idp" error:

```
HTTP/1.1 302 Found
Location: https://client.example.net/clientredirect?
  error=invalid_idp&
  state=client_random_state
```

**Step 3.4: IdP Authorization Request**
The Resource Holder redirects the user to the IdP's authorization endpoint, including:
- The "openid" and "udap" scopes
- A nonce parameter (recommended)
- The Resource Holder's own state value (not reusing the Client App's state)

```
HTTP/1.1 302 Found
Location: https://idp.example.com/optionalpath/authorize?
  response_type=code&
  state=resource_holder_random_state&
  client_id=resourceHolderClientIDforIdP&
  scope=openid+udap&
  nonce=resource_holder_nonce&
  redirect_uri=https://resourceholder.example.net/redirect HTTP/1.1
```

### Step 4: IdP User Authentication

**Step 4.1: Authorization Code Return**
Upon successful authentication, the IdP returns an authorization code:

```
HTTP/1.1 302 Found
Location: https://resourceholder.example.net/redirect?
   code=authz_code_from_idp&
   state=resource_holder_random_state
```

The Resource Holder must validate that the returned state matches the value generated in Step 3.4. Mismatches trigger a "server_error" response to the Client App.

**Step 4.2: Error Responses**
If the IdP cannot authenticate the user or the user denies authorization, the IdP returns an error:

```
HTTP/1.1 302 Found
Location: https://resourceholder.example.net/redirect?
  error=access_denied&
  state=resource_holder_random_state
```

The Resource Holder validates the state and forwards an "access_denied" error to the Client App:

```
HTTP/1.1 302 Found
Location: https://client.example.com/redirect?
  error=access_denied&
  state=client_random_state
```

**Step 4.3: Token Exchange**
The Resource Holder exchanges the authorization code at the IdP's token endpoint using JWT-based client authentication:

```
POST /optionalpath/token HTTP/1.1
Host: idp.example.com
Content-type: application/x-www-form-urlencoded

grant_type=authorization_code&
  code=authz_code_from_idp &
  client_assertion_type=urn:ietf:params:oauth:grant-type:jwt-bearer&
  client_assertion=eyJh[...remainder of JWT omitted for brevity...]&
  udap=1
```

Token Response:

```
HTTP/1.1 200 OK
Content-Type: application/json

{
  "access_token": "tokenForResourceHolder",
  "token_type": "Bearer",
  "expires_in": 300
  "id_token": "{_jwt containing claims listed below_}",
  etc.
}
```

**Token Requirements:**
- IdP must NOT issue refresh tokens
- Access tokens are for immediate use with maximum 5-minute lifetime
- ID tokens must be validated per standard OpenID Connect procedures

**Required ID Token Claims:**
- `iss`: IdP's unique identifying URI (matches idp parameter from Step 2)
- `sub`: unique user identifier within issuer's namespace
- `aud`: Resource Holder's client_id
- `exp`: expiration time (short-lived)
- `iat`: issued at time
- `auth_time`: user's last authentication time (optional)
- `nonce`: must match value from Step 3.4 if included in request
- `acr`: authentication context class reference (http://udap.org/[ial1-3|loa1-4])
- `amr`: authentication methods reference (http://udap.org/[aal1-3|loa1-4])

**Step 4.4: UserInfo Request**
If the subject identifier hasn't been previously mapped to a local user, the Resource Holder may request additional identity details:

```
GET /optionalpath/userinfo HTTP/1.1
Host: idp.example.com
Authorization: Bearer tokenForResourceHolder
```

UserInfo Response:

```
HTTP/1.1 200 OK
Content-Type: application/json

{
  "iss": {_same as in ID Token_}
  "sub": {_same as in ID Token_}
  "last_name": {_subject's last name}
    ...more claims...
}
```

**Step 4.5: Identity Processing**
The Resource Holder processes the authenticated identity information, potentially:
- Mapping the authenticated user to local user or role
- Interacting with the user to resolve identity
- Obtaining user authorization for Client App resource access
- Storing identity bindings for future use

**Step 4.5.1: Successful Authorization**
Upon successful authentication and authorization, the Resource Holder returns an authorization code or access token matching the Client App's requested response type:

```
HTTP/1.1 302 Found
Location: https://client.example.com/clientredirect?
   code=authz_code_from_resource_holder&
   state=client_random_state
```

**Step 4.5.2: Authorization Failure**
If identity mapping fails or the user denies authorization, the Resource Holder returns an error:

```
HTTP/1.1 302 Found
Location: https://client.example.com/clientredirect?
  error=access_denied&
  state=client_random_state
```

## Key Design Principles

**Direct Data Flow**: "The Resource Holder obtains the user data directly from the IdP that has authenticated the user instead of from the Client App or other third party, the risk of information leakage or assertion substitution is substantially reduced."

**Scope Requirement**: The "udap" scope signals UDAP protocol usage. As noted: "If this scope is omitted, the behavior of the Resource Holder is unspecified and the UDAP Tiered OAuth for User Authentication workflow defined in this document might not be supported."

**Grant Type Requirements**: The Resource Holder must use authorization code flow with IdPs regardless of the Client App's requested grant type. For Client Apps: "The client MAY use either the authorization code or implicit grant flow."

**State Parameter Management**: The Resource Holder generates independent state values for each tier: "The Resource Holder MUST generate its own random value for the state parameter and MUST NOT reuse the value provided by the Client App."

## References

- RFC 5280 - Internet X.509 Public Key Infrastructure Certificate and CRL Profile
- RFC 6749 - The OAuth 2.0 Authorization Framework
- NIST SP 800-63C - Digital Identity Guidelines, Federation and Assertions
- OpenID Connect Core 1.0
