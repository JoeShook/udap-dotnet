# UDAP Client Authorization Grants using JSON Web Tokens

**Version:** DRAFT 2019-05-15
**Source:** https://www.udap.org/udap-client-authorization-grants.html
**Authors:** Luis C. Maas III, EMR Direct; Julie Maas, EMR Direct
**Copyright:** 2016-2025 UDAP.org

---

## Overview

UDAP extends OAuth 2.0 authorization framework (RFC 6749) through certificate-based client authorization grants using JSON Web Tokens. This implementation builds on assertion-based authorization patterns defined in RFC 7521 and RFC 7523.

**Core Mechanism:** Client applications obtain digitally signed Authorization Assertions (AzA) and submit them to the token endpoint.

## Authorization Assertion Acquisition Methods

### Method A: Resource Owner-Initiated

"A resource owner or other authorized party may generate and sign an Authorization Assertion and provide it to a Client App so that the app may then access certain data" as an alternative when the user cannot interact with the OAuth server in real time.

### Method B: Application-Initiated

"A privileged application or other requesting party may generate and sign an Authorization Assertion to communicate information that the OAuth Server requires in order to determine what data should be accessible," including self-signed assertions by the application itself.

## Protocol Architecture

**Foundation:** This protocol relies on "standard public key infrastructure tools and is independent of the protocol used to authenticate the Client App."

**Trust Model:** "Before granting an access token, the Authorization Server validates the digital signature on the AzA submitted by the Client App and evaluates the trust chain for the Assertion Signer's X.509 certificate."

**Constraint:** This mechanism "MAY be used only in settings where the Assertion Signer is able to protect the private key used to sign AzAs."

## Workflow Steps

### Step 1: Server Capability Discovery

Client applications verify UDAP federation support:

```
GET https://resourceholder.example.com/.well-known/udap HTTP/1.1

Response:
HTTP/1.1 200 OK
Content-Type: application/json

{
  "x5c" : ["{cert1}", "{cert2}", ...]
}
```

A 404 response indicates the server does not advertise UDAP Client Authorization Grants protocol support.

### Step 2: Client Registration

Applications must register with the Authorization Server. Registration approach depends on server capabilities:

- **Dynamic Registration:** If supported, use UDAP Dynamic Client Registration protocol
- **Alternative Methods:** Server should provide another registration method if dynamic registration is unavailable

**Grant Type Selection:**
- `urn:ietf:params:oauth:grant-type:jwt-bearer` for authorization-only scenarios
- `client_credentials` for self-signed assertions used for both authorization and authentication

### Step 3: Authorization Assertion Generation

The AzA is a signed JWT containing required claims:

| Claim | Purpose |
|-------|---------|
| `iss` | Unique URI identifying the Client Token Service for the Assertion Signer |
| `sub` | Authorized accessor for the access token (client ID for self-signed assertions) |
| `azp` | Authorized party (Client App's identifying URI; omit for self-signed) |
| `aud` | Token endpoint URI of the Authorization Server |
| `exp` | Expiration time (seconds since epoch) |
| `iat` | Issued-at time (seconds since epoch) |
| `jti` | Identifier preventing assertion replay |
| `resources` | *Optional* - URIs of specific authorized resources |
| `scope` | *Optional* - Space-delimited list of restricted scopes |
| `extensions` | *Optional* - JSON object for custom parameters |

**JOSE Header Requirements:**

```json
{
  "alg": "RS256",
  "x5c": ["cert1", "cert2", "..."],
  "x5u": "valid URI (optional)"
}
```

The `x5c` claim presents the Assertion Signer's certificate chain as base64-encoded DER X.509 certificates. The leaf certificate (cert1) holds the public key corresponding to the private signing key. The AzA is "signed and assembled using JWS compact serialization as per RFC 7515."

### Step 4: Extension Support

"An Authorization Server MAY support extensions to this protocol using the extensions parameter. The extension names and their required formats are defined by the Authorization Server and are communicated in an out-of-band manner."

Example extensions:

```json
{
  "extensions": {
    "purpose_of_use": "payment",
    "query_initiator": {"name": "john smith", "user_id": "A98765"}
  }
}
```

### Step 5: Token Request

Two implementation patterns exist:

#### 5.1: Authorization-Only Pattern

Client includes:
- `grant_type`: `urn:ietf:params:oauth:grant-type:jwt-bearer`
- `assertion`: JWS compact serialization of signed AzA
- `udap`: "1" (signals protocol version)

Optional: client authentication credentials if required by server.

Example Request:

```
POST /token HTTP/1.1
Host: as.example.com
Content-type: application/x-www-form-urlencoded
Authorization: Basic bXlDbGllbnRJRDpINDl4LXN0cm9uZy1wYXNzd29yZC1CJDYz

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&
assertion=ewogICAiYWxnIjogIlJT...&
scope=read+write&
udap=1
```

**Use Case:** Resource owner signs an AzA valid for one hour when unavailable for interactive authorization code flow.

#### 5.2: Combined Authorization and Authentication Pattern

For client credentials grant, a single signed JWT serves both purposes. Client includes:
- `grant_type`: `client_credentials`
- `client_assertion_type`: `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`
- `client_assertion`: JWS compact serialization of signed AzA
- `udap`: "1"

**Critical Requirement:** "For this special case, the value of the AzA sub claim MUST be set to the client ID issued to the Client App by the AS."

Example Request:

```
POST /token HTTP/1.1
Host: hospital.example.com
Content-type: application/x-www-form-urlencoded

grant_type=client_credentials&
client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&
client_assertion=ewogICAiYWxnIjogIlJT...&
scope=system%2FPatient.read&
udap=1
```

**Use Case:** Privileged application requesting authorization on its own behalf, such as hospital system accessing patient health information with auditing extensions.

### Step 6: Authorization Server Validation

**6.1 Digital Signature Validation:**
"The AS validates the digital signature on the AzA using the public key extracted from cert1 in the x5c parameter of the JOSE header. If the signature cannot be validated, the request is denied."

**6.2 Certificate Chain Validation:**
"The AS attempts to construct a valid certificate chain from the Assertion Signer's certificate (cert1) to an anchor certificate trusted by the AS using conventional X.509 chain building techniques and path validation, including certificate validity and revocation status checking."

**6.3 Claims Validation:**

| Claim | Validation Rule |
|-------|-----------------|
| `sub` | Must identify entity recognized and authorized by AS |
| `azp` | If present, MUST match Client App's client ID |
| `aud` | MUST contain AS's base URL |
| `exp` | AzA must be unexpired |
| `jti` | Cannot be reused (replay protection) |

- Maximum 60-minute AzA lifetime recommended
- Server may deny duplicate assertions (same jti value)

**6.4 Extensions Processing:**
"If the extensions parameter is included, then the AS processes the extensions. The AS MAY ignore any extension names that it does not recognize. Alternatively, the AS MAY deny the request and return the error code 'invalid_grant' if an unrecognized name is encountered."

Error: Server should use "invalid_grant" if required extension names are missing.

**6.5 Scope Validation:**
"If the scope parameter is included, then the AS MUST disallow any scopes requested by the Client App that are not listed in the Authorization Assertion."

Options for disallowed scopes:
- Continue processing other requested scopes
- Return "invalid_scope" error code (RFC 6749 section 5.2)

"For assertions signed by the Client App, the Client App MUST still request scopes in the usual manner required by the OAuth flow in use even if it includes a list of scopes in this assertion."

**6.6 Additional Parameter Validation:**
"The AS validates any other parameters in the request as per the requirements of the authentication mechanism in use, if any."

**6.7 Resources Parameter Support:**
Optional feature. If assertion includes resources but server doesn't support: deny with "invalid_request" error. If resources included and supported: "AS MUST further narrow the scope of any access token granted to disallow access to resources that are not explicitly included in the list."

"Each resource URI listed MUST be treated as a fully specified URI, i.e. a listed resource URI does not allow access to resources that are located at subpaths of the listed URI or that contain additional query parameters."

### Step 7: Authorization Server Response

**7.1 Successful Response:**

```
HTTP/1.1 200 OK
Content-Type: application/json

{
  "access_token": "example_access_token_issued_by_AS",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

Optional: Refresh token may be included in response.

"The expiration time of the access token SHOULD NOT significantly exceed the expiration time of the AzA."

**7.2 Error Response:**

```
HTTP/1.1 400 Bad Request
Content-Type: application/json

{
  "error": "invalid_grant",
  "error_description": "The submitted authorization assertion has expired."
}
```

Error Code Guidance:
- Trust validation or signature failures: use "invalid_grant"
- Include "error_description" parameter in response

## Key Security Principles

1. **Key Protection:** Protocol requires "the Assertion Signer is able to protect the private key used to sign AzAs"
2. **Authentication Flexibility:** Works with HTTP Basic, UDAP JWT-Based Client Authentication, other mechanisms, or public clients without authentication
3. **Trust Chain Validation:** Mandatory X.509 certificate chain validation to server's trusted anchor certificates
4. **Lifetime Management:** Supports short-lived assertions appropriate to specific use cases

## References

- RFC 5280 - Internet X.509 Public Key Infrastructure Certificate and CRL Profile
- RFC 6749 - The OAuth 2.0 Authorization Framework
- RFC 7515 - JSON Web Signature (JWS)
- RFC 7519 - JSON Web Token (JWT)
- RFC 7521 - Assertion Framework for OAuth 2.0 Client Authentication and Authorization Grants
- RFC 7523 - JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants
