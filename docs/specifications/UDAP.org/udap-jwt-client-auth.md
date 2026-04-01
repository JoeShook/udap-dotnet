# UDAP JWT-based Client Authentication Specification

**Version:** STU 1
**Source:** https://www.udap.org/udap-jwt-client-auth.html
**Authors:** Luis C. Maas III, EMR Direct; Julie Maas, EMR Direct
**Copyright:** 2016-2025 UDAP.org

---

## Overview

UDAP JWT-based Client Authentication extends OAuth 2.0 (RFC 6749) to enable organizations to reuse digital identities within trust communities. The specification allows "Client Apps [to construct] and digitally sign a JSON Web Token (JWT)" for authentication at the Authorization Server's token endpoint.

## Core Workflow

The specification defines a seven-step process:

### Step 1: Discovery

Client Apps retrieve Authorization Server UDAP metadata from `/.well-known/udap`, discovering the server's certificate chain and confirming UDAP support.

### Step 2: Registration

Client Apps must register with the Authorization Server unless using the unregistered client flow (Section 8.1). Dynamic Client Registration may be used if supported.

### Step 3: Grant-Specific Preparation

- **Authorization Code Flow**: Direct users to the authorization endpoint
- **Client Credentials Flow**: No additional steps required
- **Other Grant Types**: Follow respective requirements

### Step 4: Authentication Token (AnT) Construction

The AnT is a signed JWT containing:

**Claims:**
- `iss`, `sub`: Client ID
- `aud`: Token endpoint URI
- `exp`, `iat`: Expiration and issuance times
- `jti`: Token identifier for replay detection

**JOSE Header:**
- `alg`: "RS256"
- `x5c`: Certificate chain array
- `x5u`: Optional URI

### Step 5: Token Request

Client submits request with:
- `client_assertion_type`: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
- `client_assertion`: JWS compact serialization
- `udap`: "1"

No HTTP Basic authentication is permitted.

### Step 6: Authorization Server Validation

The AS performs four validations:

**6.1** Digital signature validation using public key from cert1

**6.2** X.509 certificate chain construction and path validation, "including certificate validity and revocation status checking"

**6.3** Claims validation (iss, sub, aud, exp, iat, jti) with 5-minute maximum lifetime recommended

**6.4** Grant mechanism-specific parameter validation

**6.5** Optional certificate attribute-based authorization constraints

### Step 7: Response

Success returns access token per RFC 6749 Section 5.1:

```
HTTP/1.1 200 OK
Content-Type: application/json

{
   "access_token": "example_access_token_issued_by_AS",
   "token_type": "Bearer",
   "expires_in": 3600
}
```

Failures return error codes: "invalid_client" for trust validation failures, "invalid_request" for signature issues.

## Key Requirements

- **Confidential Clients Only**: Protocol "SHALL only be used only by Client Apps that are able to protect the private key"
- **No Shared Secrets**: HTTP Basic authentication explicitly prohibited
- **Certificate Binding**: Client registration must bind to uniformResourceIdentifier in certificate Subject Alternative Names
- **Client ID Matching**: If included, client_id parameter must match iss and sub claims
- **Replay Prevention**: AS may deny requests using duplicate jti values

## Unregistered Client Flow (Section 8.1)

Authorization Servers may permit unregistered Client Apps when identity and privileges are fully determinable from certificate attributes, using client_credentials flow with reserved sub claim value (e.g., "unregistered"). Not suitable for authorization code flow due to redirect URI pre-registration requirements.

## Protocol Applicability

Compatible with authorization code flow, client credentials flow, and "other extension grant flows utilizing the token endpoint."

## References

- RFC 5280 - Internet X.509 Public Key Infrastructure Certificate and CRL Profile
- RFC 6749 - The OAuth 2.0 Authorization Framework
- RFC 7515 - JSON Web Signature (JWS)
- RFC 7519 - JSON Web Token (JWT)
- RFC 7521 - Assertion Framework for OAuth 2.0 Client Authentication and Authorization Grants
- RFC 7523 - JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants
