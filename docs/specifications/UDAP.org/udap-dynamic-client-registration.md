# UDAP Dynamic Client Registration

**Version:** STU 1
**Source:** https://www.udap.org/udap-dynamic-client-registration.html
**Authors:** Luis C. Maas III, EMR Direct; Julie Maas, EMR Direct
**Copyright:** 2016-2025 UDAP.org

---

## Overview

This specification extends RFC 7591 OAuth 2.0 Dynamic Client Registration Protocol using digital certificates for scalable client registration in large ecosystems. It enables "real-time trust assessment, validation of identifying attributes, and support for revocation of certificates" through a PKI-based approach to client registration.

## Workflow Steps

### Step 1: Metadata Discovery

Client applications query `/.well-known/udap` to verify Authorization Server support and retrieve the server's certificate chain (x5c).

### Step 2: Software Statement Preparation

Clients create a signed JWT containing registration metadata with required claims:
- `iss`/`sub`: Client operator's unique URI
- `aud`: Registration endpoint URL
- `exp`/`iat`/`jti`: Temporal and replay protection claims
- `client_name`, `redirect_uris`, `grant_types`, `response_types`, `token_endpoint_auth_method`

JOSE header includes:
- `alg`: "RS256"
- `x5c`: Certificate chain (leaf certificate required)
- `x5u`: Optional URI for certificates

### Step 3: Registration Request

Clients POST to the registration endpoint with:

```
software_statement: [signed JWT]
certifications: [optional array of endorsement JWTs]
udap: "1"
```

### Step 4: Authorization Server Validation

**4.1 Signature Validation:** Server validates the digital signature using the public key from cert1 in the x5c header.

**4.2 Certificate Chain Building:** Server constructs and validates a certificate chain to a trusted anchor using "conventional X.509 chain building techniques and path validation, including certificate validity and revocation status checking."

**4.3 Claims Validation:** Server validates iss, sub, aud, exp, iat, and jti claims. The iss value must match a Subject Alternative Name (uriName) entry in the client certificate. Maximum software statement lifetime is 5 minutes. The server may deny requests with duplicate jti values (replay protection).

**4.4 Parameter Validation:** Server validates all registration parameters against RFC 7591 requirements.

**4.5 Previous Registration Handling:** Server may cancel previous registrations linked to the same public key for the requested grant type.

### Step 5: Authorization Server Response

**Success (201 Created):**
Server returns registration response including:
- `client_id` (issued by server)
- `software_statement` (as submitted)
- All registration parameters from the software statement
- Server stores the client certificate for subsequent authentication

Example successful response:

```json
{
  "client_id": "example_client_id_issued_by_AS",
  "software_statement": "{the software statement as submitted}",
  "client_name": "string",
  "redirect_uris": ["array of URIs"],
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "private_key_jwt"
}
```

**Error (400 Bad Request):**
Server returns error codes per RFC 7591:
- `invalid_software_statement`: Invalid signature
- `unapproved_software_statement`: Trust validation failure
- Optional `error_description` parameter

## Section 6: Modifying or Cancelling Registrations

The client operator's URI (from Subject Alternative Name and 'iss' field) uniquely identifies an application over time, enabling registration modifications.

### Modification Request

Client submits a new registration request with the same 'iss' value but different claims or certifications. Server treats this as a request to "replace all information from the previous registration request with the information included in the new request."

Response should include the same client_id, with HTTP 200 status code (not 201).

### Cancellation Request

Client submits a registration request with the same 'iss' value but an empty grant_types array. Server should cancel the previous registration.

## Important Requirements & Constraints

- Protocol applies only to "confidential clients and certain native device apps" capable of protecting private keys
- Software statements should be "short-lived, max 5 minutes from iat"
- Client should "NOT attempt registration again with the same certificate if an unapproved_software_statement error is returned"
- Clients may attempt re-registration with alternative certificates if denied
- Authorization Servers "SHOULD support the X.509 AIA mechanism for chain building"
- Registration parameters should primarily exist in the signed software statement, not at JSON top level
- If a parameter appears in both locations, server "MUST ignore the parameter included at the top level"

## References

- RFC 5280 - Internet X.509 Public Key Infrastructure Certificate and CRL Profile
- RFC 6749 - The OAuth 2.0 Authorization Framework
- RFC 7519 - JSON Web Token (JWT)
- RFC 7591 - OAuth 2.0 Dynamic Client Registration Protocol
