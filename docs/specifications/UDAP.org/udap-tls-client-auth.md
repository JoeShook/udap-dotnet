# UDAP Mutual TLS Client Authentication

**Version:** STU 1
**Source:** https://www.udap.org/udap-tls-client-auth.html
**Author:** Luis C. Maas III, EMR Direct
**Copyright:** 2016-2025 UDAP.org

---

## Overview

The specification describes how TLS client authentication extends OAuth 2.0 (RFC 6749) for client application authentication. As stated: "Client authentication using TLS has been deployed broadly in the field and provides an opportunity to leverage existing trust communities."

## Core Protocol Mechanism

The protocol leverages mutual TLS during the token endpoint handshake. The Authorization Server validates the client's X.509 certificate signature and trust chain before issuing access tokens. This applies to confidential clients and certain native device applications capable of protecting private keys.

## Eight-Step Workflow

### Step 1: UDAP Metadata Discovery

Clients retrieve Authorization Server metadata from `/.well-known/udap`, receiving certificate chains (x5c parameter).

### Step 2: Client Registration

Clients register with the Authorization Server, optionally through Dynamic Client Registration, specifying `token_endpoint_auth_method` as `tls_client_auth`.

### Step 3: Grant-Specific Prerequisites

Clients perform grant-type-specific steps (e.g., authorization code flow directs users to authorization endpoint).

### Step 4: TLS Handshake

Clients present suitable authentication certificates from acceptable issuers identified during the handshake.

### Step 5: Token Request

Clients submit token requests including:
- `grant_type` parameter (authorization_code, client_credentials, or extension grants)
- `client_id` as request parameter
- `udap=1` extension parameter
- No HTTP Basic authentication allowed

### Step 6: Authorization Server Validation

**6.1:** Verifies client certificate presentation during TLS handshake

**6.2:** Constructs and validates certificate chain to trusted anchor using conventional X.509 techniques, including revocation checking

**6.3:** Confirms Subject DN and Subject Alternative Names match values associated with the presented client_id per trust community certificate profiles

**6.4:** Validates remaining request parameters per grant mechanism requirements

### Step 7: Server Response

**7.1:** On approval, returns token response per RFC 6749 Section 5.1, including access_token, token_type, expires_in, and optionally refresh_token

**7.2:** On denial, returns error per RFC 6749 Section 5.2 using error codes: "invalid_client" for trust/validation failures, "invalid_request" for signature issues

### Step 8: Alternative Workflows (Section 8)

**8.1 - Direct Resource Server Authentication:**
Resource Servers may validate client certificates independently, using 403 responses with `invalid_client` error for failed validation.

**8.2 - Mutual Validation Model:**
Resource Servers may require both TLS client authentication and Bearer token validation. Authorization Servers communicate client public keys/certificate attributes via access tokens or introspection endpoints. Mismatches trigger 403 responses with `invalid_grant` error.

**8.3:** Specification does not restrict Authorization Server/Resource Server communication regarding workflow selection.

## Important Notes

- HTTP examples are non-normative with formatting adjustments for readability
- Client authentication at authorization endpoint is excluded from this protocol
- User agents at authorization endpoints lack access to client private keys
- Document references mutual TLS because client authentication supplements required server authentication

## References

- RFC 5280 - Internet X.509 Public Key Infrastructure Certificate and CRL Profile
- RFC 6749 - The OAuth 2.0 Authorization Framework
- RFC 7525/BCP 195 - Recommendations for Secure Use of TLS and DTLS
