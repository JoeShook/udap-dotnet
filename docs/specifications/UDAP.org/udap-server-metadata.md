# UDAP Server Metadata

**Version:** STU 1
**Source:** https://www.udap.org/udap-server-metadata.html
**Authors:** Luis C. Maas III, EMR Direct; Julie Maas, EMR Direct
**Copyright:** 2020-2025 UDAP.org

---

## Overview

This specification defines server metadata requirements for UDAP (Unified Data Access Profiles), enabling communities to publish OAuth 2.0 endpoint information at well-known URLs.

## Key Principles

Metadata requirements differ between client and server roles. When metadata keys end in "_supported" with parameter arrays, other actors should assume those are the only supported values for UDAP workflows: "other actors MAY assume that, at least for UDAP workflows, the publisher of the metadata does NOT support other parameter values."

Empty arrays communicate unsupported optional functionality. Omitted keys should not trigger assumptions about supported parameters.

## Supported Metadata Elements

### Certificate Chain
- **x5c**: Base64-encoded DER certificate array; first certificate is the signing key, remainder forms chain

### UDAP Protocol
- **udap_versions_supported**: Array of UDAP versions; currently only "1" defined (case-insensitive)
- **udap_profiles_supported**: Identifies supported profiles:
  - `udap_dcr` - Dynamic Client Registration
  - `udap_authn` - JWT Authentication
  - `udap_authz` - Client Authorization
  - `udap_to` - Tiered OAuth
  - Minimum one required

### Certifications
- **udap_certifications_supported**: URIs for acceptable certification values
- **udap_certifications_required**: URIs for mandatory certification values

### Authorization Extensions
- **udap_authorization_extensions_supported**: Key names for supported authorization extension objects in JWT submissions
- **udap_authorization_extensions_required**: Key names for required authorization extension objects

### OAuth Endpoints and Parameters
- **grant_types_supported**: OAuth grant types for UDAP workflows (minimum one required)
- **scopes_supported**: Supported scopes for UDAP workflows
- **authorization_endpoint**: URI for authorization endpoint
- **token_endpoint**: URI for token endpoint
- **registration_endpoint**: URI for registration endpoint

### Signed Endpoints
- **signed_endpoints**: Signed JWT containing endpoint URIs (detailed in Section 2)

### Authentication Methods
- **token_endpoint_auth_methods_supported**: Authentication methods (typically "private_key_jwt"; minimum one required)
- **token_endpoint_auth_signing_alg_values_supported**: Supported JWA algorithms for token endpoint JWTs (minimum one required)
- **registration_endpoint_jwt_signing_alg_values_supported**: Supported algorithms for registration endpoint statements (minimum one required; "RS256" recommended)

## Signed Endpoints JWT

### Claims

- **iss**: Server's unique identifying URI (base for UDAP metadata)
- **sub**: Must match iss
- **exp**: Expiration time (may be long-lived, e.g., 1 year)
- **iat**: Issued-at timestamp
- **jti**: Unique token identifier preventing replay
- **authorization_endpoint**: Authorization endpoint URI (if included in unsigned metadata)
- **token_endpoint**: Token endpoint URI (if included in unsigned metadata)
- **registration_endpoint**: Registration endpoint URI (if included in unsigned metadata)

### JOSE Header Requirements

- **alg**: "RS256"
- **x5c**: Certificate chain [cert1, cert2, ...] (cert1 required; chain optional)
- **x5u**: Valid URI (optional)

The x5c element contains Base64-encoded DER X.509 certificates. The leaf certificate (cert1) holds the public key for JWT signature validation. The JWT uses JWS compact serialization per RFC 7515.

## Client Validation Process

### 3.1 - Signature Validation

Clients extract the public key from cert1's x5c parameter and validate the digital signature. Invalid signatures result in request denial.

### 3.2 - Chain Building

Clients construct a certificate chain from the Server's certificate to a trusted anchor using standard X.509 techniques, including validity and revocation checking. Servers may provide complete chains; clients may use additional certificates from caches or X.509 AIA mechanisms. "Client apps SHOULD support the X.509 AIA mechanism for chain building."

### 3.3 - Claims Validation

Clients verify iss, sub, exp, iat, and jti. The iss value MUST match a uriName entry in the Server certificate's Subject Alternative Names extension (typically the base URL). Sub must match iss, and the JWT must not be expired.

### 3.4 - Endpoint Matching

Clients confirm unsigned metadata endpoints match signed_endpoints JWT claims. Mismatches or missing endpoints trigger rejection.

### 3.5 - Failure Handling

"If the Client app rejects the signed_endpoints JWT for any reason, the Client app SHOULD NOT proceed, and, if applicable, SHOULD alert the end user that the server's endpoint metadata could not be validated."

## Design Rationale

The primary use case is client verification of OAuth 2.0 endpoint authenticity before user redirection or data submission. This approach validates that metadata is signed by the expected organization -- analogous to how Authorization Servers validate client submissions during Dynamic Client Registration or JWT-Based Client Authentication.

For authorization code flows, signed endpoints allow clients to display validated signing organization information to end users before authorization redirection, providing more granular authentication than TLS certificate attributes alone.

## Metadata Consistency Requirements

Publishers should not include keys or values inconsistent with other metadata. For example, servers without authorization code flow support should omit the authorization_endpoint key and exclude "authorization_code" from supported grant types.

## References

- RFC 5280 - Internet X.509 Public Key Infrastructure Certificate and CRL Profile
- RFC 6749 - The OAuth 2.0 Authorization Framework
- RFC 7515 - JSON Web Signature (JWS)
- RFC 7519 - JSON Web Token (JWT)
