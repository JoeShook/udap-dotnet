# UDAP Certifications and Endorsements for Client Applications

**Version:** STU 1
**Source:** https://www.udap.org/udap-certifications-and-endorsements.html
**Authors:** Luis C. Maas III, EMR Direct; Julie Maas, EMR Direct
**Copyright:** 2016-2025 UDAP.org

---

## Overview

This specification details how UDAP supports portable electronic client certifications for expressing verified attributes about client application developers and applications.

"UDAP supports portable electronic client certifications that can be used by a Certifier to express verified attributes about a client application developer or a specific client application."

## Certification JWT Claims

The specification defines required and optional claims for certification JWTs:

### Essential Identifiers
- `iss`: Certifier URI
- `sub`: Client URI
- `jti`: Token ID

### Temporal Bounds
- `exp`: Expiration (max 3 years)
- `iat`: Issued time

### Certification Metadata
- `certification_name`: Name of the certification
- `certification_logo`: Logo URI
- `certification_description`: Description text
- `certification_uris`: URIs identifying the certification type
- `certification_issuer`: Issuing organization (omitted for self-declarations)

### Client Parameters
- `client_name`: Client application name
- `software_id`: Software identifier
- `redirect_uris`: Redirect URIs
- `grant_types`: Supported grant types

### Contact Information
- `contacts`: Array of contact URIs (must use mailto or https schemes)

## JOSE Header Requirements

- `alg`: Signing algorithm (e.g., "RS256")
- `x5c`: Certificate chain array - "The x5c claim contains the Certifier's certificate chain as an array of one or more elements, each containing a Base64 encoded representation of the DER encoded X.509 certificate."
- `x5u`: Optional certificate URI

## Validation Workflow

Authorization servers must perform six validation steps:

1. **Digital signature verification** using the public key from cert1
2. **Certification URI evaluation** - evaluate `certification_uris` against local policy
3. **Claims validation** - validate `iss`, `sub`, `aud`, `exp`, `iat`, `jti` claims
4. **X.509 certificate chain construction** and path validation per RFC 5280
5. **Parameter matching** - match registration parameters against certification constraints
6. **Coverage check** - reject if required parameters lack certification coverage

## Three Certification Types

The specification provides examples of:

1. **Third-party validations** - External certifier validates the client application
2. **Self-declarations by developers** - Developer self-certifies; omits the `certification_issuer` field and requires `certification_uris`
3. **Endorsements** - Third-party endorsement of specific attributes

## Revocation Mechanism

Certifiers may support status checking via a TLS-protected endpoint. Relying parties submit HTTP GET requests including URL-encoded `jti` and `exp` parameters, receiving a JSON response with a boolean `valid` field.

## Integration with Dynamic Registration

Clients submit certifications as an array parameter in Dynamic Client Registration requests per RFC 7591, including the extension parameter "udap" with value "1".

## References

- RFC 5280 - Internet X.509 Public Key Infrastructure Certificate and CRL Profile
- RFC 6749 - The OAuth 2.0 Authorization Framework
- RFC 7519 - JSON Web Token (JWT)
- RFC 7591 - OAuth 2.0 Dynamic Client Registration Protocol
