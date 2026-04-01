# UDAP.org Specifications

**Source:** https://www.udap.org
**Downloaded:** 2026-04-01

The Unified Data Access Profiles (UDAP) published by UDAP.org increase confidence in open API transactions through the use of trusted identities and verified attributes. UDAP's first applications are in the healthcare sector, but the profiles are not healthcare specific.

## Specifications

| Specification | Version | File |
|---------------|---------|------|
| [JWT-Based Client Authentication](udap-jwt-client-auth.md) | STU 1 | Asymmetric cryptography for client authentication at token endpoint |
| [Tiered OAuth for User Authentication](udap-user-auth.md) | STU 1 | Scalable cross-organizational user authentication via trusted IdPs |
| [Dynamic Client Registration](udap-dynamic-client-registration.md) | STU 1 | PKI-based dynamic client registration extending RFC 7591 |
| [Mutual TLS Client Authentication](udap-tls-client-auth.md) | STU 1 | Client authentication during TLS handshake |
| [Certifications and Endorsements](udap-certifications-and-endorsements.md) | STU 1 | Third-party validation of client applications |
| [Client Authorization Grants](udap-client-authorization-grants.md) | DRAFT | JWT-based client authorization assertions |
| [Server Metadata](udap-server-metadata.md) | STU 1 | Publishing capabilities and endpoints for discovery |

## Key Concepts

- **Trust Communities**: Groups of organizations sharing common trust anchors (root CAs)
- **X.509 PKI**: All trust is rooted in X.509 certificate chains with revocation checking
- **Software Statements**: Signed JWTs containing client registration metadata
- **Authorization Assertions (AzA)**: Signed JWTs conveying authorization grants
- **Signed Endpoints**: Server metadata JWTs for endpoint authenticity verification

## Contact

- Email: collaborate@udap.org
- Google Group: https://groups.google.com/forum/#!forum/udap-discuss/join
