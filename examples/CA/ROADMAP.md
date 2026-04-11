# Sigil Roadmap — Toward EJBCA Feature Parity

**Vision**: A modern, .NET-native Certificate Authority and PKI management platform with first-class UDAP/FHIR support. Lightweight enough for dev/test, capable enough for production.

## Phase 1: Foundation (Current — In Progress)
- [x] Project scaffolding (Blazor Server, FluentUI v4, PostgreSQL, Serilog)
- [x] Data model: Community, CaCertificate (self-ref hierarchy), IssuedCertificate, CRL, CertificateRevocation, CertificateTemplate, Job/JobExecution
- [x] Certificate Explorer: tree view + detail panel (extensions, SANs, general info)
- [x] Drag & drop import: .pfx, .cer, .pem, .crl with auto-detection (role, chain matching via AKI/SKI)
- [x] CRL import with signature validation, CRL number tracking, next update
- [x] Bulk import from PKI generator certstores directory
- [x] Communities page (CRUD)
- [x] ASN.1 structure viewer (collapsible tree with OID friendly names, parsed values)
- [ ] Dashboard page (expiry warnings, community summary, recent activity)

## Phase 2: Certificate Issuance & Templates
- [ ] Template CRUD page with preset profiles (Root CA, Intermediate CA, UDAP Client, SSL Server)
- [ ] Certificate generation engine using .NET CertificateRequest + BouncyCastle
- [ ] "Issue Certificate" flow from Explorer: select issuing CA → pick template → fill subject/SANs → generate
- [ ] Root CA self-signed generation
- [ ] Intermediate CA generation (signed by parent)
- [ ] End-entity cert generation with full extension control
- [ ] ECDSA support alongside RSA
- [ ] Certificate download (.pfx, .cer, .pem)
- [ ] Certificate renewal (re-issue with same subject/SANs, new key, new validity)

## Phase 3: Revocation & CRL Management
- [ ] Revoke certificate action from Explorer (select reason code)
- [ ] CRL generation using BouncyCastle X509V2CrlGenerator
- [ ] Auto-increment CRL number from last known CRL
- [ ] CRL publishing endpoint (HTTP GET returns DER-encoded CRL)
- [ ] CRL viewer in Explorer (show revoked serials, dates, reasons)
- [ ] Delta CRL support

## Phase 4: Job Scheduler & Monitoring
- [ ] BackgroundJobScheduler (IHostedService + PeriodicTimer)
- [ ] CRL auto-renewal job (regenerate before NextUpdate)
- [ ] Certificate expiry reminder job (configurable window: 30/60/90 days)
- [ ] Jobs page: CRUD, execution history, manual "Run Now"
- [ ] Dashboard integration: expiring certs widget, overdue CRLs, job status
- [ ] Email/webhook notifications for expiry and job failures

## Phase 5: Certificate Store Providers
- [ ] ICertificateStoreProvider interface finalization
- [ ] File system provider (read/write PFX/PEM on disk)
- [ ] Database provider (current default — PFX bytes in PostgreSQL)
- [ ] PKCS#11 / HSM provider (private keys never leave HSM)
- [ ] Google Cloud KMS provider
- [ ] HashiCorp Vault provider (Transit secrets engine for signing, PKI engine for issuance)
- [ ] Azure Key Vault provider
- [ ] AWS CloudHSM / KMS provider
- [ ] Provider configuration UI (select per-community or per-CA)

## Phase 6: Protocol Support
- [ ] **EST (RFC 7030)** — Enrollment over Secure Transport (simpleenroll, simplereenroll, cacerts, csrattrs)
- [ ] **SCEP** — Simple Certificate Enrollment Protocol (legacy device support)
- [ ] **CMP (RFC 4210)** — Certificate Management Protocol (cert requests, revocation, key update)
- [ ] **ACME (RFC 8555)** — Automated Certificate Management Environment (Let's Encrypt-style)
- [ ] **REST API** — Full CRUD for certs, CRLs, templates, communities, jobs
- [ ] API authentication (API keys, mTLS, OAuth2)

## Phase 7: OCSP Responder
- [ ] OCSP responder endpoint (RFC 6960)
- [ ] Delegated OCSP signing certificate support
- [ ] OCSP response caching
- [ ] OCSP stapling support
- [ ] Configurable per-CA (CRL-only vs OCSP vs both)

## Phase 8: UDAP/FHIR-Specific Features
- [ ] UDAP community trust chain validation (full chain build + CRL check)
- [ ] UDAP metadata generation (.well-known/udap)
- [ ] UDAP-specific certificate templates (SANs with FHIR URIs, UDAP EKUs)
- [ ] TEFCA trust chain profiles
- [ ] Certification & Endorsement JWT generation
- [ ] Community trust anchor distribution
- [ ] Conformance testing integration (validate certs against UDAP spec)

## Phase 9: Security & Compliance
- [ ] Role-based access control (RBAC) — Admin, Operator, Auditor, RA roles
- [ ] Full audit logging (who did what, when, to which cert)
- [ ] Audit log viewer/export
- [ ] RA (Registration Authority) workflows — request/approve/reject
- [ ] Key escrow / key recovery
- [ ] FIPS 140-3 compliance mode (HSM-only key generation)
- [ ] Certificate transparency (CT) log submission
- [ ] Policy constraints enforcement (name constraints, path length)

## Phase 10: Operations & Scale
- [ ] High availability (multi-instance with shared DB)
- [ ] Database support: PostgreSQL (primary), SQL Server, MySQL
- [ ] OpenTelemetry integration (traces, metrics)
- [ ] Health check endpoints
- [ ] Docker / Kubernetes deployment manifests
- [ ] Backup/restore for cert stores and DB
- [ ] Import/export in standard formats (PKCS#7 bundles, PEM chains)
- [ ] Bulk operations (renew all expiring, revoke by template, etc.)

## Phase 11: Advanced CA Features
- [ ] Cross-certification (bridge CA)
- [ ] Certificate hold / unrevoke (reason code 6)
- [ ] Name constraints (permitted/excluded subtrees)
- [ ] Policy mapping between communities
- [ ] Certificate archival (soft delete with retention)
- [ ] Subordinate CA provisioning (issue sub-CA certs for external CAs)
- [ ] Multi-algorithm support (RSA, ECDSA, Ed25519, Ed448)

## Architecture Notes
- **Stack**: .NET 10+, Blazor Server (InteractiveServer), FluentUI v4, PostgreSQL, BouncyCastle, Serilog
- **Location**: `examples/Sigil/` in udap-dotnet repo
- **UI patterns**: Follow TouchStoneNginxProxy and MimeScope (FluentUI v4, code-behind, dark theme)
- **Communities**: Generic PKI hierarchy separator, not tied to UDAP semantics
- **Key principle**: Import-first + generate. Support both bringing in existing PKI and creating new hierarchies.

## EJBCA Comparison Reference
EJBCA is the benchmark for feature completeness. Key differentiators for Sigil:
1. **UDAP-native** — first-class UDAP/FHIR community support (EJBCA has none)
2. **.NET ecosystem** — integrates naturally with ASP.NET Core, Duende IdentityServer
3. **Modern UI** — FluentUI vs EJBCA's JSF/PrimeFaces
4. **Lightweight** — single app vs EJBCA's JBoss/WildFly stack
5. **Developer-friendly** — designed for PKI management workflows, not just CA operations
