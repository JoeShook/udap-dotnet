# Recognized Coordinating Entity (RCE) Implementation Guide v1.12.0

> **Package**: `sequoia.fhir.us.rce#1.12.0`
> **FHIR Version**: R4 (4.0.1)
> **Status**: Active as of 2026-03-12
> **Publisher**: Recognized Coordinating Entity (RCE) — The Sequoia Project
> **Official URL**: https://sequoiaproject.org/fhir/rce/ImplementationGuide/sequoia.fhir.us.rce

---

## 1. Overview

This RCE Directory Service Implementation Guide is used by Qualified Health Information Networks (QHINs) to share identifying information of QHINs, Participants, and Subparticipants, including relevant Child entities, as part of the TEFCA (Trusted Exchange Framework and Common Agreement) ecosystem.

The RCE Directory Service is only accessible to QHINs, and is shared by QHINs to their own Participants and Subparticipants according to Section 8 of the Common Agreement.

### Dependencies

| Dependency | Package | Version |
|---|---|---|
| HL7 Terminology | `hl7.terminology.r4` | 7.1.0 |
| HL7 Extensions | `hl7.fhir.uv.extensions.r4` | 5.2.0 |
| Sequoia Healthcare Directory | `sequoia.fhir.us.sphd` | dev |
| UDAP Security | `hl7.fhir.us.udap-security` | 1.1.0 |
| US Core | `hl7.fhir.us.core` | STU4 (4.0.0) |

### Organization Hierarchy

The RCE Directory models a hierarchical structure of healthcare organizations in the TEFCA network:

```
RCE Directory
└── QHIN (Qualified Health Information Network) — top level, no parent
    ├── Participant — must be part of exactly one QHIN
    │   ├── Subparticipant — can be part of QHIN, Participant, or another Subparticipant
    │   │   ├── Subparticipant (nested)
    │   │   └── Child — leaf-level components (facilities, locations, etc.) — no endpoints
    │   └── Child
    └── Child
```

---

## 2. Specification

### 2.1 API Key

Access to the RCE Directory requires a valid API Key, unique per client and environment (VAL key cannot be used in PROD).

**Query parameter format:**
```
GET http://BASE-URL/Organization/?_apiKey=1234
```

**Authorization header format:**
```
Authorization: api-key 1234
```

Contact `techsupport@sequoiaproject.org` to obtain keys.

### 2.2 Actors

| Actor | Role | Description |
|---|---|---|
| **RCE Requestor** | Read-only client | Retrieves organization data from the RCE Directory |
| **RCE Submitter** | Write-enabled client | Supplies organization data to the RCE Directory |
| **RCE Responder** | Server | Responds to data access requests and submissions. Also called "RCE Server" or "RCE Directory" |

### 2.3 General Guidance

- All Organization profiles inherit from Sequoia Organization → US Core Organization
- **Must Support** obligations follow [US Core conformance expectations](http://hl7.org/fhir/us/core/STU4/conformance-expectations.html#must-support-elements)
- **Contained Resources**: Currently, Endpoint and Location resources are only available as contained resources within Organization (not queryable separately). However, implementers should not rely on this — check if `Organization.endpoint` starts with `#` (contained) or is a full URI (standalone reference)

---

## 3. Resource Profiles

### 3.1 RCE Organization (Abstract Base)

| | |
|---|---|
| **URL** | `https://sequoiaproject.org/fhir/rce/StructureDefinition/RCE-Organization` |
| **Base** | `SequoiaOrganization` → `US Core Organization` |
| **Abstract** | Yes — do not instantiate directly |

This abstract profile defines shared constraints for all Organization profiles in this IG.

**Key Constraints:**

| ID | Severity | Rule |
|---|---|---|
| `rce-o1` | Warning | Organizations with Purpose of Use `T-TREAT` or `T-TRTMNT` must have an NPI identifier |
| `rce-o2` | Error | Must have `Organization.type:sequoiaorgtype` of Child, Participant, Subparticipant, or QHIN |

**Key Element Requirements:**
- `identifier` — min 2 (must include TEFCAID)
- `identifier:TEFCAID` — exactly 1..1
- `telecom:phone` — max 1
- `telecom:email` — max 1
- `address` — min 1, sliced by country
- `address.text` — required, must-support
- `address.country` — required
- `address:united-states-address` — min 1, must-support; requires `city`, `state` (required binding to USPS codes), `postalCode`; `country` fixed to "US"
- `contact.purpose` — required, must-support
- `contact.name` — required, must-support
- `contact.telecom` — min 2 (must include phone + email)
- `partOf` — references `RCE-Organization`
- `endpoint` — references `RCE-Endpoint`
- `extension:organization-node-type` — must-support

**Purposes of Use** (extension on Organization): Bound to `RCEPurposeVS` (required strength). Defines purposes for which the organization initiates requests.

### 3.2 QHIN

| | |
|---|---|
| **URL** | `https://sequoiaproject.org/fhir/rce/StructureDefinition/QHIN` |
| **Base** | `RCE-Organization` |

Represents a Qualified Health Information Network. One QHIN Organization per Designated QHIN.

**Differential from RCE-Organization:**
- `type:sequoiaorgtype` — pattern: `OrganizationType#QHIN`
- `partOf` — **max 0** (QHINs are top-level, no parent)
- `contact` — min 1

### 3.3 Participant

| | |
|---|---|
| **URL** | `https://sequoiaproject.org/fhir/rce/StructureDefinition/Participant` |
| **Base** | `RCE-Organization` |

Represents a Participant as defined in the Common Agreement. Can parent Subparticipant and Child organizations.

**Differential from RCE-Organization:**
- `extension` — min 2
- `extension:org-managing-org` — min 1 (required)
- `type:sequoiaorgtype` — pattern: `OrganizationType#Participant`
- `partOf` — min 1, targets only `QHIN` (must be part of exactly one QHIN)

### 3.4 Subparticipant

| | |
|---|---|
| **URL** | `https://sequoiaproject.org/fhir/rce/StructureDefinition/SubParticipant` |
| **Base** | `RCE-Organization` |

Represents a Subparticipant as defined in the Common Agreement. Can parent Subparticipant and Child organizations.

**Differential from RCE-Organization:**
- `extension` — min 2
- `extension:org-managing-org` — min 1 (required)
- `type:sequoiaorgtype` — pattern: `OrganizationType#Subparticipant`
- `partOf` — min 1, targets `QHIN`, `Participant`, or `SubParticipant`

### 3.5 Child

| | |
|---|---|
| **URL** | `https://sequoiaproject.org/fhir/rce/StructureDefinition/Child` |
| **Base** | `RCE-Organization` |

Represents individual components (member organizations, facilities, locations) that make up a QHIN, Participant, or Subparticipant. **A Child cannot be an endpoint (node)** — it can be part of an endpoint but does not meet the definition of one.

**Differential from RCE-Organization:**
- `extension` — min 2
- `extension:org-managing-org` — min 1 (required)
- `extension:organization-node-type` — **max 0** (not allowed on Child)
- `type:sequoiaorgtype` — pattern: `OrganizationType#Child`
- `partOf` — min 1, targets `QHIN`, `Participant`, `SubParticipant`, or `Child`
- `endpoint` — **max 0** (Children cannot have endpoints)

### 3.6 RCE Endpoint

| | |
|---|---|
| **URL** | `https://sequoiaproject.org/fhir/rce/StructureDefinition/RCE-Endpoint` |
| **Base** | `SequoiaEndpoint` |

Represents endpoints provided by Organizations participating in TEFCA exchange. Endpoints can use any QTF-supported protocol (e.g., IHE XCA) and need not be FHIR endpoints.

**Differential:**
- `extension:purposesofuse` — bound to `RCEPurposeVS` (required). Defines purposes for which the endpoint will receive/respond to requests
- `managingOrganization` — references `RCE-Organization`

---

## 4. Extensions (Defined Externally)

All defined in the Sequoia Project Healthcare Directory IG:

| Extension | Used On | Description |
|---|---|---|
| **Domains** | Organization | Which Sequoia directory the org participates in (CQ, eHx, RCE) |
| **Initiator Only** | Organization | Indicates org meets an Initiator Only exception and has no Endpoints for a Use Case |
| **OrgManagingOrg** | Organization | Tied to API key access — controls which org can create/update/delete the resource |
| **Purposes of Use** | Organization, Endpoint | On Endpoint: purposes for receiving/responding. On Organization: purposes for initiating requests |
| **State of Operation** | Organization | Repeatable; each instance is a US state/province where the org operates |
| **Use Cases** | Organization | Which TEFCA Use Case(s) the org participates in |

---

## 5. Operations

### 5.1 Activate Hierarchy
- **URL**: `https://sequoiaproject.org/fhir/rce/OperationDefinition/activate-hierarchy`
- **Scope**: Instance-level on Organization
- **Description**: Sets `Organization.active = true` for the specified Organization and all descendants (via `partOf`)
- **Output**: `List` of Organizations changed

### 5.2 Deactivate Hierarchy
- **URL**: `https://sequoiaproject.org/fhir/rce/OperationDefinition/deactivate-hierarchy`
- **Scope**: Instance-level on Organization
- **Description**: Sets `Organization.active = false` for the specified Organization and all descendants (via `partOf`)
- **Output**: `List` of Organizations changed

### 5.3 Update TEFCAID
- **URL**: `https://sequoiaproject.org/fhir/rce/OperationDefinition/update-tefcaid`
- **Scope**: Instance-level on Organization
- **Description**: Updates the TEFCAID identifier for the specified Organization and all Child descendants (via `partOf`)
- **Input**: `tefcaid` (string/token) — expressed as `system|value` (e.g., `urn:ietf:rfc:3986|[uuid]`) or value only
- **Output**: `List` of Organizations changed

---

## 6. Examples

### 6.1 QHIN Example

A top-level QHIN organization with no parent (`partOf` absent).

```json
{
  "resourceType": "Organization",
  "id": "QHIN-example",
  "meta": {
    "profile": ["https://sequoiaproject.org/fhir/rce/StructureDefinition/QHIN"]
  },
  "contained": [{
    "resourceType": "Location",
    "id": "orgloc",
    "position": { "longitude": -97.7047386, "latitude": 30.4159542 }
  }],
  "extension": [
    {
      "url": "https://sequoiaproject.org/fhir/sphd/StructureDefinition/Domains",
      "valueCoding": {
        "system": "https://sequoiaproject.org/fhir/sphd/CodeSystem/Domains",
        "code": "RCE"
      }
    },
    {
      "url": "https://sequoiaproject.org/fhir/sphd/StructureDefinition/UseCases",
      "valueCodeableConcept": {
        "coding": [{
          "system": "https://sequoiaproject.org/fhir/sphd/CodeSystem/EndpointUseCaseCodes",
          "code": "QueryBasedDocumentExchange"
        }]
      }
    },
    {
      "url": "https://sequoiaproject.org/fhir/sphd/StructureDefinition/org-managing-org",
      "valueReference": { "reference": "Organization/QHIN-example" }
    }
  ],
  "identifier": [
    {
      "type": { "coding": [{ "system": "https://sequoiaproject.org/fhir/sphd/CodeSystem/SequoiaIdentifierCodes", "code": "HCID" }] },
      "system": "urn:ietf:rfc:3986",
      "value": "urn:oid:5.5.5.5"
    },
    {
      "type": { "coding": [{ "system": "https://sequoiaproject.org/fhir/sphd/CodeSystem/SequoiaIdentifierCodes", "code": "TEFCAID" }] },
      "system": "urn:ietf:rfc:3986",
      "value": "urn:oid:5.5.5.5"
    }
  ],
  "active": false,
  "type": [{ "coding": [{ "system": "https://sequoiaproject.org/fhir/sphd/CodeSystem/OrganizationType", "code": "QHIN" }] }],
  "name": "RCE QHIN Example",
  "address": [{
    "extension": [{
      "url": "https://sequoiaproject.org/fhir/sphd/StructureDefinition/OrgLocation",
      "valueReference": { "reference": "#orgloc" }
    }],
    "use": "work", "type": "both", "text": "Primary",
    "line": ["200 Main St."], "city": "Austin", "state": "TX", "postalCode": "2472", "country": "US"
  }],
  "contact": [{
    "purpose": { "coding": [{ "system": "http://terminology.hl7.org/CodeSystem/contactentity-type", "code": "ADMIN" }] },
    "name": { "use": "official", "text": "Family, Given" },
    "telecom": [
      { "system": "phone", "value": "555-555-5555", "use": "work" },
      { "system": "email", "value": "test21@test.com", "use": "work" }
    ]
  }]
}
```

### 6.2 Endpoint Example (Contained in Participant)

RCE Endpoints are typically contained resources within Organization instances:

```json
{
  "resourceType": "Endpoint",
  "id": "RCE-orgEndpoint",
  "extension": [
    {
      "url": "https://sequoiaproject.org/fhir/sphd/StructureDefinition/Transaction",
      "valueCodeableConcept": {
        "coding": [{ "system": "https://sequoiaproject.org/fhir/sphd/CodeSystem/TransactionCodes", "code": "FHIR REST" }]
      }
    },
    {
      "url": "https://sequoiaproject.org/fhir/sphd/StructureDefinition/Version",
      "valueString": "4.0.1"
    },
    {
      "url": "https://sequoiaproject.org/fhir/sphd/StructureDefinition/Roles",
      "valueCodeableConcept": {
        "coding": [{ "system": "http://snomed.info/sct", "code": "112247003" }]
      }
    }
  ],
  "status": "active",
  "connectionType": {
    "system": "https://sequoiaproject.org/fhir/sphd/CodeSystem/EndpointConnectionTypeCodes",
    "code": "hl7-fhir-rest"
  },
  "name": "FHIR REST Endpoint",
  "managingOrganization": { "reference": "Organization/1.2.3.4.5" },
  "payloadType": [{ "coding": [{ "system": "http://terminology.hl7.org/CodeSystem/endpoint-payload-type", "code": "any" }] }],
  "address": "https://example.org/fhir"
}
```

### 6.3 Hierarchy Scenario Examples

The IG includes detailed examples illustrating TEFCA network topologies described in SOP section 4.2:

**Scenario A — QHIN A (Fully Federated)**
```
QHIN A (fully federated — no centralized data, passes all transactions down)
├── Participant 1 (maintains eMPI/RLS, returns per-Subparticipant patient IDs, passes Queries down)
│   ├── Sub Z (Subparticipant — sees Document Query/Retrieval, Responds independently via XCA)
│   └── Sub Y (Subparticipant — sees Document Query/Retrieval, Responds independently via XCA)
└── Participant 2 (maintains complete clinical data repository, Responds for all Children)
    └── Sub X (Child — never sees or Responds to TEFCA transactions directly)
```

**Scenario B — QHIN B (Centralized eMPI/RLS)**
```
QHIN B (maintains eMPI/RLS, returns consolidated patient ID + aggregated doc list, passes Queries down)
└── Participant 3 (fully federated Passthrough Node, passes all transactions down)
    ├── Sub W (Subparticipant — Passthrough Node, passes all transactions to Sub U)
    │   └── Sub U (Subparticipant — sees Document Retrieval, Responds independently via XCA)
    └── Sub V (Subparticipant — sees Document Retrieval, Responds independently via XCA)
```

---

## 7. Key Code Systems & Value Sets

| Name | URL | Usage |
|---|---|---|
| OrganizationType | `https://sequoiaproject.org/fhir/sphd/CodeSystem/OrganizationType` | Values: QHIN, Participant, Subparticipant, Child |
| SequoiaIdentifierCodes | `https://sequoiaproject.org/fhir/sphd/CodeSystem/SequoiaIdentifierCodes` | Values include: HCID, TEFCAID, AAID |
| Domains | `https://sequoiaproject.org/fhir/sphd/CodeSystem/Domains` | Values: CQ, eHx, RCE |
| EndpointUseCaseCodes | `https://sequoiaproject.org/fhir/sphd/CodeSystem/EndpointUseCaseCodes` | e.g., QueryBasedDocumentExchange |
| TransactionCodes | `https://sequoiaproject.org/fhir/sphd/CodeSystem/TransactionCodes` | e.g., FHIR REST, XCA Query, XCA Retrieve |
| EndpointConnectionTypeCodes | `https://sequoiaproject.org/fhir/sphd/CodeSystem/EndpointConnectionTypeCodes` | e.g., hl7-fhir-rest |
| RCEPurposeVS | `https://sequoiaproject.org/fhir/sphd/ValueSet/RCEPurposeVS` | Required binding for PurposesOfUse extension on RCE resources |

---

## 8. Profile Inheritance Chain

```
FHIR R4 Organization
└── US Core Organization (hl7.fhir.us.core STU4)
    └── Sequoia Organization (sequoia.fhir.us.sphd)
        └── RCE Organization (abstract) ← this IG
            ├── QHIN
            ├── Participant
            ├── Subparticipant
            └── Child

FHIR R4 Endpoint
└── Sequoia Endpoint (sequoia.fhir.us.sphd)
    └── RCE Endpoint ← this IG
```

---

## 9. Change Log (Recent)

| Date | Version | Summary |
|---|---|---|
| 2026-03-12 | 1.12.0 | Updated to Sequoia base IG 1.12.0. OrganizationNodeType extension now must-support on all RCE Orgs except Child (where it's prohibited) |
| 2026-02-12 | 1.11.0 | Added constraint rce-o2: Organization.type must be Child/Participant/Subparticipant/QHIN |
| 2026-01-20 | 1.10.0 | Added constraint rce-o1: NPI required when Purpose of Use is T-TREAT or T-TRTMNT |
| 2025-12-22 | 1.9.0 | Added FHIRIGConformance extension examples, fixed typos |
| 2025-09-30 | 1.8.1 | Added 3 OperationDefinitions (Activate/Deactivate Hierarchy, Update TEFCAID). Updated examples with transaction types and endpoints |
| 2025-06-11 | 1.6.1 | Added 11 SOP 4.2 scenario examples. US address state binding changed to required |
| 2025-02-26 | 1.4.1 | Child.endpoint set to 0..0. TEFCAID made required (1..1) |
| 2023-06-30 | 1.0.0 | Initial Release |
