---
name: fhir-ig-to-ai
description: Convert a FHIR Implementation Guide full zip download into a single AI-friendly markdown document
argument-hint: <path-to-full-ig.zip> [output-directory]
---

# Convert FHIR IG to AI-Friendly Markdown

Convert the FHIR Implementation Guide zip file at `$ARGUMENTS` into a single, consolidated, AI-optimized markdown document.

If only one argument is provided, it is the zip file path and the output will be placed in the same directory as the zip file. If two arguments are provided, the second is the output directory.

## Step 1: Extract and Discover

1. Extract the zip file to a temporary directory (`_ig_extract_temp/` next to the zip)
2. Look for `site/ai.zip` inside (the IG publisher generates this) — if found, extract it to `_ig_extract_temp/ai/`
3. If no `ai.zip`, fall back to collecting `.md` files from `site/`
4. Look for the ImplementationGuide JSON resource to extract metadata:
   - Check for `ImplementationGuide-*.json` in the site root
   - Or parse `site/index.md` or `site/index.html` for the IG metadata
5. Extract these metadata fields:
   - **IG Title** (e.g., "Recognized Coordinating Entity (RCE) Implementation Guide")
   - **Package ID** (e.g., `sequoia.fhir.us.rce`)
   - **Version** (e.g., `1.12.0`)
   - **FHIR Version** (e.g., `4.0.1`)
   - **Status** (e.g., `active`)
   - **Publisher**
   - **Official URL**
   - **Dependencies** (other IGs it depends on)

## Step 2: Read and Categorize Content

Read all the markdown files and categorize them:

- **Narrative pages**: `index.md`, specification pages, change logs — these contain the human-readable guidance
- **StructureDefinition profiles**: Files named `StructureDefinition-*.md` — contain profile constraints as prose + JSON
- **OperationDefinition**: Files named `OperationDefinition-*.md` — custom operations
- **Example instances**: Files named with resource types like `Organization-*.md`, `Endpoint-*.md`, `Patient-*.md`, etc. — example resource instances
- **CodeSystem/ValueSet**: Files describing terminologies
- **CapabilityStatement**: Files describing server capabilities
- **Other artifacts**: SearchParameters, ConceptMaps, etc.

## Step 3: Build the Consolidated Document

Create a SINGLE markdown file with this structure. The goal is to be **information-dense but readable** for an AI model consuming it in a context window:

### Output Filename Convention

Use this pattern: `{short-ig-name}-v{version}-ai-friendly.md`

- Derive the short name from the package ID (last segment) or IG title
- Examples: `rce-ig-v1.12.0-ai-friendly.md`, `us-core-v6.1.0-ai-friendly.md`, `udap-security-v1.1.0-ai-friendly.md`

### Document Structure

```markdown
# {IG Title} v{Version}

> **Package**: `{packageId}#{version}`
> **FHIR Version**: {fhirVersion}
> **Status**: {status} as of {date}
> **Publisher**: {publisher}
> **Official URL**: {url}

---

## 1. Overview
{Content from index.md / introduction — the narrative overview, stripped of navigation boilerplate}

### Dependencies
{Table of IG dependencies with package IDs and versions}

## 2. Specification
{Content from specification/guidance pages — the normative text about actors, API details, general guidance}
{Strip navigation boilerplate like TOC links, "Formal Views" references, CSV/Excel/Schematron links}

## 3. Resource Profiles
{For each StructureDefinition profile:}
### 3.N {Profile Title}
| | |
|---|---|
| **URL** | `{canonical URL}` |
| **Base** | `{base profile name}` |

{Description paragraph}

**Key Constraints:**
{Table of invariants with ID, severity, human-readable description}

**Key Element Requirements:**
{Bullet list of important differential elements with cardinalities, must-support flags, bindings, fixed values}
{Focus on WHAT IS DIFFERENT from the base — the differential, not the full snapshot}

{Do NOT include the full raw JSON StructureDefinition — it's too verbose for AI consumption.
DO preserve: constraint expressions, binding strengths/valuesets, cardinality changes, pattern values, slicing details}

## 4. Extensions
{Table of extensions with name, used-on, and description}
{If extensions are defined externally, note where they come from}

## 5. Terminology
{Tables of CodeSystems and ValueSets with URLs and key codes}

## 6. Operations
{For each OperationDefinition: name, URL, scope, description, parameters (in/out)}

## 7. Capability Statements
{If present: server/client capabilities}

## 8. Examples
{Include 1-2 representative examples per profile in full JSON}
{For large sets of similar examples (like 16 Organization examples), include just the most illustrative ones
and summarize the rest in prose or ASCII diagrams showing the relationships}

## 9. Profile Inheritance Chain
{ASCII diagram showing the inheritance hierarchy}

## 10. Change Log
{Recent changes in compact table format — date, version, summary}
```

### Consolidation Rules

1. **Strip navigation boilerplate**: Remove TOC links, "Table of Contents" bullet points, breadcrumbs, "Formal Views of Profile Content" sections, links to CSV/Excel/Schematron representations
2. **Strip verbose metadata**: Remove FHIR mapping blocks (v2, RIM, ServD, FiveWs), publisher contact details from JSON, `date` fields in JSON
3. **Distill StructureDefinitions**: Convert raw JSON differentials into human-readable tables/bullet lists. Preserve the semantic content (constraints, cardinalities, bindings, patterns) but not the JSON boilerplate
4. **Deduplicate examples**: If many examples follow the same pattern, include 1-2 representative ones and describe the rest
5. **Add visual aids**: Create ASCII hierarchy diagrams for profile inheritance and organizational relationships where helpful
6. **Preserve all normative content**: Constraint expressions (FHIRPath), binding strengths, cardinality changes, invariant rules, API details, search parameters — these must be kept accurately
7. **Keep canonical URLs**: All StructureDefinition, ValueSet, CodeSystem, and Extension URLs must be preserved exactly as they appear

## Step 4: Write Output and Clean Up

1. Write the consolidated markdown file to the output directory using the naming convention above
2. Remove the temporary extraction directory (`_ig_extract_temp/`)
3. Report to the user:
   - The output file path and size
   - How many source files were consolidated
   - A brief summary of what the IG covers

## Important Notes

- This is a FHIR IG conversion tool — the input is always a zip file downloaded from a FHIR IG publication
- The IG publisher (by HL7) generates a standard directory structure, so the patterns above should work for most IGs
- If the zip doesn't contain `site/` at the top level, look for the content directly in the root
- CRLF line endings must be preserved (this is a Windows repository)
- Do not create any files other than the single output markdown
