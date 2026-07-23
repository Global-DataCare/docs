# UC5 Sync Plan: Frontend + Node + Python

Status: proposed canonical plan for memoria use cases 5.1-5.7.

Objective:

1. Stop exposing fragmented ICA/GW flows directly to product teams.
2. Expose the same business use cases through:
   - gdc-sdk-client-ts (frontend)
   - dataspace-client-sdk-node (backend node)
   - connector-sdk-py (backend python)
3. Keep method-level parity and behavior parity.

## Why this exists

Today, onboarding and trust artifacts are split across:

- ICA verification and VC extraction
- GW activation and runtime authorization
- DataConv/digital twin operations

This is technically valid, but hard to understand at product level when not wrapped as UC-oriented methods.

## Canonical UC chain (5.1-5.7)

1. UC 5.2: legal organization onboarding identity proof
   - signed terms/evidence verified in ICA
   - Organization VC and Legal Representative VC issued
2. UC 5.2: organization activation in GW
   - Organization VC is presented via VP to activate tenant
3. UC 5.3: create organization employees
   - employee records and role assignments
4. UC 5.4: employee device activation
   - activation code -> token exchange -> DCR -> device client id
5. UC 5.1: create subject organization index context
   - subject/manager identity + consent baseline + index bootstrap
6. UC 5.5: manager imports IPS/FHIR and creates medication/clinical updates
   - manager obtains SMART token with scoped permissions
7. UC 5.6: manager grants access to doctor (or another employee)
   - consent/policy updated, doctor obtains SMART token for allowed scope
8. UC 5.7: manager triggers DataConv digital twin pipeline
   - gated by prior trust/authorization/evidence checks

## Compliance gate for Organization VC (Spain veterinary/health)

Policy requirement to encode in wrappers:

1. Before enabling organization activation, the flow must include regulatory evidence verification for sector-specific registration (for example veterinary license or health registration in Spain).
2. Verification result must be bound to Organization VC claims (or linked evidence claim set) before VP submission to GW activation.
3. If regulatory evidence is missing or invalid, wrappers must fail closed and prevent:
   - sensitive data creation,
   - outbound notifications to protected contexts,
   - digital twin generation from protected datasets.

This gate belongs to business wrappers, not to ad-hoc UI checks.

## DCR in GW: yes, but at the right step

Clarification:

1. GW organization activation via VC/VP is one step (tenant activation/trust bootstrap).
2. Device DCR is another step (employee/member runtime client registration).
3. Do not merge both mentally into one call. They are sequential and serve different trust layers.

## Wrapper parity matrix by UC

Legend:

- available: already wrapped in an SDK service API
- partial: low-level route/helpers exist but no UC-level wrapper
- missing: no usable wrapper for product teams

| UC | gdc-sdk-client-ts | dataspace-client-sdk-node | connector-sdk-py |
|---|---|---|---|
| 5.2 ICA verify -> Organization VC | partial (current guide uses ica-client-sdk-ts directly) | partial (domain path helpers, no UC facade) | partial (ICA service methods exist, not UC facade) |
| 5.2 GW activate with VP | missing (no first-class UC wrapper) | partial (hostRegistryOrganizationActivatePath exists) | partial (can call routes/services, no UC facade) |
| 5.3 create employees | partial (services exist in org admin area) | partial (employee batch route available) | partial |
| 5.4 activation code + DCR | available (CommonAuthService.activateDevice) | partial (identity auth orchestration present, not employee UX wrapper) | partial (auth operations available) |
| 5.1 subject organization bootstrap | partial (individual/family service primitives exist) | partial (family search/create helpers exist) | partial |
| 5.5 import IPS/FHIR with SMART | partial (getSmartToken available, domain wrappers incomplete) | partial (task/composition/communication routes available) | partial |
| 5.6 delegated doctor access + SMART | partial (consent models/scope builders available) | partial | partial |
| 5.7 DataConv digital twin | missing in frontend UC facade | partial (conversion + digital twin routes exist) | partial (dataconv + auth services exist) |

## Mandatory synchronized method surface (target)

Each SDK should expose equivalent UC methods (names can vary, behavior must match):

1. verifyOrganizationEvidenceAndIssueVc(...)
2. activateOrganizationInGatewayFromIcaProof(...)
3. createOrganizationEmployee(...)
4. activateEmployeeDeviceWithActivationCode(...)
5. bootstrapSubjectOrganizationIndex(...)
6. importIpsOrFhirAndUpdateIndex(...)
7. grantProfessionalAccessAndIssueScopes(...)
8. generateDigitalTwinFromSubjectData(...)

Each method must define:

1. required inputs
2. required auth profile
3. async submit/poll behavior
4. blocking conditions
5. output contract

## Portal web and chat node immediate implementation order

Priority A (needed now):

1. UC 5.2 wrapper pair
   - verify/evidence/VC
   - GW activate with VP
2. UC 5.3 and 5.4 wrappers
   - employee creation
   - device activation and DCR result parsing
3. UC 5.1 and 5.5 baseline wrappers
   - subject org bootstrap
   - SMART token + IPS/FHIR import path

Priority B (next):

1. UC 5.6 delegated professional access
2. UC 5.7 digital twin wrapper with strict gates

## Governance rule for future changes

Any SDK PR touching these UCs must include:

1. parity update in this file,
2. tests that assert equivalent behavior in at least two SDKs,
3. explicit migration note if signatures or semantics change.