# Portal Individual Controller Flow 101

## Purpose

This document explains, in simple terms, how a web portal should interact with GW CORE when an authenticated human needs to work with individual-controlled data.

It is intentionally written for frontend and integration developers, not for backend maintainers.

## The important distinction

There are two very different things in the current codebase:

1. The recommended portal-oriented SDK flow.
2. Older compatibility logic for legacy family/individual registration.

Do not treat the legacy compatibility payload status fields as the canonical web contract for new portal work.

In particular:

- `OperationOutcome` is the correct structured mechanism for request validation failures, business-rule failures, and unsupported operations.
- Legacy fields such as `org.schema.FamilyRegistration.status = already_exists | not_found` are compatibility behavior from an older flow and should not be documented as the new portal contract.

## What the portal should do

For a portal, the right mental model is:

1. The user authenticates with the portal identity provider.
2. The portal initializes a profile-scoped SDK session.
3. The portal uses role-gated services from that session.
4. The portal works with subject bootstrap, indexing, consent, and SMART token flows.
5. If the portal needs a new "list all individuals I control or belong to" feature, that must be defined explicitly as a new contract.

Today, the SDK surface already supports:

- subject organization bootstrap,
- clinical import and indexing,
- consent creation,
- SMART token retrieval,
- digital twin generation.

Today, the SDK surface does not expose a public portal method like:

- `listControlledIndividuals()`
- `searchIndividualsByControllerPhone()`
- `listMembershipsByRole()`

So if the portal requirement is exactly:

- "show all individuals for whom the logged-in actor is a controller"
- and "show all individuals for whom the actor is a member under other roles, not only responsible party"

then that should be documented as a new GW CORE contract, not retrofitted from the old family registration compatibility path.

## Recommended portal flow

### Step 1: Initialize the SDK session

The portal creates a `ClientSDK` instance and initializes a profile-scoped session.

Relevant runtime surface:

- `gdc-sdk-front-ts`
- `gdc-sdk-client-ts`

Typical entry point:

```ts
import { ClientSDK } from 'gdc-sdk-client-ts';

const sdk = new ClientSDK(sdkConfig, appInfo, wallet, verifierService, icaDid);
const manager = await sdk.initializeSession(initParams, createVaultForProfile);
```

After initialization, the portal uses the returned session manager.

Depending on the resolved profile role, the manager exposes:

- `familyAdmin`
- `individual`
- `orgAdmin`
- `professional`

For an individual-controller style portal flow, the role mapping currently enables family/individual services when the role resolves as controller, including `RESPRSN`.

## Step 2: Bootstrap the subject organization context

The current SDK wrapper for this is:

- `ProfileManager.bootstrapSubjectOrganizationIndex(...)`

This is the current high-level method the portal should call when it needs to establish or resume the hosted personal-organization context.

Example:

```ts
await manager.bootstrapSubjectOrganizationIndex({
  providerDid: 'did:web:api-provider.example.com',
  idToken: userIdToken,
  registrationClaims: {
    '@context': 'org.schema',
    'org.schema.Person.telephone': '+34600111222',
    'org.schema.Person.alternateName': 'ana',
  },
  acceptedOfferId: 'urn:offer:123', // optional
});
```

What this gives the portal:

- a registration submission thread id,
- optionally an order confirmation thread id.

What it does not give the portal:

- a canonical "list all individuals I control" response.

That feature does not exist yet as a dedicated portal API.

## Step 3: Import subject clinical data and update the index

Once the subject context exists, the portal can ingest IPS or FHIR data.

Current wrapper:

- `ProfileManager.importIpsOrFhirAndUpdateIndex(...)`

Example:

```ts
await manager.importIpsOrFhirAndUpdateIndex({
  compositionPayload: {
    '@context': 'org.hl7.fhir.r4',
    'Composition.status': 'final',
  },
  providerDid: 'did:web:api-provider.example.com',
  requiredScope: 'organization/Composition.cruds',
  idToken: userIdToken,
  format: 'org.hl7.fhir.r4',
});
```

This is part of the supported portal path today.

## Step 4: Grant access through consent

If the portal needs to authorize another actor to access subject data, the supported path is consent-first, then SMART token.

Current wrapper:

- `ProfileManager.grantProfessionalAccessSimple(...)`

Example:

```ts
await manager.grantProfessionalAccessSimple({
  subjectPhone: '+34600111222',
  subjectGivenName: 'Ana',
  actor: { didWeb: 'did:web:hospital.example.com' },
  actorRole: 'Practitioner',
  purpose: 'TREAT',
  actions: ['LOINC|48765-2'],
  providerDid: 'did:web:api-provider.example.com',
  requiredScope: 'organization/Consent.cruds',
  idToken: userIdToken,
});
```

Important:

- In the current shared contracts, phone-oriented subject targeting is treated as a compatibility or extension concern.
- The more stable canonical identifier is the subject DID when available.

## Step 5: Retrieve SMART token separately

Consent creation and runtime access token issuance are separate steps.

The portal should not collapse them into one undocumented shortcut.

The expected model is:

1. Write consent or policy intent.
2. Request runtime SMART scopes.
3. Receive only the scopes compatible with active consent policy.

## Where `OperationOutcome` belongs

For portal developers, the rule is simple:

- if the request is malformed,
- if required claims are missing,
- if the operation is not supported,
- if a business rule rejects the operation,

then the server should respond with a structured error using `OperationOutcome`.

This is the correct place for outcomes such as:

- missing required inputs,
- invalid role format,
- unsupported route or action,
- authorization failure,
- unresolved target entity,
- invalid order or consent request.

This is not the place to encode normal portal state transitions as ad hoc compatibility flags unless the route is explicitly documented as a legacy compatibility endpoint.

## What not to document as the new portal pattern

Do not present the following as the new GW CORE contract for portal developers:

- `org.schema.FamilyRegistration.status = already_exists`
- `org.schema.FamilyRegistration.status = not_found`
- old lookup semantics based on `owner.telephone + alternateName`
- old family-registration compatibility payloads as the primary "search my individuals" API

Those behaviors may still exist in legacy backend code, but they are not the right abstraction for a new portal-facing controller-membership flow.

## Current gap that must be designed explicitly

If the product requirement is:

- the logged-in user must retrieve all individuals they control,
- and also all individuals where they participate under other roles,

then GW CORE still needs an explicit contract for that.

That contract should define:

1. The authenticated actor identifier source.
2. The resource being searched.
3. The membership model.
4. The role filter model.
5. The success response shape.
6. The error model based on `OperationOutcome`.

## Suggested contract shape for the new portal feature

This is not implemented yet, but this is the level of explicitness the portal needs.

Example intent:

```ts
type ListMyIndividualsInput = {
  includeControllerRoles?: boolean;
  includeMemberRoles?: boolean;
  roleFilter?: string[];
  page?: { cursor?: string; limit?: number };
};

type ListMyIndividualsResult = {
  items: Array<{
    subjectDid: string;
    subjectDisplayName?: string;
    relationshipType?: 'controller' | 'member';
    role?: string;
    source?: 'membership' | 'related-person' | 'consent' | 'materialized-index';
  }>;
  nextCursor?: string;
};
```

Whether the backend derives this from:

- `RelatedPerson`,
- member records,
- consent state,
- relationship index documents,
- or a materialized portal-facing view,

is an implementation decision.

But the portal should receive a clean contract like this, not legacy family-registration status flags.

## Current code references

High-level portal wrappers:

- [gdc-sdk-client-ts/src/ProfileManager.ts](/Users/fernando/GITS/gdc-workspace/gdc-sdk-client-ts/src/ProfileManager.ts:184)
- [gdc-sdk-client-ts/src/frontend-services/family-admin/FamilyAdminService.ts](/Users/fernando/GITS/gdc-workspace/gdc-sdk-client-ts/src/frontend-services/family-admin/FamilyAdminService.ts:141)
- [gdc-sdk-front-ts/src/ProfileManager.ts](/Users/fernando/GITS/gdc-workspace/gdc-sdk-front-ts/src/ProfileManager.ts:58)

Role mapping for controller-like profiles:

- [gdc-sdk-front-ts/src/capabilityMapper.ts](/Users/fernando/GITS/gdc-workspace/gdc-sdk-front-ts/src/capabilityMapper.ts:24)

Developer cookbook examples already aligned with portal usage:

- [gdc-sdk-client-ts/docs/DEVELOPER_USE_CASES.md](/Users/fernando/GITS/gdc-workspace/gdc-sdk-client-ts/docs/DEVELOPER_USE_CASES.md:1)

Canonical bundle and error model:

- [gdc-common-utils-ts/src/models/bundle.ts](/Users/fernando/GITS/gdc-workspace/gdc-common-utils-ts/src/models/bundle.ts:1)

Legacy compatibility code that should not be treated as the new portal contract:

- [gdc-unid-node-ts/src/managers/FamilyManager.ts](/Users/fernando/GITS/gdc-workspace/gdc-unid-node-ts/src/managers/FamilyManager.ts:431)
- [gdc-unid-node-ts/src/managers/HostingManager.ts](/Users/fernando/GITS/gdc-workspace/gdc-unid-node-ts/src/managers/HostingManager.ts:939)
