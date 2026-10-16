# GlobalDataCare BFF authentication for the terminology service

This guide is for the backend that owns the GlobalDataCare OpenID issuer. It
uses the already published `NodeManagedWallet` API; it does not add token
signing to a terminology package.

## Required values

The terminology service operator supplies:

```dotenv
TERMINOLOGY_BASE_URL=https://terminology-st.connecthealth.info
TERMINOLOGY_OIDC_CLIENT_ID=globaldatacare-portal-bff
```

The service base URL is also the token audience, so no second audience variable
is required. The URL and client ID are not secrets. The BFF must also reuse its
existing issuer value (`https://globaldatacare.es`); do not duplicate it in a
Terminology-specific environment variable. Reuse the existing server-owned
`ES384` OpenID issuer wallet and its protected key; do not create a second key
or introduce a new seed specifically for Terminology.

Install exact released packages:

```bash
npm install --save-exact gdc-sdk-node-ts@2.9.31 terminology-sdk-node-ts@0.3.1
```

## Reuse the existing issuer wallet

Use the same server-only `NodeManagedWallet`, execution context and
`openid-id-token-signing` key that GlobalDataCare already uses to issue its
`ES384` SMART/GW tokens. This is not the wallet of the logged-in person,
professional or organization controller.

```ts
// src/server/terminology-identity.ts
import 'server-only';
import {
  issuer,
  issuerContext,
  issuerWallet,
  issuerWalletReady,
} from './existing-gdc-oidc-issuer';

const terminologyBaseUrl = requiredEnv('TERMINOLOGY_BASE_URL').replace(/\/+$/, '');
const clientId = requiredEnv('TERMINOLOGY_OIDC_CLIENT_ID');

export async function createTerminologyAccessToken(): Promise<string> {
  await issuerWalletReady;
  const now = Math.floor(Date.now() / 1_000);
  return issuerWallet.signCompactJws!(issuerContext, {
    header: { typ: 'at+jwt' },
    claims: {
      iss: issuer,
      sub: `service:${clientId}`,
      aud: terminologyBaseUrl,
      client_id: clientId,
      azp: clientId,
      iat: now,
      exp: now + 300,
    },
    key: {
      ownerScope: 'runtime',
      purpose: 'openid-id-token-signing',
    },
  });
}

export async function getIssuerJwks() {
  await issuerWalletReady;
  return {
    keys: (await issuerWallet.getPublicJwks(issuerContext, {
      ownerScope: 'runtime',
      purpose: 'openid-id-token-signing',
    })).map(({ publicJwk }) => publicJwk),
  };
}

function requiredEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}
```

`existing-gdc-oidc-issuer` above represents the existing GlobalDataCare module;
adapt only that import path to the BFF. The signed service token has a different
audience and claims from a user token, but it is signed by the same `ES384`
issuer key. The private key must never be committed or exposed to the browser.

## Publish the issuer metadata and JWKS

The web backend for `https://globaldatacare.es` must return JSON, not the SPA
fallback, from both endpoints.

`GET /.well-known/jwks.json`:

```ts
return Response.json(await getIssuerJwks(), {
  headers: { 'cache-control': 'public, max-age=300' },
});
```

`GET /.well-known/openid-configuration`:

```ts
return Response.json({
  issuer: 'https://globaldatacare.es',
  jwks_uri: 'https://globaldatacare.es/.well-known/jwks.json',
  id_token_signing_alg_values_supported: ['ES384'],
  subject_types_supported: ['public'],
  response_types_supported: ['id_token'],
});
```

The `issuer` must exactly match the token's `iss`, including `https://` and the
absence of a trailing slash. The JWKS must contain the public key with the same
`kid` used in the JWT header. Both URLs must answer with
`Content-Type: application/json`; a `200` response containing the portal HTML is
not valid discovery and will be rejected.

Publish the same `ES384` issuer public key already used to validate
GlobalDataCare SMART/GW tokens. Terminology does not require a separate
ML-DSA key. Do not send an existing user `id_token` to Terminology: mint a
short-lived backend access token with the Terminology audience using that same
issuer key.

SOS GW and UHC GW can either discover this `jwks_uri` from the OpenID document
or receive it explicitly in their trusted-provider entry:

```json
{
  "iss": "https://globaldatacare.es",
  "aud": "globaldatacare.es",
  "jwksUri": "https://globaldatacare.es/.well-known/jwks.json"
}
```

Their user `id_token` audience remains the audience configured for those
gateways. Do not use the terminology audience for a GW login token.

## Supply fresh tokens to the terminology client

```ts
// src/server/terminology.ts
import 'server-only';
import {
  MemoryTerminologyCache,
  TerminologyClient,
} from 'terminology-sdk-node-ts/terminology-client';
import { createTerminologyAccessToken } from './terminology-identity';

export const terminology = new TerminologyClient({
  baseUrl: requiredEnv('TERMINOLOGY_BASE_URL').replace(/\/+$/, ''),
  accessTokenProvider: createTerminologyAccessToken,
  cache: new MemoryTerminologyCache({ maxEntries: 2_000 }),
  candidateTtlMs: 5 * 60_000,
  stableTtlMs: 24 * 60 * 60_000,
});
```

`TerminologyClient` obtains the access token only for an uncached request and
sends it as `Authorization: Bearer ...`. React never receives the wallet, seed
or access token.

## Connect the portal screen and Research

After creating the singleton above, copy the canonical product-neutral
examples from these sections:

- BFF route that calls `searchCodeCandidatesFromText(...)` when the user presses
  Search:
  https://github.com/Global-DataCare/terminology-sdk-node-ts/blob/main/docs/NEXTJS_BFF_INTEGRATION.md#search-candidates-when-the-user-presses-search
- Reusable React component that renders the candidates and returns the selected
  `system|code`:
  https://github.com/Global-DataCare/terminology-sdk-node-ts/blob/main/docs/NEXTJS_BFF_INTEGRATION.md#reusable-react-code-search-component
- The same component used in a Research query builder:
  https://github.com/Global-DataCare/terminology-sdk-node-ts/blob/main/docs/NEXTJS_BFF_INTEGRATION.md#use-the-same-component-in-research
- Governed ValueSet dropdown with every valid option:
  https://github.com/Global-DataCare/terminology-sdk-node-ts/blob/main/docs/NEXTJS_BFF_INTEGRATION.md#populate-a-dropdown-from-the-governed-valueset

Both clinical data entry and the Research query builder call the same
authenticated BFF candidate route. The user must select one intended
`system|code`; only that selected pair is submitted to the create operation or
to the exact Research filter. Do not submit all returned candidates as an
implicit OR query.

For an intentionally free-text Research search, query the indexed English
`code-display` and the localized `code-text` instead. The code picker can then
be offered as an explicit refinement to an exact `system|code` filter.

The terminology service configures the corresponding trusted provider:

```json
[
  {
    "iss": "https://globaldatacare.es",
    "aud": "https://terminology-st.connecthealth.info",
    "jwksUri": "https://globaldatacare.es/.well-known/jwks.json",
    "clientIds": ["globaldatacare-portal-bff"],
    "algorithms": ["ES384"]
  }
]
```

The terminology staging deployment trusts that exact issuer, audience, client
ID, JWKS URL and `ES384` algorithm. GlobalDataCare must publish the two JSON
well-known endpoints from its existing issuer implementation and add the
Terminology-specific token minting call. No new wallet, ML-DSA key or shared
static terminology token is required.

## Acceptance check

Before calling the terminology routes, verify that the well-known endpoints
return JSON:

```bash
curl --fail --show-error https://globaldatacare.es/.well-known/jwks.json
curl --fail --show-error https://globaldatacare.es/.well-known/openid-configuration
```

Then mint one five-minute `at+jwt` using `createTerminologyAccessToken()` and
call:

```http
GET https://terminology-st.connecthealth.info/v1/terminology/capabilities?sector=<authorized-sector>&jurisdiction=<authorized-jurisdiction>
Authorization: Bearer <server-generated-token>
```

Acceptance is `200`. A missing bearer must remain `401`. Do not print the seed
or token in build logs.

The canonical wallet API and issuer-publication explanation remain in
[`gdc-sdk-node-ts/docs/101-SDK_END_TO_END.md`](https://github.com/Global-DataCare/gdc-sdk-node-ts/blob/main/docs/101-SDK_END_TO_END.md#two-proofs-are-required-and-they-are-not-interchangeable).
