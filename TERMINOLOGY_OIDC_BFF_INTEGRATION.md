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

The issuer configuration is:

```dotenv
GDC_OIDC_ISSUER=https://globaldatacare.es
GDC_OIDC_ISSUER_SEED=<secret-manager-reference>
```

The service base URL is also the token audience, so no second audience variable
is required. The URL and client ID are not secrets. The issuer seed is a
server-only secret and must remain in KMS or the hosting platform's secret
manager.

Install exact released packages:

```bash
npm install --save-exact gdc-sdk-node-ts@2.9.31 terminology-sdk-node-ts@0.3.1
```

## Provision the issuer wallet once

Create one server-only singleton. This is the OpenID issuer wallet, not the
wallet of the logged-in person, professional or organization controller.

```ts
// src/server/terminology-identity.ts
import 'server-only';
import { NodeManagedWallet } from 'gdc-sdk-node-ts';

const issuer = requiredEnv('GDC_OIDC_ISSUER');
const terminologyBaseUrl = requiredEnv('TERMINOLOGY_BASE_URL').replace(/\/+$/, '');
const clientId = requiredEnv('TERMINOLOGY_OIDC_CLIENT_ID');
const issuerSeed = requiredEnv('GDC_OIDC_ISSUER_SEED');

const issuerContext = {
  runtime: {
    runtimeId: 'globaldatacare-oidc-issuer',
    runtimeType: 'web-bff',
  },
} as const;

const issuerWallet = new NodeManagedWallet({
  policy: { defaults: { 'openid-id-token-signing': 'ML-DSA-44' } },
});
const ready = issuerWallet.provisionManagedKeys(issuerContext, {
  ownerScope: 'runtime',
  purposes: ['openid-id-token-signing'],
  seedMaterial: issuerSeed,
  mode: 'deterministic',
});

export async function createTerminologyAccessToken(): Promise<string> {
  await ready;
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
  await ready;
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

In production, prefer a KMS/HSM-backed wallet adapter. A deterministic seed is
shown because it is supported by the released package, but the seed must never
be committed or exposed to the browser.

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
  id_token_signing_alg_values_supported: ['ML-DSA-44'],
  subject_types_supported: ['public'],
  response_types_supported: ['id_token'],
});
```

The `issuer` must exactly match the token's `iss`, including `https://` and the
absence of a trailing slash. The JWKS must contain the public key with the same
`kid` used in the JWT header. Both URLs must answer with
`Content-Type: application/json`; a `200` response containing the portal HTML is
not valid discovery and will be rejected.

This ML-DSA key is the BFF service identity used only for BFF-to-Terminology
calls. Existing ES384 keys and tokens required by SMART on FHIR, SHC or a GW
user-login profile remain separate and do not need to change.

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

The terminology service configures the corresponding trusted provider:

```json
[
  {
    "iss": "https://globaldatacare.es",
    "aud": "https://terminology-st.connecthealth.info",
    "jwksUri": "https://globaldatacare.es/.well-known/jwks.json",
    "clientIds": ["globaldatacare-portal-bff"],
    "algorithms": ["ML-DSA-44"]
  }
]
```

The terminology staging deployment already trusts that exact issuer, audience,
client ID, JWKS URL and algorithm. GlobalDataCare must now publish the two JSON
well-known endpoints and deploy its BFF wallet. No shared static terminology
token is required after that succeeds.

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
