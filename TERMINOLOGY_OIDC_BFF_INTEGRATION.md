# GlobalDataCare BFF authentication for the terminology service

This guide is for the backend that owns the GlobalDataCare OpenID issuer. It
uses the already published `NodeManagedWallet` API; it does not add token
signing to a terminology package.

## Required values

The terminology service operator supplies:

```dotenv
TERMINOLOGY_BASE_URL=https://terminology.example
TERMINOLOGY_OIDC_AUDIENCE=https://terminology.example
TERMINOLOGY_OIDC_CLIENT_ID=globaldatacare-portal-bff
```

The issuer configuration is:

```dotenv
GDC_OIDC_ISSUER=https://globaldatacare.es
GDC_OIDC_ISSUER_SEED=<secret-manager-reference>
```

The audience and client ID are not secrets. The issuer seed is a server-only
secret and must remain in KMS or the hosting platform's secret manager.

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
const audience = requiredEnv('TERMINOLOGY_OIDC_AUDIENCE');
const clientId = requiredEnv('TERMINOLOGY_OIDC_CLIENT_ID');
const issuerSeed = requiredEnv('GDC_OIDC_ISSUER_SEED');

const issuerContext = {
  runtime: {
    runtimeId: 'globaldatacare-oidc-issuer',
    runtimeType: 'web-bff',
  },
} as const;

const issuerWallet = new NodeManagedWallet();
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
      aud: audience,
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
  id_token_signing_alg_values_supported: ['ES384'],
  subject_types_supported: ['public'],
  response_types_supported: ['id_token'],
});
```

The `issuer` must exactly match the token's `iss`, including `https://` and the
absence of a trailing slash. The JWKS must contain the public key with the same
`kid` used in the JWT header.

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
  baseUrl: requiredEnv('TERMINOLOGY_BASE_URL'),
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
    "aud": "https://terminology.example",
    "jwksUri": "https://globaldatacare.es/.well-known/jwks.json",
    "clientIds": ["globaldatacare-portal-bff"],
    "algorithms": ["ES384"]
  }
]
```

This JSON becomes `TERMINOLOGY_TRUSTED_OIDC_PROVIDERS_JSON` in the terminology
API deployment. The concrete service URL, audience and assigned client ID must
come from the operator; do not copy the example hostnames into production.

The canonical wallet API and issuer-publication explanation remain in
[`gdc-sdk-node-ts/docs/101-SDK_END_TO_END.md`](https://github.com/Global-DataCare/gdc-sdk-node-ts/blob/main/docs/101-SDK_END_TO_END.md#two-proofs-are-required-and-they-are-not-interchangeable).
