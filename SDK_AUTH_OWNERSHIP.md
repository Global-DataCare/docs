# SDK Auth Ownership Matrix (Frontend vs Backend)

This document defines which SDK owns each authentication and execution flow across:

- Expo/React frontend app: [apptemplate-expo54-ts](../apptemplate-expo54-ts)
- Call center backend: [uhc-unid-chat-node](../uhc-unid-chat-node)
- GW/backend orchestration: [gdc-unid-node-ts](../gdc-unid-node-ts)

## Short answer

- Frontend app (Expo/React) should use [gdc-sdk-client-ts](../gdc-sdk-client-ts).
- Backend services should use [dataspace-client-sdk-node](../dataspace-client-sdk-node).
- ICA/DataConv TS SDKs are domain SDKs and can be used for specific integrations, but are not the default SDK for call center orchestration.

Detailed frontend code examples are documented in:

- [gdc-sdk-client-ts/docs/frontend-controller-ica-smart-flow.md](../gdc-sdk-client-ts/docs/frontend-controller-ica-smart-flow.md)

Cross-SDK UC synchronization plan (memoria 5.1-5.7):

- [UC5_SDK_SYNC_PLAN.md](UC5_SDK_SYNC_PLAN.md)

## Ownership table

| Use case | Runtime | SDK owner | Why |
|---|---|---|---|
| User signs in and obtains user identity token (`id_token`) | Expo app | [gdc-sdk-client-ts](../gdc-sdk-client-ts) + app auth provider | Frontend identity/session context |
| Activation code -> initial token -> DCR device activation | Expo app | [gdc-sdk-client-ts](../gdc-sdk-client-ts) | App/device lifecycle and secure client bootstrap |
| Patient/family scoped token usage in app workflows | Expo app | [gdc-sdk-client-ts](../gdc-sdk-client-ts) | Subject context + scoped operations |
| Service-to-service token for chat/call-center backend | Node backend | [dataspace-client-sdk-node](../dataspace-client-sdk-node) | Backend identity-exchange.v1 and smart-backend.v1 |
| Family registration/search and reminder task submission from backend | Node backend | [dataspace-client-sdk-node](../dataspace-client-sdk-node) | GW async submit/poll and route helpers |
| Voice orchestration + telephony integration | Node backend | [uhc-unid-chat-node](../uhc-unid-chat-node) using [dataspace-client-sdk-node](../dataspace-client-sdk-node) | Existing architecture and env model |

## Profile boundaries

Two auth profiles must remain explicit:

- `identity-exchange.v1`: `_dcr -> _code -> _token -> _exchange`
- `smart-backend.v1`: `client_credentials + private_key_jwt`

Backend default today remains `identity-exchange.v1` unless a target endpoint explicitly requires SMART backend profile.

## Integration rule

- Do not use [dataspace-client-sdk-node](../dataspace-client-sdk-node) directly inside Expo UI code.
- Do not move frontend session/token UX concerns into call-center backend.
- Share only pure helpers/contracts across layers (payload builders, scope mapping, type models), not runtime auth clients.

## End-to-end test plan (Expo + Call Center)

### 1) Frontend app flow (apptemplate-expo54-ts)

Goal: verify frontend can obtain and use the correct token context.

1. Sign in in app and capture user `id_token`.
2. Execute activation-code exchange and DCR flow through frontend managers/services.
3. Confirm app stores active subject context (`subjectId`, `accessToken`) for the selected persona.
4. Execute one protected operation (for example family onboarding submission) and verify HTTP Authorization uses the expected token for that flow.

Reference docs:

- [apptemplate-expo54-ts/docs/frontend-guide.md](../apptemplate-expo54-ts/docs/frontend-guide.md)

### 2) Call center flow (uhc-unid-chat-node)

Goal: verify backend can authenticate and submit family/reminder operations.

1. Run backend in `SECURITY_MODE=pkce` with valid API key and signing JWK.
2. Verify `GwClientFacade` can resolve bearer token through backend auth flow.
3. Execute family search/create-or-resume from call flow.
4. Execute reminder task creation and verify task submission/poll success.

Reference implementation:

- [uhc-unid-chat-node/src/infrastructure/gw-client/GwClientFacade.ts](../uhc-unid-chat-node/src/infrastructure/gw-client/GwClientFacade.ts)

### 3) Cross-layer acceptance

1. Frontend onboarding creates/updates expected family organization data.
2. Call center can resolve and operate on the same organization context.
3. Reminder creation and downstream execution work with consistent identifiers and phones.

## Migration and refactor guidance

If you need to align Node backend with Python more strictly:

1. Keep [dataspace-client-sdk-node](../dataspace-client-sdk-node) as backend facade.
2. Introduce profile adapters behind it:
   - `IdentityExchangeAuthAdapter`
   - `SmartBackendAuthAdapter`
3. Keep frontend auth/session concerns in [gdc-sdk-client-ts](../gdc-sdk-client-ts).

This avoids coupling Expo concerns to backend orchestration while keeping parity with Python profile semantics.