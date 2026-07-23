# INTEGRATORS GUIDE - ICA `_verify` API (ES)

Guia de integracion para el flujo asincrono de verificacion de terminos PDF firmados digitalmente.

Para operativa CLI ICA (onboarding, CSR, DCAT), ver:
[`CLI_OPERATIONS_RUNBOOK.md`](./CLI_OPERATIONS_RUNBOOK.md)

## 0) Resumen del contrato vigente

- `_verify` acepta solo DIDComm plaintext JSON (`Content-Type: application/didcomm-plain+json`).
- El PDF se envia dentro de `attachments[].data.base64` (o `attachments[].data.links`).
- `_verify` no admite `multipart/form-data`, `application/json` plano ni binario directo.
- Polling asincrono por `_verify-response`.
- `_activate` (credentials) acepta DIDComm con `body.key` (1 clave) o `body.data[]` (N claves).
- Respuesta final de negocio (`200`) y errores tempranos (`4xx/5xx`) salen en DIDComm uniforme:
  - header HTTP: `Content-Type: application/didcomm-plain+json`
  - mensaje DIDComm: `type: "application/bundle-api+json"`
  - `body` con `Bundle` + `issues` (`OperationOutcome`)

## 1) Operacion local (dev)

Scripts recomendados:

- `npm run dev`
- `npm run api:dev` (watch)

Ambos scripts cargan `.env.local` automaticamente si existe.

Arranque local recomendado:

```bash
cp .env.local.example .env.local
npm run dev
```

Variables utiles para plantilla de terminos:

- `ICA_TERMS_TEMPLATE_URL_PATTERN`
  Ejemplo:
  `https://raw.githubusercontent.com/Global-DataCare/terms/refs/heads/main/dataspace/{sector}/{jurisdictionLower}/{resourceVersion}/terms.pdf`
- `ICA_ALLOW_TEST_RESOURCE_TYPE_PREFIX=true` para aceptar `resourceType=test-...` en API
- `ICA_TERMS_TEMPLATE_USE_TEST_PREFIX=true` para resolver plantilla con prefijo `test-...` en dev/test
- `ICA_TERMS_ACTIVE_RESOURCE_TYPES` (CSV) para controlar versiones activas
- `ICA_TERMS_TEMPLATE_CACHE_TTL_SECONDS` y `ICA_TERMS_TEMPLATE_CACHE_MAX_ENTRIES`
- `ICA_TERMS_TEMPLATE_PRELOAD_ENABLED` + `ICA_TERMS_TEMPLATE_PRELOAD_RESOURCE_TYPES`

## 2) Variables de prueba

```bash
BASE="http://localhost:3310"
TENANT="ica"
JUR="ES"
SECTOR="animal-care"
VERSION="202603051133"
THID="verify-terms-001"
PDF_FILE="$HOME/Documents/TEST-A4-signed-fnmt.pdf"
```

Comprobaciones rapidas:

```bash
curl -sS "$BASE/" | jq .
curl -sS "$BASE/openapi.json" | jq '.openapi, (.paths|keys)'
curl -sS "$BASE/openapi.json" | jq '.paths["/{tenantId}/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_activate"].post.requestBody.content["application/didcomm-plain+json"].schema.properties.body.properties | keys'
test -f "$PDF_FILE" && echo "OK: $PDF_FILE" || echo "MISSING: $PDF_FILE"
```

Si la salida anterior no incluye `"data"`, estas ejecutando una instancia antigua (reinicia el proceso de la API).

## 2.1 Endpoint `_activate` (credentials keys)

Patron:

```text
POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_activate
```

Request DIDComm (`application/didcomm-plain+json`) con multiples claves:

```json
{
  "jti": "activate-req-002",
  "thid": "activate-signing-key-002",
  "type": "https://globaldatacare.es/didcomm/ica/signing-keys/activate-request/v1",
  "body": {
    "data": [
      {
        "key": {
          "kid": "ica-es384-20260305",
          "alg": "ES384",
          "privateKeyPem": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
        }
      },
      {
        "key": {
          "kid": "ica-es256k-20260305",
          "alg": "ES256K",
          "privateKeyPem": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
        }
      }
    ]
  }
}
```

Compatibilidad: `body.key` (clave unica) sigue soportado.

## 3) Endpoint de envio (`_verify`)

Patron:

```text
POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/terms/pdf/{resourceType}/_verify
```

Restricciones de ruta:

- `sector`: `animal-care` o `health-care`
- `resourceType` produccion: `yyyyddmmhhmm` (12 digitos)
- `resourceType` pruebas: `test-yyyyddmmhhmm` (requiere `ICA_ALLOW_TEST_RESOURCE_TYPE_PREFIX=true`)
- opcional: allowlist de versiones activas con `ICA_TERMS_ACTIVE_RESOURCE_TYPES`
- `format`: `pdf`
- `section`: `terms`

Nota ICA monotenant:

- `tenantId` es namespace de ruta por compatibilidad del patron, no el `alternateName` de la organizacion firmante.
- Para esta ICA usa `tenantId=ica` y configura `ICA_LOCAL_TENANT_ID=ica`.
- La identidad de organizacion y representante se obtiene del certificado embebido en la firma del PDF.

### 3.1 Request DIDComm plaintext (`application/didcomm-plain+json`)

```bash
PDF_B64=$(base64 < "$PDF_FILE" | tr -d '\n')

curl -i -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/terms/pdf/$VERSION/_verify" \
  -H "Content-Type: application/didcomm-plain+json" \
  -d "{
    \"jti\":\"msg-$THID\",
    \"thid\":\"$THID\",
    \"type\":\"https://globaldatacare.es/didcomm/ica/terms/verify-request/v1\",
    \"meta\":{
      \"jws\":{
        \"protected\":{
          \"alg\":\"ES384\",
          \"kid\":\"controller-es384-001\",
          \"jwk\":{\"kty\":\"EC\",\"crv\":\"P-384\",\"x\":\"<controller-x>\",\"y\":\"<controller-y>\"}
        }
      }
    },
    \"attachments\":[
      {
        \"id\":\"pdf-1\",
        \"media_type\":\"application/pdf\",
        \"data\":{\"base64\":\"$PDF_B64\"}
      },
      {
        \"id\":\"org-jwk-1\",
        \"media_type\":\"application/jwk+json\",
        \"filename\":\"organization-public-key.jwk.json\",
        \"data\":{\"json\":{\"kty\":\"EC\",\"crv\":\"P-384\",\"x\":\"<org-x>\",\"y\":\"<org-y>\"}}
      }
    ]
  }"
```

Notas:

- Si `Content-Type` no es `application/didcomm-plain+json`, la API responde `415`.
- Si el payload DIDComm no trae `attachments[].data.base64` o `attachments[].data.links`, responde `400`.
- `meta.jws.protected.jwk` es la clave publica del controller/mensajeria, no la de firma de credenciales de la organizacion.
- La clave publica de la organizacion viaja como attachment `application/jwk+json`; si no llega, ICA autogenera una `ES384` y la devuelve en `_verify-response`.

### 3.2 Respuesta inicial (`202` asincrona)

Body: vacio.

Headers esperados:

```http
HTTP/1.1 202 Accepted
Location: /<tenantId>/cds-ES/v1/animal-care/terms/pdf/202603051133/_verify-response
Retry-After: 5
```

`Location` no incluye `thid`; el cliente debe enviarlo en cada polling.

## 4) Endpoint de polling (`_verify-response`)

Patron:

```text
POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/terms/pdf/{resourceType}/_verify-response
```

Puedes enviar `thid` por query (recomendado) o por body JSON.

### 4.1 Polling por query

```bash
curl -i -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/terms/pdf/$VERSION/_verify-response?thid=$THID"
```

### 4.2 Polling por body JSON

```bash
curl -i -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/terms/pdf/$VERSION/_verify-response" \
  -H "Content-Type: application/json" \
  -d "{\"thid\":\"$THID\"}"
```

### 4.3 Estrategia de polling

El cliente debe repetir `POST` a `_verify-response` con el mismo `thid` hasta salir de `202`.

- Si recibe `202`, espera el valor de `Retry-After` (o 5 segundos si no viene) y vuelve a consultar.
- El estado terminal llega cuando la respuesta deja de ser `202` (normalmente `200` con Bundle DIDComm, o `4xx/5xx` en errores tempranos).


## 5) Modelo de respuesta uniforme (DIDComm + Bundle)

### 5.1 Job pendiente (`202`)

Body: vacio.

```http
HTTP/1.1 202 Accepted
Location: /<tenantId>/cds-ES/v1/animal-care/terms/pdf/202603051133/_verify-response
Retry-After: 5
```

### 5.2 Error temprano (`4xx/5xx`) en formato uniforme

```json
{
  "jti": "urn:uuid:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "iss": "did:web:localhost%3A3310",
  "aud": "",
  "thid": "",
  "type": "application/bundle-api+json",
  "body": {
    "resourceType": "Bundle",
    "type": "batch-response",
    "total": 0,
    "data": [],
    "issues": {
      "resourceType": "OperationOutcome",
      "issue": [
        {
          "severity": "error",
          "code": "invalid",
          "diagnostics": "..."
        }
      ]
    }
  }
}
```

Notas:

- En errores tempranos, `thid` y/o `aud` pueden venir vacios si no se pudieron derivar de la request.
- `iss` lo emite siempre la ICA (no se copia del request).

### 5.3 Job fallido (`200`, mensaje DIDComm con Bundle)

```json
{
  "jti": "urn:uuid:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "iss": "did:web:ica.example.com",
  "aud": "did:web:ica.example.com",
  "thid": "verify-terms-001",
  "type": "application/bundle-api+json",
  "body": {
    "resourceType": "Bundle",
    "type": "batch-response",
    "issues": {
      "resourceType": "OperationOutcome",
      "issue": [
        {
          "severity": "error",
          "code": "exception",
          "diagnostics": "Revocation check did not pass (status=unknown)."
        }
      ]
    },
    "total": 1,
    "data": [
      {
        "type": "TermsVerification-v1.0",
        "resource": {
          "id": "urn:uuid:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
          "type": "terms-verification-v1.0",
          "thid": "verify-terms-001",
          "status": "failed",
          "content": {
            "error": "Revocation check did not pass (status=unknown)."
          }
        },
        "response": {
          "status": "500",
          "outcome": {
            "resourceType": "OperationOutcome",
            "issue": [
              {
                "severity": "error",
                "code": "exception",
                "diagnostics": "Revocation check did not pass (status=unknown)."
              }
            ]
          }
        }
      }
    ]
  }
}
```

### 5.4 Job exitoso (`200`, mensaje DIDComm con Bundle)

```json
{
  "jti": "urn:uuid:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "iss": "did:web:ica.example.com",
  "aud": "did:web:ica.example.com",
  "thid": "verify-terms-001",
  "type": "application/bundle-api+json",
  "body": {
    "resourceType": "Bundle",
    "type": "batch-response",
    "result": {
      "ok": true,
      "verifiedAt": "2026-03-05T08:10:21.000Z",
      "templateUrl": "https://raw.githubusercontent.com/Global-DataCare/terms/refs/heads/main/dataspace/animal-care/es/202603051133/terms.pdf",
      "templateMatch": true,
      "signatureValid": true,
      "chainValid": true,
      "revocationStatus": "good",
      "digest": {
        "alg": "sha3-384",
        "signedPdfHex": "<hex>",
        "unsignedPdfHex": "<hex>",
        "templateHex": "<hex>"
      },
      "hashes": {
        "signedPdfSha256Hex": "<hex>",
        "unsignedPdfSha256Hex": "<hex>",
        "templateSha256Hex": "<hex>"
      },
      "notes": ["..."]
    },
    "issues": {
      "resourceType": "OperationOutcome",
      "issue": [
        {
          "severity": "information",
          "code": "informational",
          "diagnostics": "Verification completed."
        }
      ]
    },
    "total": 2,
    "data": [
      {
        "type": "Organization-verification-v1.0",
        "response": {
          "status": "200",
          "outcome": {
            "resourceType": "OperationOutcome",
            "issue": [
              {
                "severity": "information",
                "code": "informational",
                "diagnostics": "Organization credential extracted from verified document."
              }
            ]
          }
        },
        "resource": {
          "type": ["VerifiableCredential", "OrganizationCredential"],
          "credentialSubject": {
            "@type": "Organization",
            "legalName": "Acme Health SL",
            "taxID": "VATES-A12345678"
          }
        }
      },
      {
        "type": "LegalRepresentative-verification-v1.0",
        "response": {
          "status": "200",
          "outcome": {
            "resourceType": "OperationOutcome",
            "issue": [
              {
                "severity": "information",
                "code": "informational",
                "diagnostics": "Legal representative credential extracted from verified document."
              }
            ]
          }
        },
        "resource": {
          "type": ["VerifiableCredential", "PersonCredential", "LegalRepresentativeCredential"],
          "credentialSubject": {
            "@type": "Person",
            "roleName": "legal-representative",
            "memberOf": {
              "@type": "Organization",
              "legalName": "Acme Health SL",
              "taxID": "VATES-A12345678"
            }
          }
        }
      }
    ]
  }
}
```

# 2) Permiso cross-project para pull de imágenes
gcloud projects add-iam-policy-binding globaldatacare-ica-dev \
  --member="serviceAccount:$default" \
  --role="roles/artifactregistry.reader"


## 6) Semantica de verificacion

La comprobacion criptografica actual incluye:

- Validacion de firma CMS/PAdES del PDF.
- Validacion de cadena X.509 frente a FNMT.
- Comprobacion de revocacion mediante CRL.
- Verificacion de plantilla original via hash (GitHub template URL pattern).
- Cache de plantilla y precarga opcional de versiones.
- Estructura `evidence` alineada al modelo OIDC4IDA (`electronic_signature` y `document`).
- `attachments.digest.value` en Base64 (OIDC4IDA), no Base58.

## 7) Casos de error para pruebas de integracion

Metodo incorrecto:

```bash
curl -i "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/terms/pdf/$VERSION/_verify"
```

`_verify-response` sin `thid`:

```bash
curl -i -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/terms/pdf/$VERSION/_verify-response"
```

Content-Type no soportado:

```bash
curl -i -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/terms/pdf/$VERSION/_verify" \
  -H "Content-Type: application/json" \
  -d "{\"thid\":\"$THID\",\"dataBase64\":\"abc\"}"
```

## 8) Catalogo semantico de credenciales

Los valores de `resource.type` (por ejemplo `OrganizationCredential`, `PersonCredential`, `LegalRepresentativeCredential`) deben estar definidos y versionados en el catalogo de datos del dominio ICA.

Recomendacion de gobierno:

- Publicar para cada tipo su schema JSON/JSON-LD, version y reglas de validacion.
- Mantener compatibilidad hacia atras por version (no por sobrescritura).
- No usar `resourceType` dentro de una VC W3C v2.
- Para Organization, reservar `identifier` para identificadores de dominio (por ejemplo registro sanitario), no para `taxID`.

## 9) Mapeo campo a campo (estado actual)

- Origen de identidad del firmante: certificado embebido en firma CMS/PAdES (`signerSubject`, `signerIssuer`, `signerCertificateSerialNumber`).
- `evidence[0].type = "electronic_signature"`: evidencia de firma digital.
- `evidence[0].signature_type = "pades"`: firma PDF validada.
- `evidence[0].issuer`: emisor del certificado del firmante (`signerIssuer`).
- `evidence[0].serial_number`: serial del certificado (`signerCertificateSerialNumber`), no `taxID`.
- `evidence[0].created_at`: timestamp de verificacion backend.
- `evidence[1].type = "document"`: evidencia del documento verificado.
- `evidence[1].method = "eid"`: metodo OIDC4IDA configurado; no codifica por si solo el tipo juridico del certificado.
- `evidence[1].check_details = ["vdig","vcrypt"]`: comprobaciones de integridad/cripto.
- `evidence[1].attachments.digest.alg`: algoritmo de hash (`ICA_VERIFY_DIGEST_ALGORITHM`, default `sha3-384`).
- `evidence[1].attachments.digest.value`: hash en Base64.
- `evidence[1].document_details.document_number`: version del documento (`resourceType`).
- VC Organization (`credentialSubject`): `legalName` y `taxID`.
- VC Person (`credentialSubject`): relacion por `memberOf` + `roleName: "legal-representative"`.
