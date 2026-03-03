# Integrators Guide (Animal Health - ES)

Guía breve para integradores de software veterinario o de gestión de animales.

Objetivo: convertir exportaciones locales (Excel/CSV) a payload interoperable y enviarlo al conector del espacio de datos.

## 1) Dos APIs, dos dominios

Hay dos servicios distintos:

1. API de preconversión: transforma Excel/CSV a un mensaje con `body.data[]` (conjunto de uno o varios `Composition`, uno por gemelo digital).
2. API del conector al data space: recibe ese mensaje y actualiza colecciones de research (`digitaltwin`).

Ejemplo de dominios:

- Preconversión: `https://example-conversion-veterinary.globaldatacare.es`
- Conector: `https://example-connector-clinic.globaldatacare.es`

## 2) Flujo mínimo end-to-end

Todas las operaciones de negocio son HTTP asíncronas:

- La acción inicial (`_create`, `_upload`, `_batch`) responde `202 Accepted`.
- El servidor devuelve `Location` (endpoint `*-response`) y `Retry-After`.
- La app cliente debe hacer polling con `POST` al `*-response` hasta estado terminal.

1. Crear configuración de organización/software en API de preconversión.
2. Hacer polling en `_create-response` hasta obtener respuesta terminal.
3. Subir fichero (`_upload`) con Excel/CSV.
4. Hacer polling en `_upload-response` hasta obtener respuesta terminal y verificar `status=succeeded`.
5. Tomar el mensaje preconvertido de la respuesta.
6. Enviar ese mensaje al endpoint research del conector (`digitaltwin/.../Composition/_batch`).
7. Hacer polling en `_batch-response` hasta respuesta terminal.

### Cómo interpretar el polling (importante)

Ambos flujos son asíncronos, pero el contrato actual no es totalmente simétrico:

- `config/_create-response`:
  - `200` significa terminal.
  - En la respuesta final el `status` puede ser `succeeded` o `failed`.
  - Si envías `thid/jti`, la API puede aceptar `POST .../_create` y devolver el fallo en `_create-response` con `status=failed`.
  - Si no envías `thid/jti`, los errores de validación/auth se devuelven directamente en `POST .../_create`.
  - Es de consumo único (POP): si lo lees una vez, deja de estar disponible.
  - `401` significa credenciales inválidas o no aceptadas.
  - `500` significa error interno del servidor.

- `conversion/_upload-response`:
  - `202` significa en progreso (`queued` o `running`).
  - `200` significa terminal, pero puede ser `succeeded` o `failed`.
  - Por eso aquí no basta con HTTP `200`: hay que revisar `status`.
  - `401` significa credenciales inválidas o no aceptadas.
  - `500` significa error interno del servidor.

## 3) Paso 1: crear configuración (preconversión)

Endpoint:

`POST /host/cds-{jurisdiction}/v1/animal-care/{alternate-name}/config/didcomm/_create`

Ejemplo:

```bash
BASE_PRECONV="https://preconversion.example.globaldatacare.es"
ALT="clinic-demo"
JUR="ES"
SOFTWARE_ID="qvet-v1.0"
ISS="did:web:clinic-demo.globaldatacare.es:employee:it:loader"
CFG_THID="cfg-$(uuidgen)"
NOW="$(date +%s)"
EXP="$((NOW + 3600))"

curl -sS -X POST "$BASE_PRECONV/host/cds-$JUR/v1/animal-care/$ALT/config/didcomm/_create" \
  -H "Content-Type: application/json" \
  --data-binary @- <<JSON
{
  "iss": "$ISS",
  "thid": "$CFG_THID",
  "jti": "$CFG_THID",
  "type": "application/api+json",
  "iat": $NOW,
  "exp": $EXP,
  "data": [
    {
      "softwareId": "$SOFTWARE_ID",
      "config": {
        "mappingConfig": {
          "headerRowIndex": 1,
          "fieldMap": {
            "section": "SECCION",
            "family": "FAMILIA",
            "subfamily": "SUBFAMILIA",
            "concept": "CONCEPTO",
            "subjectId": "CHIP",
            "species": "ESPECIE",
            "date": "FECHA",
            "time": "HORA"
          }
        }
      }
    }
  ]
}
JSON
```

Polling:

```bash
curl -sS -X POST "$BASE_PRECONV/host/cds-$JUR/v1/animal-care/$ALT/config/didcomm/_create-response" \
  -H "Content-Type: application/json" \
  --data-binary @- <<JSON
{
  "iss": "$ISS",
  "thid": "$CFG_THID",
  "type": "application/api+json",
  "iat": $NOW,
  "exp": $EXP
}
JSON
```

## 4) Paso 2: subir Excel/CSV (preconversión)

Endpoint:

`POST /{alternate-name}/cds-{jurisdiction}/v1/animal-care/conversion/{software-id}/{csv|excel}/_upload`

Ejemplo con el fichero de prueba:

`/Users/fernando/GITS/gdc-workspace/adapter-ingestion-py/examples/input/exampleQvetES.xlsx`

```bash
UP_THID="up-$(uuidgen)"

curl -i -sS -X POST "$BASE_PRECONV/$ALT/cds-$JUR/v1/animal-care/conversion/$SOFTWARE_ID/excel/_upload" \
  -F "file=@/Users/fernando/GITS/gdc-workspace/adapter-ingestion-py/examples/input/exampleQvetES.xlsx" \
  -F "iss=$ISS" \
  -F "thid=$UP_THID" \
  -F "jti=$UP_THID" \
  -F "type=application/api+json" \
  -F "iat=$NOW" \
  -F "exp=$EXP"
```

Polling:

```bash
curl -sS -X POST "$BASE_PRECONV/$ALT/cds-$JUR/v1/animal-care/conversion/$SOFTWARE_ID/excel/_upload-response" \
  -H "Content-Type: application/json" \
  --data-binary @- <<JSON
{
  "iss": "$ISS",
  "thid": "$UP_THID",
  "type": "application/api+json",
  "iat": $NOW,
  "exp": $EXP
}
JSON
```

Cuando termine (`status=succeeded`), la respuesta incluye un resumen del proceso y el mensaje preconvertido listo para envío.

Ejemplo de mensaje objetivo para ingesta research en el conector:

- `/Users/fernando/GITS/gdc-workspace/gwtemplate-node-ts/src/__tests__/data/example-payloads.ts`
- constante: `RESEARCH_COMPOSITION_INGESTION_MESSAGE`

Ejemplo (contenido de `data.message`, listo para enviar al conector):

```json
{
  "jti": "research-composition-request-<test-id>",
  "thid": "research-composition-thread-<test-id>",
  "iss": "did:web:clinic.example.com:employee:data-loader",
  "aud": "did:web:api.acme.org",
  "type": "application/api+json",
  "body": {
    "resourceType": "Bundle",
    "type": "batch",
    "data": [
      {
        "type": "Composition",
        "resource": {
          "resourceType": "Composition",
          "id": "urn:uuid:0dbe2f39-3f6a-48a3-9807-2f9a102f1a11",
          "meta": {
            "claims": {
              "@context": "org.hl7.fhir.api",
              "@type": "Composition:ResearchDigitalTwin",
              "Composition.subject": "did:web:connector.example.com:animal:multihash:z3vYh7w9q2p1k4m8n6a5b4c3d2e1f0",
              "Composition.section": "LOINC|26436-6",
              "Composition.type": "LOINC|60591-5",
              "Composition.date": "2026-01-31T10:45:00Z",
              "Composition.author": "",
              "Composition.entry": "urn:uuid:c2b1f9ee-90d4-4f1d-8dc6-4c3f0b29621b,urn:uuid:aad1f0bc-5781-42dc-9d8f-30252fbce6a9"
            }
          },
          "contained": [
            {
              "resourceType": "DocumentReference",
              "id": "urn:uuid:c2b1f9ee-90d4-4f1d-8dc6-4c3f0b29621b",
              "meta": {
                "claims": {
                  "@context": "org.hl7.fhir.api",
                  "@type": "DocumentReference:Lab",
                  "DocumentReference.subject": "did:web:connector.example.com:animal:multihash:z3vYh7w9q2p1k4m8n6a5b4c3d2e1f0",
                  "DocumentReference.identifier": "urn:uuid:c2b1f9ee-90d4-4f1d-8dc6-4c3f0b29621b",
                  "DocumentReference.type": "http://loinc.org|26436-6",
                  "DocumentReference.category": "http://loinc.org|26436-6",
                  "DocumentReference.status": "current",
                  "DocumentReference.date": "2026-01-15T09:00:00Z",
                  "DocumentReference.description": "Laboratorio propio"
                }
              }
            },
            {
              "resourceType": "DocumentReference",
              "id": "urn:uuid:aad1f0bc-5781-42dc-9d8f-30252fbce6a9",
              "meta": {
                "claims": {
                  "@context": "org.hl7.fhir.api",
                  "@type": "DocumentReference:Imaging",
                  "DocumentReference.subject": "did:web:connector.example.com:animal:multihash:z3vYh7w9q2p1k4m8n6a5b4c3d2e1f0",
                  "DocumentReference.identifier": "urn:uuid:aad1f0bc-5781-42dc-9d8f-30252fbce6a9",
                  "DocumentReference.type": "http://loinc.org|18748-4",
                  "DocumentReference.category": "http://loinc.org|18726-0",
                  "DocumentReference.status": "current",
                  "DocumentReference.date": "2026-01-16T12:30:00Z",
                  "DocumentReference.description": "Diagnostico por imagen propio"
                }
              }
            }
          ]
        },
        "request": {
          "method": "POST",
          "url": "digitaltwin/org.hl7.fhir.api/Composition"
        }
      }
    ]
  }
}
```

## 5) Paso 3: enviar al conector (research/digital twin)

Endpoint de ingesta research:

`POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/digitaltwin/org.hl7.fhir.api/Composition/_batch`

Ejemplo:

```bash
BASE_CONNECTOR="https://api.example.globaldatacare.es"
TENANT_ID="clinic-demo"
SECTOR="animal-research"
AUTH_TOKEN="<bearer-token>"

# Guarda el mensaje preconvertido en un fichero local (por ejemplo, message.json)
curl -i -X POST "$BASE_CONNECTOR/$TENANT_ID/cds-$JUR/v1/$SECTOR/digitaltwin/org.hl7.fhir.api/Composition/_batch" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -H "App-ID: com.example.integrator" \
  -H "App-Version: 1.0.0" \
  --data-binary @message.json
```

Polling del conector:

```bash
curl -sS -X POST "$BASE_CONNECTOR/$TENANT_ID/cds-$JUR/v1/$SECTOR/digitaltwin/org.hl7.fhir.api/Composition/_batch-response" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -H "App-ID: com.example.integrator" \
  -H "App-Version: 1.0.0" \
  --data-binary @- <<JSON
{
  "thid": "$UP_THID"
}
JSON
```

Nota: el `thid` para polling en el conector debe ser el `thid` del mensaje que enviaste al conector.

## 6) Alcance actual del payload

La preconversión devuelve un mensaje con:

- `body.data[]`
- `data[].resource.resourceType = Composition`
- `data[].resource.meta.claims` (claims de Composition)
- `data[].resource.contained[].meta.claims` (normalmente DocumentReference)

En esta fase, el flujo de research está centrado en Composition + DocumentReference.
`Encounter` y `Patient` serán también añadidos.

## 7) Nota técnica (opcional)

El mensaje de preconversión se basa en:

- DIDComm v2 plaintext message (envoltorio del mensaje).
- Un híbrido de JSON:API y FHIR Bundle:
  - estilo JSON:API para `body.data[]`;
  - recursos FHIR (`Composition`, `contained[]`) dentro de cada item.

## 8) Reglas prácticas de integración

- Se puede comprimir el payload; indícalo en el header HTTP: `Content-Encoding: gzip`.
- Mantén separados los dominios de preconversión y conector.
- Usa siempre polling asíncrono: acción y acción con sufijo `-response`.
- Usa `data.message` de `_upload-response` como payload para el conector y así alimentar las colecciones de datos anonimizadas (gemelos digitales anónimos).

## 9) Referencias

- Preconversión API: `/Users/fernando/GITS/gdc-workspace/adapter-ingestion-py/docs/es/08-api-config-multitenant.md`
- Preconversión E2E local: `/Users/fernando/GITS/gdc-workspace/adapter-ingestion-py/docs/es/API_DEVELOPMENT_GUIDE.md`
- Conector (research digital twin): `/Users/fernando/GITS/gdc-workspace/gwtemplate-node-ts/docs/API_INTEGRATORS_GUIDE.md`
- Ejemplo payload research del conector: `/Users/fernando/GITS/gdc-workspace/gwtemplate-node-ts/src/__tests__/data/example-payloads.ts` (`RESEARCH_COMPOSITION_INGESTION_MESSAGE`)
