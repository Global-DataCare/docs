# Integrators Guide (Animal Health - ES)

Guía breve para integradores de software veterinario o de gestión de animales.

Objetivo: convertir exportaciones locales (Excel/CSV) a payload interoperable y enviarlo al conector del espacio de datos.

## 1) Dos APIs, dos dominios

Hay dos servicios distintos:

1. API de preconversión: transforma Excel/CSV a un mensaje con `body.data[]` (conjunto de uno o varios `Patient`, uno por sujeto), donde cada `Patient` incluye `contained[]` con `Composition`, `DocumentReference` y `Encounter`.
2. API del conector al data space: recibe ese mensaje y actualiza colecciones de research (`digitaltwin`).

Ejemplo de dominios:

- Preconversión: `https://example-conversion-veterinary.globaldatacare.es`
- Conector: `https://example-connector-clinic.globaldatacare.es`

## 2) Flujo mínimo end-to-end

Todas las operaciones de negocio son HTTP asíncronas:

- La acción inicial (`_create`, `_upload`, `_batch`) responde `202 Accepted`.
- El servidor devuelve `Location` (endpoint `*-response`) y `Retry-After`.
- En `202` de `_create` no hay body funcional; la app debe usar `Location` y conservar el `thid` que envió.
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
  - La respuesta final viene como `Bundle` (`batch-response`) en `body.data[]`.
  - Cada entry trae `response.status` + `response.outcome` (`OperationOutcome`).
  - En polling sí puede devolverse `thid` para trazabilidad.
  - Si envías `thid`, la API puede aceptar `POST .../_create` y devolver el fallo en `_create-response` como entry con `response.status` `4xx/5xx`.
  - Si no envías `thid`, los errores de validación/auth se devuelven directamente en `POST .../_create`.
  - Es de consumo único (POP): si lo lees una vez, deja de estar disponible.
  - `401` significa credenciales inválidas o no aceptadas.
  - `500` significa error interno del servidor.

- `conversion/_upload-response`:
  - `202` significa en progreso (`queued` o `running`).
  - `200` significa terminal, pero puede ser `succeeded` o `failed`.
  - En polling sí puede devolverse `thid` para trazabilidad.
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
            "sourceId": "IDARTICULO",
            "species": "ESPECIE",
            "date": "FECHA",
            "time": "HORA"
          },
          "fieldDefaults": {},
          "allowedSections": ["clinica"],
          "excludedSectionFamilies": ["clinica:vacunas"],
          "loincBySectionFamily": {
            "clinica:laboratorio": "30954-2",
            "clinica:consultas": "34109-9",
            "clinica:cirugia": "11504-8",
            "clinica:medicamentos": "10160-0",
            "clinica:varios": "11503-0"
          }
        }
      }
    }
  ]
}
JSON
```

Nota:
- Guarda `CFG_THID` en cliente; lo necesitarás en `.../_create-response`.
- No esperes `thid` en el body de la respuesta inicial `202` de `.../_create`.

Referencia de config base Qvet:

- `$HOME/GITS/gdc-workspace/adapter-ingestion-py/configs/qvet.schema.example.json`

Regla importante de calidad:

- `loincBySectionFamily` debe cubrir las categorías clínicas que quieras publicar.
- Si una fila no tiene mapeo LOINC para su `section:family`, la preconversión la omite.
- Por cada fila omitida se añade una entrada `OperationOutcome` dentro de `body.data[]`.
- Esa entrada incluye `response.outcome` y `OperationOutcome.rowNumber` para identificar la fila.
- Además, `_upload-response` lo resume en `outcome.issue[].diagnostics` (con filas de muestra).

En una configuración completa también se suelen incluir:

- `speciesLocalToFhirCode` (texto local -> código FHIR species).
- `runtimeDefaults` (por ejemplo `language`, `subjectKind`, `subjectDidPrefix`, `includeFields`).

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

`$HOME/GITS/gdc-workspace/adapter-ingestion-py/examples/input/exampleQvetES.xlsx`

```bash
UP_THID="up-$(uuidgen)"

curl -i -sS -X POST "$BASE_PRECONV/$ALT/cds-$JUR/v1/animal-care/conversion/$SOFTWARE_ID/excel/_upload" \
  -F "file=@$HOME/GITS/gdc-workspace/adapter-ingestion-py/examples/input/exampleQvetES.xlsx" \
  -F "iss=$ISS" \
  -F "thid=$UP_THID" \
  -F "jti=$UP_THID" \
  -F "type=application/api+json" \
  -F "iat=$NOW" \
  -F "exp=$EXP"
```

Nota:
- Guarda `UP_THID` en cliente; lo necesitarás en `.../_upload-response`.

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

Cuando termine (`status=succeeded`), la respuesta incluye el mensaje DIDComm listo para envío.
Si hubo filas omitidas por mapeo, `body.data[]` incluirá recursos `OperationOutcome`.

Ejemplos de mensaje preconvertido:

- `$HOME/GITS/gdc-workspace/adapter-ingestion-py/examples/current-output/composition-message.sample.json`
- `$HOME/GITS/gdc-workspace/adapter-ingestion-py/docs/es/12-ejemplos-salida-actual.md`

Ejemplo (mensaje DIDComm listo para enviar al conector):

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
        "resource": {
          "resourceType": "Patient",
          "id": "82ef6455-9c10-59a3-9f73-440939a6adc3",
          "meta": {
            "claims": {
              "Patient.identifier": "did:web:example.org:animal:subject:zW1jubAfgQFCTho9XgbZXhfekVLNAc4KBmCicaijNywzqpN",
              "Patient.active": "true",
              "Patient.language": "es-ES"
            }
          },
          "contained": [
            {
              "resourceType": "Composition",
              "id": "40304495-a1bd-53d9-b7ea-8d7c8b0655eb",
              "meta": {
                "claims": {
                  "Composition.identifier": "40304495-a1bd-53d9-b7ea-8d7c8b0655eb",
                  "Composition.subject": "did:web:example.org:animal:subject:zW1jubAfgQFCTho9XgbZXhfekVLNAc4KBmCicaijNywzqpN",
                  "Composition.section": "http://loinc.org|11369-6",
                  "Composition.author": "",
                  "Composition.date": "2026-03-05T01:21:34.680892+00:00",
                  "Composition.type": "http://loinc.org|11369-6",
                  "Composition.title": "immunizations index",
                  "Composition.entry": "urn:uuid:3827b617-5938-5292-898d-852f9296d8f9,urn:uuid:01e85565-0cad-5313-b0d0-c430c6fabd9d"
                }
              }
            },
            {
              "resourceType": "Encounter",
              "id": "3827b617-5938-5292-898d-852f9296d8f9",
              "meta": {
                "claims": {
                  "Encounter.identifier": "3827b617-5938-5292-898d-852f9296d8f9",
                  "Encounter.subject": "did:web:example.org:animal:subject:zW1jubAfgQFCTho9XgbZXhfekVLNAc4KBmCicaijNywzqpN",
                  "Encounter.date": "2026-01-01T10:00:00Z",
                  "Encounter.status": "finished",
                  "Encounter.class": "http://terminology.hl7.org/CodeSystem/v3-ActCode|AMB"
                }
              }
            },
            {
              "resourceType": "DocumentReference",
              "id": "01e85565-0cad-5313-b0d0-c430c6fabd9d",
              "meta": {
                "claims": {
                  "DocumentReference.identifier": "01e85565-0cad-5313-b0d0-c430c6fabd9d",
                  "DocumentReference.subject": "did:web:example.org:animal:subject:zW1jubAfgQFCTho9XgbZXhfekVLNAc4KBmCicaijNywzqpN",
                  "DocumentReference.author": "",
                  "DocumentReference.date": "2026-01-01T10:00:00Z",
                  "DocumentReference.type": "urn:gdc:wakyma:clinica:vacunas:vacuna-perro",
                  "DocumentReference.category": "http://loinc.org|11369-6",
                  "DocumentReference.description": "Vacuna anual",
                  "DocumentReference.language": "es-ES"
                }
              }
            }
          ]
        }
      },
      {
        "resource": {
          "resourceType": "OperationOutcome",
          "id": "urn:uuid:29e88ddd-5253-504f-a26b-a8f84d59e991",
          "issue": [
            {
              "severity": "warning",
              "code": "processing",
              "details": {
                "text": "Row skipped during preconversion."
              },
              "diagnostics": "Missing required LOINC mapping for section:family 'clinica:laboratorio'."
            }
          ],
          "meta": {
            "claims": {
              "@context": "org.hl7.fhir.api",
              "@type": "OperationOutcome:PreconversionRowIssue",
              "OperationOutcome.rowNumber": "42",
              "OperationOutcome.sectionFamily": "clinica:laboratorio",
              "OperationOutcome.issueCode": "missing-loinc-mapping"
            }
          }
        },
        "response": {
          "status": "422",
          "outcome": {
            "resourceType": "OperationOutcome",
            "issue": [
              {
                "severity": "warning",
                "code": "processing",
                "details": {
                  "text": "Row skipped during preconversion."
                },
                "diagnostics": "Missing required LOINC mapping for section:family 'clinica:laboratorio'."
              }
            ]
          }
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
- `data[].resource.resourceType = Patient` (principal por sujeto).
- `data[].resource.meta.claims` (claims de Patient).
- `data[].resource.contained[]` incluye `Composition`, `DocumentReference` y `Encounter` del mismo sujeto.
- `data[].resource.contained[].meta.claims` guarda claims interoperables por recurso.
- Agrupación actual: **1 Patient por sujeto**.
- Si un sujeto tiene varias secciones (`section:family`), se representan como varias `Composition` dentro de `Patient.contained[]`.
- La relación sección -> recursos se mantiene en `Composition.entry` (referencias `urn:uuid:` a recursos de `contained[]`).

## 7) Nota técnica (opcional)

El mensaje de preconversión se basa en:

- DIDComm v2 plaintext message (envoltorio del mensaje).
- Un híbrido de JSON:API y FHIR Bundle:
  - estilo JSON:API para `body.data[]`;
  - recursos FHIR (`Patient` + `contained[]`) dentro de cada item.

## 8) Reglas prácticas de integración

- Se puede comprimir el payload; indícalo en el header HTTP: `Content-Encoding: gzip`.
- Mantén separados los dominios de preconversión y conector.
- Usa siempre polling asíncrono: acción y acción con sufijo `-response`.
- Usa el mensaje DIDComm de `_upload-response` (con `body.data[]`) como payload para el conector y así alimentar las colecciones de datos anonimizadas (gemelos digitales anónimos).

## 9) Referencias

- Preconversión API: `$HOME/GITS/gdc-workspace/adapter-ingestion-py/docs/es/08-api-config-multitenant.md`
- Preconversión E2E local: `$HOME/GITS/gdc-workspace/adapter-ingestion-py/docs/es/API_DEVELOPMENT_GUIDE.md`
- Conector (research digital twin): `$HOME/GITS/gdc-workspace/gwtemplate-node-ts/docs/API_INTEGRATORS_GUIDE.md`
- Ejemplo payload research del conector: `$HOME/GITS/gdc-workspace/gwtemplate-node-ts/src/__tests__/data/example-payloads.ts` (`RESEARCH_COMPOSITION_INGESTION_MESSAGE`)
