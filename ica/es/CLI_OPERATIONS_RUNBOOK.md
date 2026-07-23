# ICA CLI Operations Runbook (ES)

Este documento agrupa la operativa del CLI ICA para onboarding y publicacion.
La API `_verify` se documenta en:

- [`INTEGRATORS_GUIDE.md`](./INTEGRATORS_GUIDE.md)
- [`dataspace-ica-cli/README.md`](../../../dataspace-ica-cli/README.md)

## Transporte alternativo sin API online (GCS Signed URL)

Usar cuando un cliente no puede llamar una API ICA publica y se necesita un canal temporal de subida.

Flujo:

1. Se abre `requestId`.
2. ICA emite Signed URL `PUT` para `inbox/<requestId>/submission.tgz`.
3. Cliente sube `submission-<requestId>.tgz`.
4. ICA descarga en `requests/<requestId>/intake/`.
5. ICA ejecuta `request:ingest`.

### Setup unico GCS

```bash
export GCP_PROJECT="<tu-proyecto>"
export GCS_BUCKET="gdc-ica-submissions-prod"

gcloud config set project "$GCP_PROJECT"
gcloud services enable storage.googleapis.com

gcloud storage buckets create "gs://$GCS_BUCKET" \
  --location=europe-west1 \
  --uniform-bucket-level-access

gcloud iam service-accounts create ica-submission-signer \
  --display-name="ICA Submission Signer"

gcloud storage buckets add-iam-policy-binding "gs://$GCS_BUCKET" \
  --member="serviceAccount:ica-submission-signer@${GCP_PROJECT}.iam.gserviceaccount.com" \
  --role="roles/storage.objectAdmin"

mkdir -p .secrets
gcloud iam service-accounts keys create ./.secrets/ica-submission-signer.json \
  --iam-account="ica-submission-signer@${GCP_PROJECT}.iam.gserviceaccount.com"
```

### Emitir URL firmada (24h / 48h)

```bash
export REQUEST_ID="req-2026-0001"
export OBJECT_PATH="inbox/${REQUEST_ID}/submission.tgz"

gcloud storage sign-url "gs://${GCS_BUCKET}/${OBJECT_PATH}" \
  --http-verb=PUT \
  --duration=24h \
  --content-type=application/gzip \
  --service-account="ica-submission-signer@${GCP_PROJECT}.iam.gserviceaccount.com" \
  --private-key-file="./.secrets/ica-submission-signer.json"
```

### Ingesta ICA tras subida

```bash
export REQUEST_ID="req-2026-0001"

mkdir -p "requests/${REQUEST_ID}/intake"
gcloud storage cp "gs://${GCS_BUCKET}/inbox/${REQUEST_ID}/submission.tgz" \
  "requests/${REQUEST_ID}/intake/submission.tgz"

node ./bin/ica-cli.js request:ingest \
  --bundle "requests/${REQUEST_ID}/intake/submission.tgz" \
  --request-id "${REQUEST_ID}"
```

## Suites criptograficas (estado actual)

- Firma ICA actual: `ES-384` (`ECDSA P-384`, `secp384r1`).
- Cadena X.509 publicada en `pki/*` y `x5c` en `jwks.json`.
- No hay mensajeria post-cuantica productiva en este repo.

## Arquitectura de verificacion de firma

La API usa un manager de verificacion con adaptadores:

- manager: `SignatureVerificationManager` (selecciona adaptador por perfil/jurisdiccion)
- adaptador actual: `fnmt-es` (implementacion en `FnmtPdfVerificationService`)

Variables de seleccion:

- `ICA_VERIFY_ADAPTER` (id preferido, por ejemplo `fnmt-es`)
- `ICA_VERIFY_ADAPTER_STRICT` (`true|false`)
- `ICA_FNMT_ADAPTER_JURISDICTIONS` (CSV, default `ES`)

Objetivo futuro (no implementado aqui):

- `ML-DSA` y `ML-KEM`.
- perfiles `ES256K / secp256k1` para ciertos ecosistemas.

## Flujo recomendado (CLI)

### 1) Reservar dominio

```bash
node ./bin/ica-cli.js domain:reserve \
  --domain api-orgdemo.globaldatacare.es \
  --request-id req-2026-0001
```

### 2) Inicializar CA raiz + ICA (una vez)

```bash
node ./bin/ica-cli.js ca:init-root \
  --common-name onehealth-root.unid.online \
  --country ES \
  --out-dir ca/root

node ./bin/ica-cli.js ca:init-ica \
  --common-name onehealth-ica.accuro.es \
  --root-key ca/root/root-key.pem \
  --root-cert ca/root/root-cert.pem \
  --country ES \
  --out-dir ca/ica
```

### 3) Ingesta + validacion

```bash
node ./bin/ica-cli.js request:ingest \
  --bundle /ruta/submission-req-2026-0001.tgz \
  --request-id req-2026-0001

node ./bin/ica-cli.js request:validate \
  --request-id req-2026-0001 \
  --allowed-isco 1219,2421 \
  --allowed-sectors health-research:provider,animal-care:provider,health-care:reader
```

### 4) Firma CSR (organizacion + controladores)

```bash
node ./bin/ica-cli.js csr:sign-batch \
  --request-id req-2026-0001 \
  --ica-key ca/ica/ica-key.pem \
  --ica-cert ca/ica/ica-cert.pem \
  --root-cert ca/root/root-cert.pem \
  --days 730 \
  --ica-name onehealth-ica.accuro.es.pem \
  --root-name root-unid.pem
```

### 5) Aprobacion y publicacion en repo cliente

```bash
node ./bin/ica-cli.js request:approve \
  --request-id req-2026-0001

node ./bin/ica-cli.js publish:client \
  --request-id req-2026-0001 \
  --client-repo /ruta/repo-publico-org
```

### 6) Generar DCAT en repo publico ICA

```bash
node ./bin/ica-cli.js dcat:add-service \
  --ica-public-repo /ruta/repo-publico-ica \
  --endpoint-url https://api-orgdemo.globaldatacare.es/dsp/dcat3/animal-index \
  --publisher-did did:web:onehealth-ica.accuro.es \
  --service-title "Org Demo Unified Index Service (ES)" \
  --service-description "Servicio de indice unificado de datos para Org Demo." \
  --sign-key ca/ica/ica-key.pem

node ./bin/ica-cli.js dcat:build-catalog \
  --ica-public-repo /ruta/repo-publico-ica \
  --publisher-did did:web:onehealth-ica.accuro.es \
  --base-url https://onehealth-ica.accuro.es \
  --title "Catalogo OneHealth ICA Accuro" \
  --description "Catalogo de servicios de indice unificado publicados por la ICA." \
  --sign-key ca/ica/ica-key.pem
```

### 7) Activar dominio

```bash
node ./bin/ica-cli.js domain:activate \
  --domain api-orgdemo.globaldatacare.es \
  --request-id req-2026-0001
```

## Notas operativas

- `csr:sign-batch` inyecta `x5c` en `jwks.json`.
- `requests/` no se publica.
- El paquete cliente no debe incluir `.private/`.
- `--allowed-sectors` se mantiene por compatibilidad y valida scopes exactos.

## Flujo productivo recomendado para hosting services

Para produccion, el alta de un `hosting service` debe separar tres cosas:

- autorizacion comercial y de politica
- identidad publica (`did:web`, `did.json`, `jwks.json`, catalogos)
- identidad tecnica Fabric/X.509

Decision operativa:

- la licencia o `exchange` autoriza que el host puede solicitar identidad de red
- el `CSR` aporta la clave publica del host para firma
- el certificado emitido materializa la identidad tecnica del host en Fabric

### Secuencia recomendada

1. El host completa un flujo ICA de licencia / `exchange` / activacion.
2. ICA valida region, dominio, capacidades, rol y estado de autorizacion.
3. El host genera localmente su `keypair`.
4. El host genera localmente su `CSR`.
5. El host envia a ICA:
   - `csr`
   - `licenseId` o evidencia de activacion
   - `did`
   - `domain`
   - `region`
   - perfil o rol solicitado
6. ICA valida la peticion y llama internamente a su `fabric-ca`.
7. ICA devuelve:
   - certificado leaf
   - cadena CA
   - metadatos de enrollment
8. El host guarda su clave privada localmente o en KMS/HSM y usa el certificado para conectar.

### Regla de seguridad

- La clave privada del host no debe generarse en ICA en produccion.
- `fabric-ca` no debe exponerse a Internet.
- `dataspace-ica-ts` debe actuar como pasarela publica y punto de politica.
- Solo la API ICA publica, `did.json`, `jwks.json` y artefactos de discovery deben publicarse externamente.
- `fabric-ca`, peers, orderers y secretos de enrollment deben quedar en red privada.

### Relacion con tenants

Para simplificar el modelo actual:

- solo los `hosts` necesitan identidad Fabric directa
- los `tenants` publican y operan a traves del `host service`
- los `tenants` pueden seguir usando onboarding ICA, credenciales y discovery sin certificado Fabric propio

### Contrato sugerido de API ICA

Si se quiere dejar esto listo para produccion, el contrato recomendado es:

1. `POST .../hosting-service/_exchange`
   valida licencia/politica y abre el hilo de enrollment
2. `POST .../hosting-service/csr/_activate`
   recibe `csr` + licencia + metadatos del host
3. `POST .../hosting-service/csr/_activate-response`
   polling asincrono del resultado

La licencia responde a "este host puede enrolarse".
El `CSR` responde a "firma esta clave publica para ese host autorizado".
