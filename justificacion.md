# Justificación del flujo de demostración local

## Objetivo

Documentar el flujo mínimo y correcto para una demo local con capturas de pantalla, sin necesidad de delegar acceso a terceros mediante API keys.

## Decisión funcional

Para el caso actual (capturas/evidencias), **no es necesario** crear API keys de terceros.

Se usa el flujo **admin directo**:

1. `login` (obtener/guardar `id_token` del IdP o token demo)
2. `exchange` (obtener Bearer de sesión)
3. `config` (si aplica, por `mapping-json`)
4. `upload` (con polling automático)
5. `patch` o `batch` (confirmación/promoción)
6. `search` (verificación de publicación)

## Aclaración clave de autenticación

- El `id_token` **siempre** viene del login/IdP.
- La API key **no genera** `id_token`.
- La API key se usa en `/exchange` para restringir/delegar permisos.
- El token que consumen `config`, `upload`, `patch/batch` y `search` es el **Bearer** devuelto por `/exchange`.

## ¿Hace falta subir versión (`0.x.1`) antes de probar?

No. Para pruebas locales:

- basta con reconstruir y levantar el backend local con los cambios,
- configurar variables de entorno,
- y ejecutar el flujo CLI en orden (`login -> exchange -> upload -> patch/batch -> search`).

El bump de versión se reserva para release/publicación, no para validar local.

## Variables de entorno mínimas

- `DATACONV_BASE_URL`
- `DATACONV_TENANT_ID` (VAT)
- `DATACONV_JURISDICTION`
- `DATACONV_SECTOR`
- `DATACONV_SOFTWARE_ID`
- `DATACONV_ID_TOKEN`

Opcionales para script de evidencia:

- `DATACONV_PUBLICACION_MAPPING_JSON`
- `DATACONV_PUBLICACION_HEADER_ROW_INDEX`
- `DATACONV_PROMOTION_MODE` (`patch` o `batch`)

## Comandos recomendados (manual)

```bash
# 1) Login
node dist/cli.js login --id-token "$DATACONV_ID_TOKEN"

# 2) Exchange de sesión
node dist/cli.js exchange --scope "excel/_upload Subject/_search DocumentReference/_search"

# 3) Upload + polling automático
node dist/cli.js upload ./ruta.xlsx --output-json ./artifacts/upload-response.json

# 4) Confirmación de publicación (elige uno)
node dist/cli.js patch --thid "<thid>" --output-json ./artifacts/patch-response.json
# o
node dist/cli.js batch --thid "<thid>" --output-json ./artifacts/batch-response.json

# 5) Verificación por búsqueda
node dist/cli.js search --resource-type Subject --output-json ./artifacts/search-subject.json
node dist/cli.js search --resource-type DocumentReference --output-json ./artifacts/search-documentreference.json
```

## Ejecución recomendada para capturas (automática)

```bash
cd dataconv-client-sdk-ts
./scripts/evidencia-publicacion.sh
```

Con mapping externo y promoción por `batch`:

```bash
DATACONV_PUBLICACION_MAPPING_JSON=./examples/mappings/qvet-v1.json \
DATACONV_PUBLICACION_HEADER_ROW_INDEX=1 \
DATACONV_PROMOTION_MODE=batch \
./scripts/evidencia-publicacion.sh
```

## Checklist de capturas de pantalla

1. **Swagger/API docs** cargado con tags actualizados (sin `V1`).
2. **Login + Exchange** mostrando scope y expiración de sesión.
3. **Upload** aceptado con `thid` y polling automático.
4. **Patch o Batch** completado (`status`, `promotedCount`).
5. **Search Subject** con `total` y `entry`.
6. **Search DocumentReference** con `total` y `entry`.
7. **Evidencia DCAT** en `patch-response.json` o `dcat-ap-datasets-publicados.json` (rutas `accessURL`).

## Nota sobre flujo delegado (futuro)

El flujo delegado para evaluadores (terceros con solo lectura) es válido, pero es un escenario aparte:

1. admin crea API key con scopes de búsqueda,
2. tercero hace `/exchange` con su `id_token` + API key,
3. tercero obtiene Bearer restringido y ejecuta solo `search`.

No se necesita para las capturas actuales.