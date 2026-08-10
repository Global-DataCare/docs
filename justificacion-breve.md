# Justificación breve (1 página)

## Qué vamos a demostrar

Se demostrará el ciclo completo de publicación y consulta en local con evidencias:

1. autenticación,
2. publicación de datos,
3. confirmación de publicación,
4. consulta final,
5. evidencia DCAT-AP de datasets actualizados.

## Decisión de alcance

Para esta demo **no se necesita** flujo delegado con terceros ni creación de API keys para evaluadores.

Se usa el flujo **admin directo**, porque es más corto, más estable y suficiente para capturas y validación funcional.

## Orden correcto del flujo

1. `login` (obtener/guardar `id_token`)
2. `exchange` (obtener Bearer de sesión)
3. `upload` (con polling automático)
4. `patch` o `batch` (confirmación/promoción)
5. `search` (verificación)

## Punto clave de autenticación

- El `id_token` viene del login/IdP.
- La API key no genera `id_token`.
- La API key se usaría en `/exchange` para delegar o limitar permisos en un escenario futuro.
- El token usado por `upload/patch/batch/search` es el Bearer devuelto por `/exchange`.

## Pruebas en local

Para pruebas locales basta con:

- levantar backend local con los cambios,
- inicializar variables de entorno,
- ejecutar el flujo CLI en el orden indicado.

## Comandos mínimos (demostración de funcionamiento)

```bash
node dist/cli.js login --id-token "$DATACONV_ID_TOKEN"
node dist/cli.js exchange --scope "excel/_upload Subject/_search DocumentReference/_search"
node dist/cli.js upload ./ruta.xlsx --output-json ./artifacts/upload-response.json
node dist/cli.js patch --thid "<thid>" --output-json ./artifacts/patch-response.json
node dist/cli.js search --resource-type DocumentReference --output-json ./artifacts/search-documentreference.json
```

Alternativa de confirmación:

```bash
node dist/cli.js batch --thid "<thid>" --output-json ./artifacts/batch-response.json
```

## Evidencias a capturar

1. Swagger cargado con grupos actualizados.
2. `login + exchange` (scope y expiración de sesión).
3. `upload` aceptado con `thid` y polling.
4. `patch` o `batch` completado (`status`, `promotedCount`).
5. `search` con `total` y resultados.
6. evidencia DCAT (`accessURL`) en respuestas/artefactos.

## Nota final

El flujo delegado para evaluadores de solo lectura es válido, pero no es necesario para esta entrega de capturas. Se puede activar en una fase posterior.