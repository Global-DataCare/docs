# ICA + Fabric Network Shape

## Objetivo

Fijar a nivel de `gdc-workspace` la forma general de la arquitectura de redes y del flujo de alta en ICA, sin atar este documento a nombres concretos de canales o redes dentro de un repo específico.

## Principios

- La ICA del dataspace usa Fabric como base de identidad digital propia.
- Pontus-X u otras redes federadas pueden coexistir para operaciones externas o federadas, pero no sustituyen necesariamente la red de identidad propia del dataspace.
- El flujo de onboarding legal y de onboarding técnico no son lo mismo, aunque estén conectados.
- En el contexto de onboarding de hosts, el segmento que históricamente se llama `sector` en algunas rutas no representa un sector de negocio sino el tipo de red o entorno operativo.

## Separación de redes

### Red de identidad

Debe existir una red o canal de identidad separado para:

- alta de identidades digitales de hosts
- binding de `did:web`
- binding de JWKs / JWKS
- binding del `controller kid`
- estado de la identidad digital
- metadatos mínimos de confianza y pertenencia

Esta red es la base de confianza común del dataspace.

### Redes sectoriales o de dominio

Además de la red de identidad, pueden existir redes o canales sectoriales para anclar:

- hashes de documentos
- hashes de reglas de acceso
- evidencias de publicación
- estados o eventos sectoriales que no deben mezclarse con la identidad base

Para animales, el arranque puede hacerse con redes globales para optimizar infraestructura.

Para health-care, la regionalización futura existe como dirección de arquitectura, pero no se fija en este documento.

La granularidad exacta de estas redes no debe fijarse todavía aquí con nombres concretos. En particular:

- este documento no fija taxonomía veterinaria detallada
- este documento no fija nombres regionales concretos
- la taxonomía veterinaria futura se aterrizará en `uhc-sdk-core-ts`
- en ICA, por ahora, solo se documenta un dominio animal inicial único

## Flujo general de onboarding de un hosting service

### 1. Alta legal o comercial en ICA

El flujo empieza en la ICA con una solicitud de alta respaldada por:

- un PDF firmado, o
- un formulario estructurado firmado con `meta.claims`, o
- un contrato equivalente admitido por ICA

La ICA valida:

- identidad del representante
- datos organizativos
- tipo de actor
- entorno o tipo de red solicitada
- capacidades o perfil operativo solicitados

El resultado de esta fase es una licencia, autorización o registro aprobable para continuar.

### 2. Bootstrap auth

Una vez aprobada esa alta, el hosting service no entra todavía por CSR.

Primero realiza el intercambio auth para obtener un `initial_access_token`, que servirá para el registro técnico posterior.

Conceptualmente:

- la licencia o activation code permite el exchange
- el exchange devuelve el `initial_access_token`
- el `initial_access_token` permite el DCR

### 3. DCR

Con el `initial_access_token`, el hosting service registra su identidad técnica cliente/backend ante ICA.

En esta fase ICA puede consolidar o persistir:

- `did:web` del hosting
- JWKs operativas
- `controller kid`
- material base para DID Documents
- binding inicial en blockchain de esa identidad digital

### 4. CSR

Solo después del alta legal y del bootstrap auth/DCR se pide el CSR.

En esta fase:

- el hosting genera localmente su clave privada
- el hosting genera localmente el CSR
- ICA valida que el actor ya está autorizado y correctamente vinculado
- ICA tramita la emisión interna contra su CA/Fabric CA
- ICA devuelve certificado y cadena

## Reglas de seguridad

- La clave privada del host debe generarse en el host, no en la ICA, salvo casos excepcionales controlados.
- `fabric-ca` no debe exponerse públicamente a Internet.
- La ICA pública actúa como pasarela, capa de política y punto de control.
- Las APIs públicas, `did.json`, `jwks.json` y artefactos de discovery pueden exponerse.
- La infraestructura interna de CA, peers y orderers debe permanecer en red privada.

## Interpretación del segmento de red en rutas

Para este flujo concreto, el segmento usado en las rutas para el alta de hosts no debe interpretarse como sector de negocio.

Debe interpretarse como:

- entorno de red, o
- tipo de red operativa

Ejemplos conceptuales:

- red de pruebas
- red productiva
- red Fabric de identidad

Los nombres concretos se decidirán en los repos o documentos que definan el despliegue operativo.

## Qué no fija este documento

Este documento no fija:

- nombres concretos de canales Fabric
- nombres concretos de redes regionales o globales
- taxonomía final de dominios animales
- taxonomía final de regiones health-care
- contratos OpenAPI definitivos de cada endpoint

## Límite actual por repos

- `dataspace-ica-ts`
  de momento solo debe hablar del dominio animal inicial `animal-pet-global`
- `uhc-sdk-core-ts`
  será el repositorio donde se defina la taxonomía veterinaria más fina
- `gdc-common-utils-ts`
  no debe fijar taxonomía de redes animales ni regionalización concreta

Solo fija la forma de la solución y la separación conceptual necesaria para no mezclar:

- onboarding legal
- bootstrap auth
- registro técnico DCR
- emisión PKI por CSR
