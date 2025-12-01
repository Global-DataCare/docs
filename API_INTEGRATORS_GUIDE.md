# Gateway API Service: Integration Guide

This guide provides a comprehensive, step-by-step walkthrough for the complete API integration flow, from registering a new organization to onboarding its first customer.

**Interactive Documentation:** All endpoints are documented and can be tested interactively via the Swagger UI at the `/api-docs` endpoint of the running service.

## 1. Vision: The Unified Health ID and Index

The Gateway Service is the cornerstone of a shared data space, enabling individuals to maintain a real-time **Unified Health Index (UHIx)** through explicit, legally compliant consents. This capability is critical for enhancing personal safety, especially in emergencies where an individual may be unable to communicate, and for empowering users with varying levels of digital literacy or physical abilities.

The UHIx functions as a comprehensive, longitudinal "table of contents," linking to a patient's health data providers worldwide. It allows authorized practitioners and individuals to construct a **unified International Patient Summary (IPS)** by retrieving distinct clinical documents and data from decentralized healthcare and insurance providers across the globe. This approach empowers individuals to maintain an automatically updated health record, regardless of their technical expertise.

Furthermore, the UHIx provides individuals with the option to participate in research studies with full control, allowing them to share an anonymized digital twin of their health data.


### 1.1. Architectural Role

The Gateway Service is a microservice that connects client organizations (e.g., hospitals, clinics, research institutions) with the blockchain nodes that serve as the primary trust anchors in the data space. Its key responsibilities include:

-   **Consent Management:** Collecting and storing signed consent forms (e.g., PDFs) to activate an individual's UHIx.
-   **Real-Time Updates:** Ensuring that the sections and resource links in a patient’s UHIx are updated in real-time.
-   **Secure Communication:** Enabling healthcare and insurance providers to establish secure communication channels based on granular permissions. This allows for the secure exchange of information—such as appointments, consents, contracts, invoices, and emergency contacts—with a patient's authorized endpoints, complete with audit logs.

This architecture is built on the **International Patient Summary (IPS) standard (ISO 27269)**, which is endorsed by the G7 and EU for global healthcare data exchange and is supported by major EHR systems.

---

## 2. Core Concepts: Digital Identity and Endpoint Resolution

Before interacting with the API, it is essential to understand how identity and service endpoints are managed within this data space. The entire system is built on the W3C `did:web` standard.

### 2.1. What is `did:web`?

The `did:web` method is a decentralized identifier that leverages a standard HTTPS domain name as its root of trust. It provides a simple and secure way to link a domain you control to a cryptographic identity.

A `did:web` identifier is resolved to an HTTPS URL to retrieve a **DID Document** (a `did.json` file). The method converts each `:` in the DID into a `/` in the URL path. This document contains the entity's public keys and service endpoints.

-   **Self-Hosted DID:** `did:web:api.acme-hospital.com` resolves to **URL:** `https://api.acme-hospital.com/.well-known/did.json`
-   **Hosted DID:** `did:web:connector.host.com:acme-hospital:cds-es:v1:health-care` resolves to **URL:** `https://connector.host.com/acme-hospital/cds-es/v1/health-care/.well-known/did.json`

All endpoints described in this guide are relative to the base URL derived from an entity's `did:web` identifier.


### 2.2. Hosted vs. Self-Hosted Identity Models

After an organization registers with the gateway's host, it will operate under one of two identity models:

1.  **Self-Hosted (External Domain):** The organization runs its own instance of the Gateway API Service on its domain.
    -   **`did:web` Example:** `did:web:api.acme-hospital.com`
    -   **Endpoint Base:** `https://api.acme-hospital.com/`

2.  **Hosted:** The organization utilizes the shared infrastructure provided by the host connector. Its identity is namespaced under the host's domain, including path segments for the tenant ID, jurisdiction, version, and sector.
    -   **`did:web` Example:** `did:web:connector.host.com:acme-hospital:cds-es:v1:health-care`
    -   **Endpoint Base:** `https://connector.host.com/acme-hospital/cds-es/v1/health-care/`


---

## 3. Security Philosophy and Architecture

The architecture is founded on a robust combination of standards from Self-Sovereign Identity (SSI), HL7 FHIR, and the Financial-grade API (FAPI) Security Profile. This synergy creates the **Unified Health ID Protocol**, a new paradigm in health data security engineered to provide **military-grade, post-quantum protection** for all interactions.

### 3.1. The Threat: Beyond HTTPS

In today's hostile digital landscape, relying solely on HTTPS is insufficient. Advanced Persistent Threat (APT) actors deploy sophisticated malware, such as the infamous **"Turla" and "Snake" implants**, designed to compromise systems at a fundamental level.

These threats bypass traditional transport security by operating within the compromised system itself. They intercept data from memory **after** it has been decrypted by the TLS/HTTPS protocol or **before** it is encrypted. This allows them to capture plaintext secrets like access tokens and API keys, rendering transport-layer security ineffective on its own.

### 3.2. Our Solution: Defense-in-Depth with JWE/DIDComm

The Gateway API Service operates in a "zero-trust" environment, protecting the **data itself**, not just the channel it travels through. Our protocol is analogous to placing an armored truck inside a tunnel—even if an attacker breaches the tunnel (bypasses HTTPS), they still cannot access the contents of the armored truck (our secure message).

Every secure message is a **JWE/DIDComm** object: a JSON Web Encryption (JWE) that encrypts a signed JSON Web Signature (JWS). This JWS contains a message with the specific structure and semantics of a DIDComm payload (`body`, `thid`, etc.), providing three critical layers of defense:

1.  **Confidentiality (JWE):** The entire message is encrypted. If malware intercepts it from memory, it only captures an indecipherable block of ciphertext.
2.  **Integrity and Authenticity (JWS):** The inner message is digitally signed, proving its origin and ensuring it has not been tampered with.
3.  **Post-Quantum Cryptography:** We utilize Post-Quantum Cryptography (PQC) algorithms to safeguard against future threats from quantum computers.

### 3.3. Proactive Defense: Resilience Through DIDComm

The use of a JWE/DIDComm message structure is a deliberate strategic choice that enables unparalleled operational resilience, which is essential as the healthcare sector is a critical component of national security.

**What is DIDComm?** DIDComm is a secure messaging protocol built on Decentralized Identifiers (DIDs) and JOSE standards (JWE/JWS). Crucially, it is **transport-agnostic**, meaning it standardizes the *message format*, not how it is transmitted.

**Enabling Offline and Disconnected Operations:** This transport independence allows for the continuation of critical data sharing even when internet connectivity is lost. In mission-critical scenarios—such as a disaster zone or a hospital during a network outage—professionals can securely exchange confidential information directly between their devices using local networks like Bluetooth. When connectivity is restored, the applications can seamlessly synchronize their state with the Gateway.


### 3.4. Asynchronous vs. Synchronous Endpoints

The Gateway's architecture distinctly separates public discovery from secure transactions.

| Feature           | Public Discovery (`/.well-known`)                         | Secure Transactions (e.g., `/Consent/_batch`)          |
| ----------------- | --------------------------------------------------------- | ------------------------------------------------------ |
| **Method**        | `GET`                                                     | `POST`                                                 |
| **Synchronicity** | **Synchronous**                                           | **Asynchronous**                                       |
| **Security**      | Public, Unprotected (Served over HTTPS)                   | End-to-End Encrypted (JWE/DIDComm)                     |
| **Purpose**       | Discovering public identity, keys, and capabilities.      | Securely processing confidential transactions.         |

All secure endpoints handling confidential information operate asynchronously, adhering to the FAPI Polling Pattern:

1.  The client `POST`s a secure JWE/DIDComm message.
2.  The server immediately returns an `HTTP 202 Accepted` response with a `thid` for correlation.
3.  The client polls a separate endpoint using the `thid` until the final, secure JARM response is available.
4.  The polling endpoint provides the final JWE/DIDComm message for the client to decrypt.

### 3.5. Standardized Discovery with `/.well-known`

For a client to trust the gateway, it must first discover its capabilities and public keys via the standardized `/.well-known/` path (RFC 8615).

**Key supported `.well-known` endpoints include:**
-   `/.well-known/did.json`: Provides the entity's W3C DID Document.
-   `/.well-known/jwks.json`: The entity's public keys as a JSON Web Key Set (JWKS).
-   `/.well-known/openid-configuration`: The standard discovery document for OpenID Connect endpoints.
-   `/.well-known/smart-configuration`: The discovery document for SMART on FHIR.
-   `/.well-known/fhir/capabilitystatement`: The standard discovery document for HL7 FHIR API capabilities.
-   `/.well-known/self-description.json`: The entity's GAIA-X Self-Description Verifiable Credential.


## 4. Interaction Modes

### 4.1. FHIR Legacy Mode (Insecure)

This mode is available for basic interoperability testing on the test network. **It MUST NOT be used for sensitive data.**

-   **`Content-Type`:** `application/fhir+json`
-   **`Body`:** A standard, unprotected FHIR resource.
-   **Response:** A synchronous `application/fhir+json` response.

### 4.2. Secure JWE/DIDComm Mode

This is the **mandatory** mode for all production traffic. It follows the FAPI **JWT-Secured Authorization Request (JAR)** pattern, wrapped in an encrypted envelope according to the **sign-then-encrypt** methodology of DIDComm.

-   **`Content-Type` Header:** `application/x-www-form-urlencoded`
-   **`Body`:** The body must contain a single `request` parameter, whose value is the complete JWE object.
    -   Example: `request=eyJhbGciOiJSU0Et...`

#### Cryptographic Layering

The `request` parameter is a JWE constructed with the following nested structure: `JWE(JWS(DIDComm Plaintext))`

1.  **Inner Payload (DIDComm Plaintext):** The core message, as defined in Section 5.
2.  **JWS Layer (Signature):** The plaintext payload is signed as a JWS.
3.  **JWE Layer (Encryption):** The entire JWS is then encrypted as a JWE. The JWE Protected Header **must** include a `typ` (Type) header with the value `"application/didcomm-encrypted+json"`. This header signals to the recipient that the object is an encrypted DIDComm message before decryption begins.

-   **Response:** The response is delivered asynchronously via the FAPI polling flow.


## 5. The DIDComm Message Payload

The plaintext of a JWE/DIDComm message is a JSON object containing the following top-level properties:

| Property          | Type     | Required? | Description                                                                                                                              |
| ----------------- | -------- | --------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `jti`             | `string` | **Yes**   | **JWT ID:** A unique message identifier to prevent replay attacks.                                                                       |
| `iss`             | `string` | **Yes**   | **Issuer:** The DID of the client application.                                                                                           |
| `aud`             | `string` | **Yes**   | **Audience:** The URL or DID of the gateway endpoint.                                                                                    |
| `thid`            | `string` | **Yes**   | **Thread ID:** A correlation identifier for requests and their corresponding asynchronous responses.                                   |
| `type`            | `string` | **Yes**   | **Message Type:** A URI that defines the protocol or data format of the `body`.                                                          |
| `response_type`   | `string` | No        | **Response Content Type:** Overrides the HTTP `Accept` header. It informs the server of the desired format for the final JARM response payload. |
| `response_mode`   | `string` | No        | **Response Protocol:** Specifies the format of the JARM response itself.                                                                 |
| `body`            | `object` | **Yes**   | **Business Payload:** The content of the request, structured according to the `type` field.                                              |


---

## 6. Onboarding a New Organization

This section details the secure workflow for registering a new organization. The process is built on OpenID Connect (OIDC), Dynamic Client Registration (DCR), and the Financial-grade API (FAPI) Security Profile.

Onboarding a new organization involves registering its legal information, creating a self-issued verifiable credential, generating a DID Document for its API connector, and verifying the legal information to obtain a verifiable presentation signed by a government entity. This final step is required for production network access.

-   For `host-level` operations related to the network (e.g., registering a new tenant), the `:sector` is `test`. This will evolve to `test-network` and `network` to manage access to the underlying blockchain ledger.

HTTP requests must include the following headers:

-   `App-ID` (mandatory): The Application ID assigned to the frontend application (web or native).
-   `App-Version` (mandatory): The user-facing application version.
-   `Authorization: Bearer` (mandatory): An `id_token` for organization registration and order endpoints, and a `smart-access-token` for subsequent requests.
-   `Platform-Version` (optional): Identifies the version of the intermediary server (for future use).

The SMART flow uses the `scope` property as defined by the SMART-on-FHIR v2.0 specification.

For demonstration purposes, `Content-Type: application/didcomm-plaintext+json` (or `application/json`) is permitted. However, in production, all messages must be secured using the FAPI Security Profile (based on JAR and JARM), where `Content-Type: application/x-www-form-urlencoded` is used to submit and receive encrypted messages via the `request` and `response` form parameters.

The following documentation explains the flow for demonstration purposes.


### 6.1. Step 1: Register a New Tenant (Organization)

This is the first step for any new organization. A legally authorized representative submits an asynchronous job to the `host`, proving their identity via an OIDC `id_token` from a trusted provider (e.g., Google, Apple, eIDAS). The `id_token` serves as a verifiable assertion of the representative's identity, which is crucial for establishing the initial trust anchor for the new tenant.

**Endpoint:** `POST /host/cds-{jurisdiction}/v1/test/registry/org.schema/Organization/_batch`

**`curl` Example:**
```bash
# -X POST: Specifies the HTTP POST method.
# --header: Provides necessary HTTP headers for the request.
#   - App-ID & App-Version: Identify the client application.
#   - Authorization: Contains the OIDC id_token of the legal representative.
#   - Content-Type: Indicates the payload is a plaintext DIDComm message (for demo).
# --data: Contains the JSON payload of the DIDComm message.
curl -X POST 'http://localhost:3000/host/cds-es/v1/test/registry/org.schema/Organization/_batch' \
--header 'App-ID: [APP-ID]' \
--header 'App-Version: [APP-VERSION]' \
--header 'Authorization: Bearer [OIDC_ID_TOKEN_OF_LEGAL_REP]' \
--header 'Content-Type: application/didcomm-plaintext+json' \
--data '{
  "jti": "org-registration-request-id",
  "thid": "org-registration-thread-id",
  "iss": "urn:ietf:rfc:7638:thumbprint-public-sig-key-device",
  "aud": "did:web:host.example.com",
  "exp": 1678886460,
  "iat": 1678886400,
  "nbf": 1678886400,
  "type": "application/json+api",
  "body": {
    "data": [
      {
        "type": "Organization-registration-form-v1.0",
        "meta": {
          "claims": {
            "@context": "org.schema",
            "@type": "template",
            "org.schema.Organization.address.addressCountry": "ES",
            "org.schema.Organization.alternateName": "acme",
            "org.schema.Organization.identifier.additionalType": "TAX",
            "org.schema.Organization.identifier.value": "A123456789",
            "org.schema.Organization.legalName": "Acme Organization SL",
            "org.schema.Organization.name": "Acme Org",
            "org.schema.Organization.numberOfEmployees.value": 2,
            "org.schema.Organization.url": "api.acme.org",
            "org.schema.Person.email": "admin1@acme.org",
            "org.schema.Person.hasOccupation": "ISCO-08:1120",
            "org.schema.Service.category": "health-care",
            "org.schema.Service.identifier": "did:web:api-provider.example.com",
            "org.schema.Service.serviceType": "http://terminology.hl7.org/CodeSystem/v3-ActReason|SRVC",
            "org.schema.Service.termsOfService": "data:application/pdf;base64,JVBERi0xLjQKMSAwIG9iago8PCAvVHlwZSAvQ2F0YWxvZyAvUGFnZXMgMiAwIFIgPj4KZW5kb2JqCjIgMCBvYmoKPDwgL1R5cGUgL1BhZ2VzIC9LaWRzIFszIDAgUl0gL0NvdW50IDEgPj4KZW5kb2JqCjMgMCBvYmoKPDwgL1R5cGUgL1BhZ2UgL1BhcmVudCAyIDAgUiAvTWVkaWFCb3ggWzAgMCAzMDAgMjAwXSAvQ29udGVudHMgNCAwIFIgL1Jlc291cmNlcyA8PCAvRm9udCA8PCAvRjEgNSAwIFIgPj4+PiA+PgplbmRvYmoKNCAwIG9iago8PCAvTGVuZ3RoIDQ0ID4+CnN0cmVhbQpCVAovRjEgMjQgVGYKMTAwIDEwMCBUZAooSGVsbG8gUERGKSBUagoKRVQKZW5kc3RyZWFtCmVuZG9iago1IDAgb2JqCjw8IC9UeXBlIC9Gb250IC9TdWJ0eXBlIC9UeXBlMSAvQmFzZUZvbnQgL0hlbHZldGljYSA+PgplbmRvYmoKeHJlZgowIDYKMDAwMDAwMDAwMCA2NTUzNSBmIAowMDAwMDAwMDEwIDAwMDAwIG4gCjAwMDAwMDAwNTMgMDAwMDAgbiAKMDAwMDAwMDEwNiAwMDAwMCBuIAowMDAwMDAwMjU1IDAwMDAwIG4gCjAwMDAwMDAzNDMgMDAwMDAgbiAKdHJhaWxlcgo8PCAvU2l6ZSA2IC9Sb290IDEgMCBSID4+CnN0YXJ0eHJlZgo0MDMKJSVFT0Y="
          }
        }
      }
    ]
  },
  "meta": {
    "jwe": {
      "header": {
        "jwk": {
          "crv": "ML-KEM-768",
          "kid": "thumbprint-enc-key",
          "kty": "OKP",
          "use": "enc",
          "x": "base64url-public-enc-key-device"
        }
      }
    },
    "jws": {
      "protected": {
        "jwk": {
          "alg": "ML-DSA-44",
          "kid": "thumbprint-sig-key-device",
          "kty": "AKP",
          "pub": "base64url-public-sig-key",
          "use": "sig"
        }
      }
    }
  }
}' -i
```
**Note:** The `meta` object containing the JSON Web Keys (JWKs) is for demonstration purposes only. In production, messages are signed and encrypted, and the `jwk` property is required in the secure envelope (JWS and JWE/DIDComm) for the organization registration request.

**Expected Response (`202 Accepted`):**
The server acknowledges the request immediately and provides a polling location.
```http
HTTP/1.1 202 Accepted
Location: http://localhost:3000/host/cds-es/v1/test/registry/org.schema/Organization/_batch-response
Retry-After: 5
```

**Polling for Organization Registration Response**

To retrieve the result of the asynchronous registration job, the client sends a `POST` request to the `Location` URL provided in the `202 Accepted` response. This polling mechanism is a core part of the FAPI security profile, preventing long-held connections and improving system resilience.

The polling request body contains the `thid` (thread ID) from the original request, allowing the server to correlate the poll with the correct job.

```bash
# Use the 'thid' from the original request body in the polling request.
# The 'thid' is sent as a URL-encoded form parameter.
curl -X POST 'http://localhost:3000/host/cds-es/v1/test/registry/org.schema/Organization/_batch-response' \
--header 'App-ID: [APP-ID]' \
--header 'App-Version: [APP-VERSION]' \
--header 'Authorization: Bearer [OIDC_ID_TOKEN_OF_LEGAL_REP]' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'thid=org-registration-thread-id'
```

*Polling retrieves the final outcome of the registration job. A successful response confirms the tenant has been created, while an error response will detail the failure.*

When the client polls for the result, a successful response will confirm the provisional creation of the tenant and include a formal, signed `Offer` with a unique identifier. This `Offer` must be accepted in the next step to finalize the registration.

The `aud` (audience) of the backend's response is the public encryption key of the software application, as defined by IETF RFC 7638 for calculating the `thumbprint` of the JWK.


**Example Response:**
```json
{
  "jti": "org-registration-response-id",
  "thid": "org-registration-thread-id",
  "aud": "urn:ietf:rfc:7638:thumbprint-public-enc-key-device",
  "iss": "did:web:host.example.com#v1_<network>_registry_org.schema_organization_batch",
  "exp": 1678886460,
  "iat": 1678886400,
  "nbf": 1678886400,
  "type": "application/json+api",
  "body": {
    "data": [
      {
        "type": "Organization-registration-offer-v1.0",
        "meta": {
          "claims": {
            "@context": "org.schema",
            "@type": "receipt",
            "org.schema.Organization.address.addressCountry": "ES",
            "org.schema.Organization.alternateName": "acme",
            "org.schema.Organization.identifier.additionalType": "TAX",
            "org.schema.Organization.identifier.value": "A123456789",
            "org.schema.Organization.legalName": "Acme Organization SL",
            "org.schema.Organization.name": "Acme Org",
            "org.schema.Organization.numberOfEmployees.value": 2,
            "org.schema.Organization.url": "api.acme.org",
            "org.schema.Person.email": "admin1@acme.org",
            "org.schema.Person.hasOccupation": "ISCO-08:1120",
            "org.schema.Service.category": "health-care",
            "org.schema.Service.identifier": "did:web:api-provider.example.com",
            "org.schema.Service.serviceType": "http://terminology.hl7.org/CodeSystem/v3-ActReason|SRVC",
            "org.schema.Service.termsOfService": "<url-stored-pdf>",
            "org.schema.Offer.acceptedPaymentMethod": "Stripe",
            "org.schema.Offer.category": "health-care",
            "org.schema.Offer.checkoutPageURLTemplate": "<payment-url>",
            "org.schema.Offer.eligibleCustomerType": "employee",
            "org.schema.Offer.eligibleQuantity.value": 2,
            "org.schema.Offer.identifier": "urn:cds-<jurisdiction>:v1:<sector>:product:org.schema:Offer:<offer-uuid>",
            "org.schema.Offer.itemOffered.name": "License Tier XS",
            "org.schema.Offer.itemOffered.sku": "web-or-app-identifier",
            "org.schema.Offer.offeredBy": "did:web:host.example.com",
            "org.schema.Offer.price": "0.00",
            "org.schema.Offer.priceCurrency": "EUR",
            "org.schema.Offer.serialNumber": "<license1>,<license2>"
          }
        }
      }
    ]
  }
}
```

### 6.2. Step 2: Confirm the Order for Registration

Once the registration `Offer` is received, the legal representative must formally accept it by submitting an order request. This step is crucial as it represents the contractual acceptance of the terms and conditions for the new tenant.

The request must be sent using the same cryptographic keys from the initial registration, identified by their respective `kid` (Key ID) properties in the secure envelope. This ensures that only the original requesting party can complete the registration.

**`curl` Example:**
```bash
# -X POST: Specifies the HTTP POST method.
# --header: Provides necessary HTTP headers for the request.
#   - Authorization: Contains the OIDC id_token of the legal representative.
#   - Content-Type: Indicates a standard JSON payload.
# --data: Contains the JSON payload of the DIDComm message.
curl -X POST 'http://localhost:3000/host/cds-es/v1/test/registry/org.schema/Order/_batch' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer [OIDC_ID_TOKEN_OF_LEGAL_REP]' \
--data '{
  "jti": "org-order-request-id",
  "thid": "org-order-thread-id",
  "iss": "urn:ietf:rfc:7638:thumbprint-public-sig-key-device",
  "aud": "did:web:host.example.com",
  "exp": 1678886460,
  "iat": 1678886400,
  "nbf": 1678886400,
  "type": "application/json+api",
  "body": {
    "data": [
      {
        "type": "Organization-order-request-v1.0",
        "meta": {
          "claims": {
            "@context": "org.schema",
            // This identifier MUST match the 'Offer.identifier' from the previous response.
            "Order.acceptedOffer.identifier": "urn:cds-<jurisdiction>:v1:<sector>:product:org.schema:Offer:<offer-uuid>"
          }
        }
      }
    ]
  },
  "meta": {
    "jwe": {
      "header": {
        "kid": "thumbprint-public-enc-key-device"
      }
    },
    "jws": {
      "protected": {
        "kid": "thumbprint-public-sig-key-device"
      }
    }
  }
}' -i
```

**Note:** As previously explained, the `meta` object is for demonstration purposes. The secure envelope in production MUST include the `kid` and `skid` properties.

**Example Expected Response (`202 Accepted`):**
The server acknowledges the order request and provides a new polling location for the order status.
```http
HTTP/1.1 202 Accepted
Location: http://localhost:3000/host/cds-es/v1/test/registry/org.schema/Order/_batch-response
Retry-After: 5
```

The backend creates a checkout session with the payment gateway, which returns a payment page URL in the response.

**Example Polling for Organization's Order Response:**
Polling the new `-response` endpoint retrieves the outcome of the order submission.
```bash
# Use the 'thid' from the order request body in the polling request.
curl -X POST 'http://localhost:3000/host/cds-es/v1/test/registry/org.schema/Organization/_batch-response' \
--header 'App-ID: [APP-ID]' \
--header 'App-Version: [APP-VERSION]' \
--header 'Authorization: Bearer [OIDC_ID_TOKEN_OF_LEGAL_REP]' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'thid=org-order-thread-id'
```

**Example Response with Payment URL:**
A successful response contains the URL for the payment gateway. The user must be redirected to this URL to complete the payment and finalize the registration.
```json
{
  "jti": "org-order-response-id",
  "thid": "org-order-thread-id",
  "aud": "urn:ietf:rfc:7638:thumbprint-public-enc-key-device",
  "iss": "did:web:host.example.com",
  "exp": 1678886460,
  "iat": 1678886400,
  "nbf": 1678886400,  
  "type": "application/json",
  "body": {
    "url": "<payment-url>"
  }
}
```

The payment gateway notifies the backend upon successful payment, and the license serial numbers from the offer are registered for the new organization.


---

## 7. Device and Identity Registration

This section details the critical process of registering a device for a user (such as the organization's legal representative, an employee, or a customer) and establishing their self-sovereign, post-quantum identity within the system.

The `:sector` parameter in the URL path has a specific meaning:

-   For tenant-specific operations (like creating an employee or customer), the `:sector` is the tenant's own operational sector (e.g., `health-care`, `health-insurance`).

For demo purposes is allowed to use `Content-Type: application/didcomm-plaintext+json` (or just `Content-Type: application/json` for brevity) in the HTTP Header, but in production the requisite is to enable secure DIDComm messages using the FAPI Security Profile (based on JAR and JARM), where `Content-Type: application/x-www-form-urlencoded` enables the `request` and `response` form parameters to submit and receive the encrypted messages.

The following documentation explains the flow for demo purposes.

### 7.1. Step 3: Register a Self-Sovereign, Post-Quantum Identity from a Device

This single, atomic transaction accomplishes two fundamental goals:
1.  It consumes a license serial number (`code`) to authorize the registration.
2.  It registers a new post-quantum, self-sovereign identity for the user's device, represented by a unique `client_id` and its associated cryptographic keys (`jwks`).

This process securely links the user's traditional identity credential (an OIDC `id_token`) to their new decentralized identity. The server validates all inputs, consumes the license, generates the `client_id` (`did:web`), and permanently stores the device's public keys.

Traditionally, the Dynamic Client Registration endpoint requires an `initial_access_token`. In this implementation, that PKCE flow is replaced: authorization is achieved by combining a pre-purchased license `code` with the user's `id_token` (from a trusted provider like Google, Apple, or eIDAS). The email used to get the `id_token` MUST match the email registered for the user.

**Endpoint:** `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/identity/openid/Device/_dcr`

Below is the **plaintext content** of the DIDComm message.

```json
{
  "jti": "device-registration-request-id",
  "thid": "device-registration-thread-id",
  "iss": "urn:ietf:rfc:7638:thumbprint-public-sig-key-device",
  "aud": "did:web:api.acme.org#identity_openid_device_dcr",
  "exp": 1678886460,
  "iat": 1678886400,
  "nbf": 1678886400,
  "type": "application/json",
  "body": {
    "application_type": "native",
    "client_name": "App for [email] as [role] on [iOS, Android, Web]",
    "code": "<license-code>",
    "redirect_uris": ["myapp://callback"],
    "token_endpoint_auth_method": "private_key_jwt",
    "ext_device_info": {
      "device_id": "iOS-17.1.2-ABC-123",
      "device_name": "User's iPhone 15 Pro",
      "os": "iOS",
      "os_version": "17.1.2",
      "push_provider": "expo",
      "push_token": "ExponentPushToken[xxxxxxxxxxxxxxxxxxxxxx]"
    },
    "jwks_uri": "did:web:api.acme.org:employee:<email-address>:isco-08:<role-value>",
    "jwks": {
      "keys": [
        {
          "alg": "ML-DSA-44",
          "kid": "thumbprint-sig-key",
          "kty": "AKP",
          "pub": "mock-sig-key",
          "use": "sig"
        },
        {
          "crv": "ML-KEM-768",
          "kid": "thumbprint-enc-key",
          "kty": "OKP",
          "x": "mock-enc-key",
          "use": "enc"
        }
      ]
    }
  }
}
```

-   **`iss`**: The Decentralized Identifier of the client application. In this initial step, it is a thumbprint of the public key, as the full `did:web` has not yet been assigned.
-   **`aud`**: The specific audience for the identity registration endpoint.
-   **`body.code`**: The single-use license activation `code`.
-   **`body.jwks`**: The complete JSON Web Key Set containing the client's new Post-Quantum public keys for signing (`sig`) and encryption (`enc`). For the legal representative's first device, `jwks_uri` can be used instead, as the keys were provided during the initial organization registration.
-   **`body.ext_device_info`**: Required metadata about the physical device.

Upon successful processing of this asynchronous job, the application running on the user's device will have a permanent `client_id` (a `did:web` identifier), and its public keys will be officially associated with it.

**Example: Expected Response (`202 Accepted`)**
```http
HTTP/1.1 202 Accepted
Location: http://localhost:3000/acme/cds-es/v1/health-care/identity/openid/Device/_dcr-response
Retry-After: 5
```

**Example: Polling for Client ID Registration**
```bash
# Use the 'thid' from the original request body in the polling request as a form parameter.
curl -X POST 'http://localhost:3000/acme/cds-es/v1/health-care/identity/openid/Device/_dcr-response' \
--header 'App-ID: [APP-ID]' \
--header 'App-Version: [APP-VERSION]' \
--header 'Authorization: Bearer [OIDC_ID_TOKEN]' \
--header 'Content-Type: application/x-www-form-urlencoded'  \
--data-urlencode 'thid=device-registration-thread-id'
```

**Example: Response with the `client_id`**
The final response contains the newly created `client_id`, which is the official `did:web` identifier for this device.

```json
{
  "jti": "device-registration-response-id",
  "thid": "device-registration-thread-id",
  "aud": "urn:ietf:rfc:7638:thumbprint-public-enc-key-device",
  "iss": "did:web:api.acme.org",
  "exp": 1678886460,
  "iat": 1678886400,
  "nbf": 1678886400,  
  "type": "application/json",
  "body": {
   "client_id": "did:web:api.acme.org:employee:admin1@acme.org:device:<uuid>"
  }
}
```

With a registered `client_id`, the application can now request scoped `access_token`s to perform actions.

### 7.2. Step 4: Authenticating and Obtaining Scoped Access Tokens

Before a client application can perform operations, it must obtain a SMART App Launch `access_token`. This token grants the application specific, fine-grained permissions (scopes) to interact with resources.

The client authenticates itself by signing a one-time-use DIDComm message with the private key corresponding to the `client_id` registered in the previous step.

#### Secure Envelope: JWE and JWS Headers

For production, the DIDComm message must be a JWE wrapping a JWS. The headers of these envelopes are critical for security and must be constructed as follows:

**JWE Header (Encryption Layer):**
-   `crv` (required): The JWA algorithm for the key agreement protocol (e.g., `ML-KEM-768`).
-   `kid` (required): The identifier of the connector's public key used to encrypt the message.
-   `skid` (required): The identifier of the client's public key.
-   `typ` (required): Must be `"application/didcomm-encrypted+json"`.

**JWS Header (Signature Layer):**
-   `alg` (required): The JWA algorithm used for signing (e.g., `ML-DSA-44`).
-   `kid` (required): The identifier of the client's private key used to sign the JWT.
-   `typ` (required): Must be `"didcomm-signed+json"`.
-   `jku` (optional): The URL pointing to the JWK Set containing the public key. This is not mandatory, as the key can be resolved from the `iss` claim (`did:web`).

#### The Token Request Payload

The plaintext `body` of the DIDComm message contains the token request.

**Key Claims:**
-   **`sub` (Subject):** This crucial claim specifies the entity being acted upon. It can be the same as the `iss` (issuer) or a different entity, enabling scenarios like:
    -   A legal representative (`iss`) acting on behalf of the organization (`sub`).
    -   An employee (`iss`) acting on behalf of a customer (`sub`).
-   **`scope`:** Defines the permissions requested, following SMART v2.0 syntax (e.g., `organization/PractitionerRole.crus`).

The connector is responsible for issuing the access token. Before doing so, it verifies that the requesting entity (`iss`) has the appropriate permissions to perform the operations requested in the `scope` on the subject (`sub`). This verification includes checking against stored consent rules. The resulting signed `access_token` can then be presented to other members of the data space as proof of authorization. For maximum security, the receiving system can further verify the consent rules on the blockchain before granting access.

***Example of a request for a `scoped` SMART token:***
```bash
# This curl example shows the plaintext DIDComm message for requesting a token.
# In production, this payload would be signed and encrypted according to the headers above.
curl -X POST 'http://localhost:3000/acme/cds-es/v1/health-care/identity/openid/auth/token' \
--header 'Content-Type: application/didcomm-plaintext+json' \
--data '{
  "jti": "smart-token-request-id",
  "thid": "smart-token-thread-id",
  "iss": "did:web:api.acme.org:employee:admin1@acme.org:device:<uuid>",
  "aud": "did:web:api.acme.org",
  "exp": 1678886460,
  "iat": 1678886400,
  "nbf": 1678886400,
  "type": "application/json",
  "body": {
    "expires_in": 300,
    "token_type": "Bearer",
    "sub": "did:web:api.acme.org",
    "scope": "organization/PractitionerRole.crus"
  },
  "meta": {
    "jwe:": {
      "header": {
        "skid": "thumbprint-public-enc-key-device"
      }
    },    
    "jws:": {
      "protected": {
        "kid": "thumbprint-public-sig-key-device"
      }
    }
  }
}'
```

After polling for the response, the client will receive a standard OAuth 2.0 token response containing the `access_token`. This token must be included as a `Bearer` token in the `Authorization` header for all subsequent API calls.


## 8. End-to-End Business Flows

Now that the organization is registered and the initial administrator has a secure device identity, this section details the complete, end-to-end workflows for common business operations. All actions are performed by obtaining a scoped SMART `access_token` and submitting secure DIDComm messages.

Note that delete operations are generally not permitted for resources like employees to ensure traceability. Instead, objects should be updated to an "inactive" status. For data privacy and "right to be forgotten" requests, specific consent flows must be used to remove an individual's index and personal information.

### 8.1. Step 5: Create an Employee Role

An employee is represented by a `Practitioner` resource, and their roles within the organization are defined by one or more `PractitionerRole` resources.

This action is typically performed by an administrator (e.g., the legal representative from the previous steps) using an `access_token` with the required scope (`organization/PractitionerRole.crus`). The `iss` of the request is the administrator's registered device `client_id`, and the `Authorization` header contains the `access_token` they obtained.

**Endpoint:** `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/entity/org.schema/Employee/_batch`

**`curl` Example:**
```bash
curl -X POST 'http://localhost:3000/acme/cds-es/v1/health-care/entity/org.schema/Employee/_batch' \
--header 'App-ID: [APP-ID]' \
--header 'App-Version: [APP-VERSION]' \
# The Bearer token is a SMART access_token with 'organization/PractitionerRole.crus' scope.
--header 'Authorization: Bearer [SMART_TOKEN_FOR_ADMIN]' \
--header 'Content-Type: application/didcomm-plaintext+json' \
--data '{
  "jti": "employeerole-registration-request-id",
  "thid": "employeerole-registration-thread-id",
  # The 'iss' is the client_id of the administrator's device.
  "iss": "did:web:api.acme.org:employee:admin1@acme.org:device:<uuid>",
  "aud": "did:web:api.acme.org",
  "exp": 1678886460,
  "iat": 1678886400,
  "nbf": 1678886400,  
  "type": "application/json+api",
  "body": {
    "data": [{
      "type": "Employee-form-v1.0",
      "meta": { "claims": {
          "org.schema.Person.identifier": "urn:uuid:11b2c3d4-e5f6-7890-1234-567890abcdef",
          "org.schema.Person.hasOccupation": "ISCO-08:4226",
          "org.schema.Person.email": "receptionist1@acme.org"
      }}
    }]
  },
  "meta": {
    "jwe:": {
      "header": {
        "skid": "thumbprint-public-enc-key-device-admin"
      }
    },    
    "jws:": {
      "protected": {
        "kid": "thumbprint-public-sig-key-device-admin"
      }
    }
  }  
}' -i
```

**Expected Response:** `202 Accepted` with a `Location` header. Polling this location retrieves the final outcome of the job.

### 8.2. Step 6: Onboard an Individual (Customer)

After an employee (e.g., `receptionist1@acme.org`) has been created, they must first register their own device by following the same process in **Step 3** and **Step 4** to get their own `client_id` and a scoped `access_token`.

Once they have an `access_token` with the `customer.create` scope, they can onboard a new customer (individual). The `iss` of the request is now the employee's device `client_id`.

**Endpoint:** `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/individual/org.schema/Person/_batch`

**`curl` Example:**
```bash
curl -X POST 'http://localhost:3000/acme/cds-es/v1/health-care/individual/org.schema/Person/_batch' \
--header 'App-ID: [APP-ID]' \
--header 'App-Version: [APP-VERSION]' \
# The Bearer token is a SMART access_token with 'customer.create' scope.
--header 'Authorization: Bearer [SMART_TOKEN_FOR_EMPLOYEE]' \
--header 'Content-Type: application/didcomm-plaintext+json' \
--data '{
  "jti": "customer-onboard-request-id",
  "thid": "customer-onboard-thread-id",
  # The 'iss' is the client_id of the employee's device.
  "iss": "did:web:api.acme.org:employee:receptionist1@acme.org:device:<uuid>",
  "aud": "did:web:api.acme.org",
  "exp": 1678886460,
  "iat": 1678886400,
  "nbf": 1678886400,   
  "type": "application/json+api",
  "body": {
    "data": [
      {
        "type": "Individual-terms-v1.0",
        "meta": {
          "claims": {
            "org.schema.Person.alternateName": "Joe",
            "org.schema.Person.identifier": "urn:uuid:8e0d846a-2492-4b9c-8a4e-5e065fb6ba76",
            "org.schema.Person.email": "customer1@example.com",
            "org.schema.Service.category": "health-care",
            "org.schema.Service.serviceType": "http://terminology.hl7.org/CodeSystem/v3-ActReason|FAMRQT,PWATRNY,METAMGT,FRAUD,RECORDMGT,COVAUTH,TREAT,DISASTER,HPAYMT,MLTRAINING,ETREAT,HOPERAT,CAREMGT,HSYSADMIN,PATADMIN,PATSFTY",            
            "org.schema.Service.termsOfService": "data:application/pdf;base64,JVBERi0xLjQKMSAwIG9iago8PCAvVHlwZSAvQ2F0YWxvZyAvUGFnZXMgMiAwIFIgPj4KZW5kb2JqCjIgMCBvYmoKPDwgL1R5cGUgL1BhZ2VzIC9LaWRzIFszIDAgUl0gL0NvdW50IDEgPj4KZW5kb2JqCjMgMCBvYmoKPDwgL1R5cGUgL1BhZ2UgL1BhcmVudCAyIDAgUiAvTWVkaWFCb3ggWzAgMCAzMDAgMjAwXSAvQ29udGVudHMgNCAwIFIgL1Jlc291cmNlcyA8PCAvRm9udCA8PCAvRjEgNSAwIFIgPj4+PiA+PgplbmRvYmoKNCAwIG9iago8PCAvTGVuZ3RoIDQ0ID4+CnN0cmVhbQpCVAovRjEgMjQgVGYKMTAwIDEwMCBUZAooSGVsbG8gUERGKSBUagoKRVQKZW5kc3RyZWFtCmVuZG9iago1IDAgb2JqCjw8IC9UeXBlIC9Gb250IC9TdWJ0eXBlIC9UeXBlMSAvQmFzZUZvbnQgL0hlbHZldGljYSA+PgplbmRvYmoKeHJlZgowIDYKMDAwMDAwMDAwMCA2NTUzNSBmIAowMDAwMDAwMDEwIDAwMDAwIG4gCjAwMDAwMDAwNTMgMDAwMDAgbiAKMDAwMDAwMDEwNiAwMDAwMCBuIAowMDAwMDAwMjU1IDAwMDAwIG4gCjAwMDAwMDAzNDMgMDAwMDAgbiAKdHJhaWxlcgo8PCAvU2l6ZSA2IC9Sb290IDEgMCBSID4+CnN0YXJ0eHJlZgo0MDMKJSVFT0Y="
          }
        },
        "request": { "method": "POST", "url": "individual/org.schema/Person/" }
      },
      {
        "type": "Personal-identity-v1.0",
        "meta": {
          "claims": {
            "org.schema.Person.identifier": "urn:uuid:8e0d846a-2492-4b9c-8a4e-5e065fb6ba76",
            "org.schema.Person.identifierType": "NNES",
            "org.schema.Person.identifierValue": "12345678X"
          }
        },
        "request": { "method": "POST", "url": "individual/org.schema/Person/" }
      }
    ]
  }
}' -i
```
**Expected Response:** `202 Accepted` with a `Location` header. Polling retrieves the outcome of the customer onboarding job.

### 8.3. Step 7: Create a Consent Record

After a customer is onboarded, they (or their legal representative) must provide granular consent for data sharing. This is done by creating a `Consent` resource. The request can be issued by an authorized employee or by the individual themselves after they have registered their own device.

**Endpoint:** `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/individual/org.hl7.fhir.r4/Consent/_batch`

**`curl` Example:**
```bash
curl -X POST 'http://localhost:3000/acme/cds-es/v1/health-care/individual/org.hl7.fhir.r4/Consent/_batch' \
--header 'App-ID: [APP-ID]' \
--header 'App-Version: [APP-VERSION]' \
--header 'Authorization: Bearer [SMART_TOKEN_MANAGE_CONSENT]' \
--header 'Content-Type: application/didcomm-plaintext+json' \
--data '{
  "jti": "consent-fhir-request-id",
  "thid": "consent-fhir-thread-id",
  "iss": "did:web:api.acme.org:employee:receptionist1@acme.org:device:<uuid>",
  "aud": "did:web:api.acme.org",
  "exp": 1678886460,
  "iat": 1678886400,
  "nbf": 1678886400,   
  "type": "org.hl7.fhir.r4.Bundle",
  "body": {
    "resourceType": "Bundle",
    "type": "batch",
    "entry": [{
      "type": "Consent",
      "meta": {
        "claims": {
          "@context": "org.hl7.fhir.r4",
          "decision": "permit",
          "subject": "did:web:api.acme.org:individual:customer1@example.com",
          "identifier": "urn:uuid:patient-consent-uuid",
          "grantee": "did:web:hospital.example.com",
          "date": "2025-11-25",
          "purpose": "TREAT",
          "action": "LOINC|48765-2",
          "actor-identifier": "did:web:hospital.example.com",
          "actor-role": "ISCO-08|2221",
          "attachment-contentType": "application/odrl+json",
          "attachment-data": "eyAiQGNvbnRleHQiOiAiaHR0cDovL3d3dy53My5vcmcvbnMvb2RybC5qc29ubGQiLCAiQHR5cGUiOiAiQWdyZWVtZW50Ii...sgIlRSRUFUIiB9XSB9XSB9"
        }
      },         
      "request": {
        "method": "POST",
        "url": "individual/org.hl7.fhir.r4/Consent"
      },
      "resource": {   
        "identifier": [{ "value": "urn:uuid:patient-consent-uuid" }],
        "resourceType": "Consent",
        "status": "active",
        "scope": {
          "coding": [{ 
            "system": "http://terminology.hl7.org/CodeSystem/consentscope",
            "code": "patient-privacy"
          }]
        },
        "category": [{
          "coding": [{
            "system": "http://terminology.hl7.org/CodeSystem/consentcategorycodes",
            "code": "TREAT"
          }]
        }],
        "patient": { "reference": "did:web:api.acme.org:individual:customer1@example.com" },
        "performer": [{ "reference": "did:web:hospital.example.com" }],
        "provision": { "type": "permit" },
        "sourceAttachment": {
          "contentType": "application/odrl+json",
          "data": "eyAiQGNvbnRleHQiOiAiaHR0cDovL3d3dy53My5vcmcvbnMvb2RybC5qc29ubGQiLCAiQHR5cGUiOiAiQWdyZWVtZW50Ii...sgIlRSRUFUIiB9XSB9XSB9"
        }
      }
    }]
  }
}' -i
```
**Expected Response:** `202 Accepted` with a `Location` header. Polling retrieves the outcome of the consent creation job.

### 8.4. Step 8: Send a Secure Communication

Based on a prior `Consent`, an authorized employee or data provider can send a secure communication (e.g., an appointment reminder) to a patient and any related persons defined in the consent rules.

**Endpoint:** `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/individual/org.hl7.fhir.r4/Communication/_batch`

**`curl` Example:**
```bash
curl -X POST 'http://localhost:3000/acme/cds-es/v1/health-care/individual/org.hl7.fhir.r4/Communication/_batch' \
--header 'App-ID: [APP-ID]' \
--header 'App-Version: [APP-VERSION]' \
--header 'Authorization: Bearer [SMART_TOKEN_SEND_COMMUNICATION]' \
--header 'Content-Type: application/didcomm-plaintext+json' \
--data '{
  "jti": "communication-fhir-request-id",
  "thid": "communication-fhir-thread-id",
  "iss": "did:web:api.acme.org:employee:receptionist1@acme.org:device:<uuid>",
  "aud": "did:web:api.acme.org",
  "exp": 1678886460,
  "iat": 1678886400,
  "nbf": 1678886400,   
  "type": "org.hl7.fhir.r4.Communication",
  "body": {
    "resourceType": "Communication",
    "status": "completed",
    "partOf": [{ "reference": "urn:uuid:communication-channel-id" }],
    "category": [{ 
      "coding": [{
        "code": "appointment-reminder",
        "system": "http://terminology.hl7.org/CodeSystem/communication-category"
      }]
    }],
    "recipient": [ { "reference": "did:web:api.acme.org:individual:customer1@example.com" } ],
    "sender": { "reference": "did:web:api.acme.org" },
    "sent": "2025-10-15T14:30:00Z",
    "note": [
      { "text": "This is your new appointment. Best regards." }
    ],
    "payload": [{
      "contentReference": {
        "reference": "https://url-to-appointment-source.com/some-uuid"
      }
    },
    {
      "contentAttachment": {
        "contentType": "text/calendar",
        "data": "QkVHSU46VkNBTEVOREFSCgpWRVJTSU9OOjIuMApQUk9ESUQ6LS8vQWNtZS8vZGlkOndlYjphcGkuYWNtZS5vcmcvL0VTCkJFR0lOOlZFVkVOVApVSUQ6PHV1aWQtdjQ+CkRUU1BTVA6MjAyNTEwMTZUMTIwMDAwWgpEVFNUQVJUOjIwMjUxMDE3VDE1MDAwMFoKRF RFTkQ6MjAyNTEwMTdUMTYwMDAwWgpTVU1NQVJZOlJlc3VtZW4gZGUgY2l0YS4KREVTQ1JJUFRJT046RW5jdWVudHJvIHZpcnR1YWwuCkxPQ0FUSU9OOk9ubGluZQpFTkQ6VkVWRU5UCkVORDpWQ0FMRU5EQVI=",
        "title": "appointment-details.ics"
      }
    }]
  }
}' -i
```

**Expected Response:** `202 Accepted` with a `Location` header. Polling retrieves the outcome of the communication job.
