# Backend TLS verification and client certificates

A FullProxy rule with `security: 2` (`e2ehttps`) re-encrypts traffic to its endpoints. By default
that leg is TLS without authentication in either direction. This page describes how a rule makes
the gateway verify its endpoints, and how it makes the gateway present a client certificate to
endpoints that require one (mutual TLS between the gateway and the backend).

Both need a build with client-certificate support, `mode: 4` and `security: 2`. Any other
combination is refused with `400`.

## 1. Register the material

Certificates are uploaded to the certificate registry and referred to by ID. A rule never carries a
path or PEM data.

| `usage` | What it holds | Request body |
|---|---|---|
| `ca` | The CA bundle endpoint certificates must chain to | `certPem` (one or more CA certificates; `chainPem` is appended). `keyPem` is sent as the empty string. |
| `client` | The certificate and key the gateway presents to endpoints | `certPem`, `keyPem`, optional `chainPem`. The pair must match. |
| `server` (default) | A listener certificate, selected by SNI | unchanged |

```
POST /netlox/v1/config/cert
{ "certId": "backend-ca", "usage": "ca", "certPem": "-----BEGIN CERTIFICATE-----\n...", "keyPem": "" }

POST /netlox/v1/config/cert
{ "certId": "backend-client", "usage": "client",
  "certPem": "-----BEGIN CERTIFICATE-----\n...", "keyPem": "-----BEGIN PRIVATE KEY-----\n..." }
```

- The usage of an ID is fixed when it is created. `PUT /config/cert/{certId}` rotates the material
  and cannot change the usage.
- `GET` never returns a private key. It returns the usage.
- Only `server` entries are offered to clients. A `ca` or `client` entry is never a listener
  certificate.
- An entry that a rule refers to cannot be deleted (`400`, naming the rule). Remove it from the rule
  first.

## 2. Refer to it from the rule

| Rule argument | Meaning |
|---|---|
| `mtls_backend.verify_server_cert: true` | Verify the certificate of every endpoint. Requires `backend_ca_cert_id`. |
| `backend_ca_cert_id` | A registry entry with usage `ca`. There is no default trust store. |
| `backend_client_cert_id` | A registry entry with usage `client`. Without it the gateway presents no certificate. |
| `backend_tls_server_name` | A DNS host name sent as SNI to every endpoint and, when verification is on, required among the DNS names of the endpoint's certificate. |

```
POST /netlox/v1/config/loadbalancer
{ "serviceArguments": {
    "externalIP": "10.10.10.254", "port": 2020, "protocol": "tcp",
    "mode": 4, "security": 2, "host": "10.10.10.254",
    "mtls_backend": { "verify_server_cert": true },
    "backend_ca_cert_id": "backend-ca",
    "backend_client_cert_id": "backend-client" },
  "endpoints": [ { "endpointIP": "31.31.31.1", "targetPort": 8443, "weight": 1 } ] }
```

Refused with `400`, naming the argument, before anything is changed:

- verification without `backend_ca_cert_id`, or a CA ID without verification;
- an ID nothing is registered under, or an entry of the wrong usage;
- a server name that is an address or not a DNS host name.

`GET` of a rule returns the three arguments as they were requested.

## 3. What a verified endpoint must present

A chain that ends in the rule's CA is not enough. The certificate must also name the endpoint the
gateway dialled:

- with `backend_tls_server_name`: the name must be a DNS subject alternative name of the
  certificate. A name that appears only in the subject is not accepted.
- without it: the endpoint's IP address must be an IP subject alternative name. No SNI is sent.

The name is never taken from the VIP or from a request's `Host` header. An endpoint that fails the
check is not connected to; the request fails as it does for an endpoint that is down.

## 4. Changing the policy of a rule that is serving

Post the rule again with the changed arguments. The gateway builds the new backend TLS context
first and puts it in service only when that succeeds; the listener is not re-created and client
connections are not dropped.

- Backend connections already established keep the context they were made with. A request or an
  HTTP/2 stream in flight finishes on its connection.
- No new work starts on a connection made under the replaced policy. On a listener that inspects
  requests (AI gateway mode) the next keep-alive request gets a new backend connection; a new
  HTTP/2 stream is never added to a backend connection made under the replaced policy.
- A client connection on a listener that relays bytes without inspecting requests stays bound to
  its backend connection until the client closes it. To cut those over at once, delete and
  re-create the rule.

## 5. Rotating a certificate

`PUT /config/cert/{certId}` replaces the material under the same ID. A rule that refers to the ID
takes the new material the next time the rule is updated: the gateway compares the files behind
the rule's IDs with the ones its context was built from and rebuilds the context when they differ.
Until then the rule keeps the material it was installed with.

## 6. Upgrading

- A backend that requires a client certificate used to receive the listener's default certificate.
  It no longer does. Name a client certificate on the rule (sections 1 and 2).
- See [Backend TLS argument changes](24-backend-tls-argument-changes.md) for the retired
  `mtls_backend` path and inline-material arguments.
