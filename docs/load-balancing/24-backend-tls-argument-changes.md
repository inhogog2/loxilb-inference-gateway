# Backend TLS argument changes

This note is for operators who upgrade a gateway that has FullProxy rules with
`security: 2` (`e2ehttps`), and for anyone who creates such rules through the REST API or
`loxicmd`.

## What changed

| Area | Before | Now |
|---|---|---|
| `mtls_backend.backend_ca_path`, `client_cert_path`, `client_key_path`, `client_cert_data`, `client_key_data` on `POST /config/loadbalancer` | accepted and stored | refused with `400`; the error names the argument |
| `mtls_backend.verify_server_cert: true` on POST | accepted and stored, without effect | honoured; needs `backend_ca_cert_id`, refused with `400` without it |
| `backend_ca_cert_id`, `backend_client_cert_id` on POST | accepted and stored | honoured; each must name a `/config/cert` entry of the right usage, refused with `400` otherwise |
| The listener's default certificate on the backend leg | presented to a backend that asked for a client certificate | never presented; a rule names its client certificate |
| The five `mtls_backend` path and inline-material keys on any read (`GET` of a rule, `/config/snapshot`, `/config/export`, the persisted configuration) | returned as stored | never returned and never written |
| `mtls_backend: {"verify_server_cert": false}`, or no `mtls_backend` | accepted | accepted, unchanged |

## What did not change

None of the retired arguments changed how the gateway talked to a backend: without a verification
request the backend leg of an `e2ehttps` rule was, and is, TLS without verification of the backend's
certificate.

One thing does change for traffic. A backend that **requires** a client certificate used to be
handed the listener's default certificate (`/opt/loxilb/cert/server.crt`). It is no longer: the
gateway presents a client certificate only when the rule names one with `backend_client_cert_id`.
A rule whose backends require a client certificate must name one after the upgrade, or those
backends refuse the gateway. See [Backend TLS verification](25-backend-tls-verification.md).

## Upgrading a gateway that already has such rules

Nothing needs to be edited before the upgrade.

- **Persisted configuration** (`snapshot.json`, or a legacy `lbconfig.txt`) written by the earlier
  release still loads. For each rule that carries a retired key the gateway logs one warning that
  names the rule and the keys, drops the keys, and applies the rule. The file on disk is not
  rewritten by the load itself: it keeps its earlier content until the next persist. Run
  `POST /config/persist` once after the upgrade to rewrite `snapshot.json` without the keys.
- **A snapshot file exported earlier** can still be restored with `POST /config/restore`. The
  response lists the same warning in `warnings`.
- **`verify_server_cert: true` without `backend_ca_cert_id` in an earlier document** is reset to
  `false` on load, with one warning per rule. It had no effect before and there is nothing to
  verify against, so nothing changes for traffic. Set it again together with a CA ID.
- **`PATCH`** on such a rule keeps working; it cannot set any backend TLS argument.

Files that an earlier release left on disk, including exported snapshots and backups, still contain
whatever was stored in them. Handle a file that may hold `client_key_data` as you would any file
that holds a private key.

## What to change in automation

Remove the retired path and inline-material arguments from every request body and from
`loxicmd create lb` invocations:

```
--mtls-backend-ca-path  --mtls-backend-cert-path  --mtls-backend-key-path  --mtls-backend-verify-server
```

A `loxicmd` that knows the certificate-ID arguments refuses these four itself and names the
replacement (`--backend-ca-cert-id`, `--backend-client-cert-id`); an earlier `loxicmd` still sends
them and the gateway refuses the request.

A request that still sends one of them fails with `400` and creates nothing. This includes a rule
file saved from an earlier release and re-applied through the API: remove the keys from the file
first.

Backend certificate verification and a backend client certificate are configured by certificate ID
(`backend_ca_cert_id`, `backend_client_cert_id`, material uploaded through `/config/cert`):
[Backend TLS verification](25-backend-tls-verification.md).
