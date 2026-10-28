# custodian-go

Go SDK for Custodian Data Vault.

## Check everything

    make check

Runs `gofmt`, `go vet` and the tests with the race detector. CI runs exactly this. Needs Go 1.27 (the Makefile selects it).

## What is here

| Path | Contents |
|---|---|
| `client/` | HTTP client with a method for every operation of the business API (customers, sessions, templates, webhook endpoints and deliveries, recovery policy, usage, audit events), plus: API key, idempotency keys on POST, typed API errors, and `ParseReturn` for the address the customer comes back to (it trusts only the session id, and only with your own `state`). No endpoint methods yet: they arrive with the API in Phase 1. |
| `disclosure/` | Key generation and opening of disclosures (hybrid X-Wing and classic X25519 suites), receiver side only |
| `webhook/` | `Verify` and `ParseEvent` for the `Custodian-Signature` header, tested against the shared known answers, including a signature the API's own code made |
| `testdata/openapi-vault.yaml` | The API spec, vendored and pinned. A test fails if the SDK calls an operation the spec lacks, or the spec has one the SDK lacks |
| `testdata/fixtures/v1/` | Fixtures vendored from `custodian-device-crypto`, checked against its manifest and a pinned hash |

Planned: disclosure signature check and acknowledge (milestone 1d).

## Taking a new API spec

    scripts/vendor-spec.sh ../Custodian

Review the diff. Add the SDK method for any new operation: the drift test fails until you do.

## Taking new fixtures

    scripts/vendor-fixtures.sh ../custodian-device-crypto

Review the diff. The tests fail if any fixture differs from the manifest, or if the manifest differs from `testdata/fixtures.lock`.

## Licence

None chosen yet.

## Check who signed a disclosure

Every approved disclosure is signed by the customer's vault-sign key. Check it against the key you kept from the `customer.enrolled` webhook, never against a key you fetch when you open the envelope.

```go
store := &disclosure.MemoryKeyStore{} // use your own database in production

// In your webhook handler, for every event after webhook.ParseEvent:
if err := disclosure.Observe(store, event.Type, event.Data.Object); err != nil { /* ErrKeyChanged: treat as an attack */ }

// When you fetch an envelope:
opened, err := disclosure.OpenEnvelopeFor(store, raw, disclosure.Expected{ /* request, business, customer, kid, keys, suite, private key */ })
```

`OpenEnvelopeFor` returns `ErrNoKey` if you hold no key for the customer, and `ErrKeyChanged` is returned by `Observe` if an event names another key than the one you kept. A key changes only after `customer.reset` or `customer.deleted`.
