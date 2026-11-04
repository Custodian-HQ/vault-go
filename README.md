# Custodian Data Vault: Go SDK

Custodian Data Vault lets your business keep sensitive data for your customers, so that **only the customer holds the key**.
You see a value only when the customer approves your request for it.

This is the official Go library. Use it on your server to follow the whole journey:
make a customer, send them to the vault, hear what happened, and ask to see a value.

> **Beta.** This is version `1.0.0-beta`. The API and this library can change before `1.0.0`.
> The library version is the same as the API version it was built for.

## Before you start

- You need a Custodian account and an API key. Start with a **test** key. Test mode never touches real customer data.
- Use this library **on your server only**. Never put your API key in a client app.
- You need **Go 1.27**. The library needs no other Go modules.

## The journey

1. [Install and connect](#1-install-and-connect)
2. [Create a customer](#2-create-a-customer)
3. [Send the customer to the vault](#3-send-the-customer-to-the-vault)
4. [Welcome the customer back](#4-welcome-the-customer-back)
5. [Listen for webhooks](#5-listen-for-webhooks)
6. [Other things a customer can do](#6-other-things-a-customer-can-do)
7. [Ask to see a value](#7-ask-to-see-a-value)
8. [Open the values](#8-open-the-values)
9. [Handle errors](#9-handle-errors)

Words used in this guide:

| Word | Meaning |
|---|---|
| Customer | A person whose data is in your vault. You identify them with your own user id. |
| Session | One visit of a customer to the Custodian vault page. Your server makes it. |
| Purpose | What a session is for, for example `client.PurposeEnrol`. |
| Disclosure | A request to see some of a customer's values. The customer decides. |

The examples after step 1 use `ctx` and `c` from that step.

## 1. Install and connect

```sh
go get github.com/Custodian-HQ/vault-go@v1.0.0-beta
```

Go keeps every version it has seen. Name the version you want, as above.

Make one client for your whole program. Read the key from the environment.

```go
ctx := context.Background()

c, err := client.New(os.Getenv("CUSTODIAN_API_KEY"))
if err != nil {
	log.Fatal(err)
}

me, err := c.Me(ctx) // me.Organization, me.Name, me.Livemode
```

The packages are `client` (the API), `webhook` (checking events) and `disclosure` (opening values).

## 2. Create a customer

Make the customer once. Use your own id for this person.

```go
customer, err := c.CreateCustomer(ctx, "user-1042")
// customer.ID looks like "cus_..."
```

If you use the same id again, the API answers `customer_exists`.

## 3. Send the customer to the vault

The customer creates their key in the vault. This is a **session** with the purpose `client.PurposeEnrol`.
Use the constants of type `client.Purpose` instead of writing the text by hand.

```go
state := newRandomState() // a random value. Save it for this signed-in user.
saveStateForUser(user.ID, state)

session, err := c.CreateSession(ctx, client.CreateSessionParams{
	Customer:  customer.ID,
	Purpose:   client.PurposeEnrol,
	ReturnURL: "https://app.example.com/vault/return",
	State:     state,
})
// Redirect the customer to session.URL
```

- The `ReturnURL` must be one you registered in the Console.
- The `State` ties the visit to your signed-in user. Without it, an attacker could send your user to the attacker's own session.
- The link in `session.URL` works one time, for 15 minutes.

## 4. Welcome the customer back

When the customer returns, do not trust the address. `client.ParseReturn` checks it against your saved `state` and gives you the session id.
Then ask Custodian what really happened.

```go
sessionID, err := client.ParseReturn(requestURL, loadStateForUser(user.ID))
if err != nil {
	return // the address is not valid
}
result, err := c.GetSession(ctx, sessionID)

if result.Status == client.SessionCompleted {
	// The customer finished.
}
```

The `Status` is one of `client.SessionCreated`, `SessionExchanged`, `SessionCompleted`, `SessionCancelled` or `SessionExpired`.
Always read it from `GetSession`. A customer could change the address.

## 5. Listen for webhooks

Custodian also tells your server about events with a signed request. This is the safest way to learn what happened.

Make the endpoint once, **in the Console**. Only a member can make, change, delete or rotate an endpoint, and only there.
The SDK and your API key cannot. This keeps the secret out of your code, and nobody with a stolen key can redirect your events.

1. In the Console, open **Webhooks** and choose **Add endpoint**.
2. Give your address (it must use https). Choose the events, for example `customer.enrolled` and `disclosure.approved`.
3. Confirm with your code. The Console shows the signing secret (`whsec_...`) **one time**. Store it in your secret store.

To replace a leaked secret, rotate it in the Console. The old secret stops working at once.

Then handle each request. Check the signature **before** you use anything.
Pass the raw body, not parsed JSON.

```go
var store = &disclosure.MemoryKeyStore{} // in production, keep keys in your own database

func handleWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	event, err := webhook.ParseEvent(os.Getenv("CUSTODIAN_WEBHOOK_SECRET"), r.Header.Get("Custodian-Signature"), body, 5*time.Minute)
	if err != nil {
		http.Error(w, "bad signature", http.StatusBadRequest) // the signature is wrong or too old
		return
	}
	// The same event can arrive more than once: ignore an event.ID you already handled.

	// Keeps the customer's signing key from "customer.enrolled".
	if err := disclosure.Observe(store, event.Type, event.Data.Object); err != nil {
		log.Println("signing key problem:", err) // disclosure.ErrKeyChanged means an attack
		http.Error(w, "key problem", http.StatusInternalServerError)
		return
	}

	// Handle event.Type here.
	w.WriteHeader(http.StatusOK)
}
```

**Why `Observe` matters.** When a customer enrols, the event holds their **signing key**. Keep it.
Later you use it to prove that data really came from this customer.
If a later event names a different key, `Observe` returns `disclosure.ErrKeyChanged`. Treat that as an attack.

## 6. Other things a customer can do

You start every visit the same way as in step 3. Only the purpose changes.

| Purpose | Use it to |
|---|---|
| `client.PurposeEnrol` | Let a new customer create their vault |
| `client.PurposeEntry` | Let the customer add data. Give a `Template` or `Keys`. |
| `client.PurposeView` | Let the customer see a record. Give the `Record` token. |
| `client.PurposeApprove` | Let the customer approve a disclosure request. Give the `Disclosure` id. See step 7. |
| `client.PurposeRecover`, `client.PurposeRecoverySettings` | Recovery with trusted people or devices, and its settings |
| `client.PurposeReset` | Start a reset |
| `client.PurposeDelete` | Let the customer delete their own data |
| `client.PurposeHolder` | Let the customer's second device act as a recovery holder |

`client.Purposes()` lists them all. `purpose.Valid()` tells you whether this library knows a purpose.
A newer API can send one that the library does not know yet.

## 7. Ask to see a value

Your server cannot read stored values. To see one, you make a **disclosure** request. The customer approves it with one passkey prompt.
The values come back in a sealed envelope that only your key can open.

**One time: make your disclosure key.** Keep the private key secret. The fingerprint is not secret.

```go
suite := disclosure.SuiteHybrid
private, public, err := disclosure.GenerateKey(suite) // keep private in your secret store
keyFingerprint := disclosure.Fingerprint(suite, public) // keep this in your app config
```

Add the public key in the Console. A member of your team confirms it with a code.

**Each time you want a value:**

```go
// 1. Ask for named keys of one record. The request holds names, never values.
request, err := c.CreateDisclosure(ctx, client.CreateDisclosureParams{
	Customer:    customer.ID,
	Record:      recordToken, // the record's token, for example from the "record.created" event
	Keys:        []string{"full_name", "date_of_birth"},
	Reason:      "Identity check for your loan application",
	Fingerprint: keyFingerprint,
})

// 2. Start an approval visit for that request.
approval, err := c.CreateSession(ctx, client.CreateSessionParams{
	Customer:   customer.ID,
	Purpose:    client.PurposeApprove,
	ReturnURL:  "https://app.example.com/vault/return",
	State:      state,
	Disclosure: request.ID,
})

// 3. Add your fingerprint to the link, then redirect the customer.
//    Take it from your own config, never from Custodian.
link, err := client.ApproveURL(approval.URL, keyFingerprint)
```

The customer may also reject the request, or let it expire. The default wait is 15 minutes.

## 8. Open the values

When the customer approves, you get a `disclosure.approved` webhook. Then:

```go
// 1. Fetch the sealed envelope. You have 15 minutes.
raw, err := c.GetDisclosureEnvelope(ctx, request.ID)

// 2. Say what you expect to find. Open it. The library checks the customer's signature against the key you kept in step 5.
opened, err := disclosure.OpenEnvelopeFor(store, raw, disclosure.Expected{
	RequestID:  request.ID,
	BusinessID: me.Organization,
	CustomerID: customer.ID,
	KID:        request.KeyID,
	Keys:       request.Keys,
	Suite:      suite,
	PrivateKey: private,
})
if err != nil {
	// Do not use the values. See the table below.
	return
}
fmt.Println(opened.Fields) // map[full_name:... date_of_birth:...]

// 3. Tell Custodian you have it. The vault then deletes the envelope.
_, err = c.AckDisclosure(ctx, request.ID)
```

If a check fails, the library returns an error. **Do not use the values.** Never fall back to a key that you fetched from Custodian.
Use `errors.Is` to see which check failed.

| Error | What it means |
|---|---|
| `disclosure.ErrNoKey` | You hold no signing key for this customer. Check that your webhook saw `customer.enrolled`. |
| `disclosure.ErrKeyChanged` | An event names a different key than the one you kept. Treat it as an attack. |
| `disclosure.ErrSignature` | The customer's key did not sign this envelope. |
| `ErrRequest`, `ErrBusiness`, `ErrCustomer`, `ErrKey` | The envelope is for something else than you asked. |
| `ErrFormat`, `ErrPayload`, `ErrCommitment` | The envelope is damaged, or its content is not what the customer approved. |

## 9. Handle errors

Every failed API call returns an `*client.APIError`. Use `errors.As` to read it.

```go
var apiErr *client.APIError
if errors.As(err, &apiErr) {
	log.Println(apiErr.Status, apiErr.Code, apiErr.Message, apiErr.RequestID)
}
```

Give the `RequestID` to support if you need help.

## More help

- [Documentation](https://docs.thecustodian.io)
- [Quickstart](https://docs.thecustodian.io/get-started/quickstart/)
- [Sessions](https://docs.thecustodian.io/developer/sessions/)
- [Webhooks](https://docs.thecustodian.io/developer/webhooks/)
- [Disclosure](https://docs.thecustodian.io/developer/disclosure/)
- [Errors](https://docs.thecustodian.io/get-started/errors/)

## Security

To report a security problem, email **support@thecustodian.io**. Do not open a public issue for it.

## Contributing

Run `make check`. It runs `gofmt`, `go vet` and the tests with the race detector.

## Licence

MIT. See [LICENSE](LICENSE).
