# Fixture provenance

These files are known answers. The Custodian reference implementation, which the browser code uses, made them. The SDKs read them with code that
was written separately, so a pass means two implementations agree.

`scripts/vendor-fixtures.sh` copies the files from a checkout of the reference implementation and pins `MANIFEST.json` in
`testdata/fixtures.lock`. Do not edit the files here. This file is the one exception: it belongs to this repository, and the script keeps it.

The Go tests read these files. The other files of the set are copied with them, but no test here reads them.

| File | Where it comes from |
|---|---|
| `hpke-xwing-vector.json` | One entry (KEM `0x647a` MLKEM768-X25519, KDF `0x0001`, AEAD `0x0003`) copied unchanged from `src/crypto/hpke/testdata/hpke-pq.json` in Go 1.26.0. Go's licence (BSD-3-Clause) is in `LICENSE-go.txt`. It pins the X-Wing KEM of `draft-ietf-hpke-pq`. |
| `hpke-xwing-aes256gcm-sample.json` | Made once by the reference implementation. A seal is random, so it is not made again. Every implementation must open it. |
| `disclosure-envelope.json`, `disclosure-key-fingerprint.json`, `file-stream.json`, `zstd-records.json` | Made by the reference implementation. They hold good cases and the cases that every reader must refuse. |
| `webhook-signature.json` | Known answers for the `Custodian-Signature` webhook header. The first signature was made by the signing code of the API server. The others follow the same rule. Every SDK must accept and refuse exactly these. |
| `MANIFEST.json` | SHA-256 of every other file here. The tests fail if a file does not match. |
| `cbor.json`, `envelope.json`, `field-padding.json`, `holder-wrap.json`, `kdf.json`, `keyring.json`, `pedersen-h.json`, `pedersen.json`, `secret-normalization.json`, `share-envelope.json`, `sign.json` | Made by the reference implementation for its own tests. The SDKs do not read them. |
