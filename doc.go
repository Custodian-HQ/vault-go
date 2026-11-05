// Package custodian is the Go SDK for Custodian Data Vault. The client is in client/, webhook checks in webhook/, and the
// disclosure reader in disclosure/. This package itself holds only the fixture checks.
//
// To receive a disclosed file: ask for its key name in a disclosure request; open the envelope with disclosure.OpenEnvelopeFor, naming
// the file in Expected.Files; download it with client.DownloadDisclosedFile before you acknowledge; decrypt it with Opened.OpenFile and
// read it to the end before you keep it; then discard the key (Close and Opened.Discard clear it). Check the file type again before you
// use the file: the library does not.
package custodian
