package disclosure

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"
	"testing/iotest"
)

type streamCase struct {
	Name      string `json:"name"`
	Flags     byte   `json:"flags"`
	ChunkSize int    `json:"chunk_size"`
	Salt      string `json:"salt_hex"`
	Prefix    string `json:"prefix_hex"`
	Seed      string `json:"plaintext_seed"`
	Bytes     int    `json:"plaintext_bytes"`
	Chunks    int    `json:"chunks"`
	Total     int    `json:"total_bytes"`
	Hash      string `json:"stream_sha256"`
	Stream    string `json:"stream_hex"`
}

type streamFixture struct {
	AAD      string       `json:"aad_hex"`
	Key      string       `json:"key_hex"`
	OtherKey string       `json:"other_key_hex"`
	KeyID    string       `json:"key_id_hex"`
	Cases    []streamCase `json:"cases"`
	Refusal  streamCase   `json:"refusal_stream"`
	MustFail []struct {
		Name   string `json:"name"`
		Stream string `json:"stream_hex"`
		Error  string `json:"error"`
	} `json:"must_fail"`
}

type zstdFixture struct {
	BlockSize int `json:"block_size"`
	MaxFrame  int `json:"max_frame"`
	Cases     []struct {
		Name    string `json:"name"`
		Bytes   int    `json:"plaintext_bytes"`
		Records string `json:"records_hex"`
	} `json:"cases"`
	MustFail []struct {
		Name    string `json:"name"`
		Records string `json:"records_hex"`
		Error   string `json:"error"`
	} `json:"must_fail"`
}

func load[T any](t *testing.T, name string) T {
	t.Helper()
	var out T
	readJSON(t, name, &out)
	return out
}

// The context the file-stream fixture was sealed with.
var fixtureContext = FileContext{BusinessID: "org_0123", CustomerID: "cus_0123", Record: "rec_0123", Name: "id_document"}

const fixtureFileID = "file_0123"

func seeded(seed string, n int) []byte {
	var out []byte
	for i := 0; len(out) < n; i++ {
		sum := sha256.Sum256([]byte(seed + "/" + strconv.Itoa(i)))
		out = append(out, sum[:]...)
	}
	return out[:n]
}

// seal is a test-only writer of the stream format. It is checked against the fixture before any test relies on it.
func seal(t *testing.T, key, keyID []byte, c FileContext, fileID string, flags byte, chunkSize int, salt, prefix, plain []byte) []byte {
	t.Helper()
	aead, commit, err := fileKeys(key, salt)
	if err != nil {
		t.Fatal(err)
	}
	header := []byte{fileVersion, fileSuiteAES, flags}
	header = append(header, keyID...)
	header = binary.BigEndian.AppendUint32(header, uint32(chunkSize))
	header = append(append(append(header, salt...), prefix...), commit...)
	out := append([]byte{}, header...)
	aad := c.aad(fileID)
	for counter := 0; ; counter++ {
		n := min(chunkSize, len(plain))
		last := n == len(plain)
		nonce := make([]byte, fileNonceSize)
		copy(nonce, prefix)
		binary.BigEndian.PutUint32(nonce[filePrefixSize:], uint32(counter))
		if last {
			nonce[fileNonceSize-1] = 1
		}
		chunkAAD := aad
		if counter == 0 {
			chunkAAD = append(append([]byte{}, header...), aad...)
		}
		out = aead.Seal(out, nonce, plain[:n], chunkAAD)
		plain = plain[n:]
		if last {
			return out
		}
	}
}

func fileOf(key []byte) File { return File{FileID: fixtureFileID, Key: bytes.Clone(key)} }

func openChunks(t *testing.T, key, stream []byte, c FileContext) ([]byte, error) {
	t.Helper()
	r, err := OpenFile(fileOf(key), bytes.NewReader(stream), c)
	if err != nil {
		return nil, err
	}
	// The stream layer alone: the fixture's plaintext is not a zstd record list, even with the flag set.
	return io.ReadAll(r.(*fileReader).chunks)
}

var fileErrors = map[string]error{"format": ErrFileFormat, "commitment": ErrFileCommitment, "open": ErrFileOpen, "truncated": ErrFileTruncated}

func TestTheFileContextIsTheOneTheFixtureWasSealedWith(t *testing.T) {
	f := load[streamFixture](t, "file-stream.json")
	if got := hex.EncodeToString(fixtureContext.aad(fixtureFileID)); got != f.AAD {
		t.Fatalf("aad %s, want %s", got, f.AAD)
	}
}

func TestEveryFixtureStreamOpensToItsPlaintext(t *testing.T) {
	f := load[streamFixture](t, "file-stream.json")
	key := mustHex(t, f.Key)
	if len(f.Cases) < 6 {
		t.Fatalf("the fixture lists %d cases", len(f.Cases))
	}
	for _, c := range f.Cases {
		stream := mustHex(t, c.Stream)
		if c.Stream == "" {
			// Large cases give only a hash. The test writer, checked against that hash, rebuilds them.
			stream = seal(t, key, mustHex(t, f.KeyID), fixtureContext, fixtureFileID, c.Flags, c.ChunkSize, mustHex(t, c.Salt), mustHex(t, c.Prefix), seeded(c.Seed, c.Bytes))
		}
		if sum := sha256.Sum256(stream); hex.EncodeToString(sum[:]) != c.Hash || len(stream) != c.Total {
			t.Fatalf("%s: the stream does not match the fixture hash", c.Name)
		}
		got, err := openChunks(t, key, stream, fixtureContext)
		if err != nil {
			t.Errorf("%s: %v", c.Name, err)
		} else if !bytes.Equal(got, seeded(c.Seed, c.Bytes)) {
			t.Errorf("%s: wrong plaintext", c.Name)
		}
	}
}

func TestTheTestWriterGivesTheFixtureBytes(t *testing.T) {
	f := load[streamFixture](t, "file-stream.json")
	for _, c := range f.Cases {
		got := seal(t, mustHex(t, f.Key), mustHex(t, f.KeyID), fixtureContext, fixtureFileID, c.Flags, c.ChunkSize, mustHex(t, c.Salt), mustHex(t, c.Prefix), seeded(c.Seed, c.Bytes))
		if sum := sha256.Sum256(got); hex.EncodeToString(sum[:]) != c.Hash {
			t.Errorf("%s: the test writer differs from the fixture", c.Name)
		}
	}
}

func TestEveryFixtureRefusalIsRefusedForTheRightReason(t *testing.T) {
	f := load[streamFixture](t, "file-stream.json")
	key := mustHex(t, f.Key)
	if len(f.MustFail) < 20 {
		t.Fatalf("the fixture lists %d refusals", len(f.MustFail))
	}
	for _, c := range f.MustFail {
		want, known := fileErrors[c.Error]
		if !known {
			t.Fatalf("%s: unknown error %q", c.Name, c.Error)
		}
		k, ctx := key, fixtureContext
		switch c.Name {
		case "another key":
			k = mustHex(t, f.OtherKey)
		case "another AAD":
			ctx.Name = "utility_bill"
		}
		if _, err := openChunks(t, k, mustHex(t, c.Stream), ctx); !errors.Is(err, want) {
			t.Errorf("%s: want %s, got %v", c.Name, c.Error, err)
		}
	}
}

func TestNoPlaintextComesFromAFirstChunkThatDoesNotCheck(t *testing.T) {
	f := load[streamFixture](t, "file-stream.json")
	for _, c := range f.MustFail {
		if !strings.Contains(c.Name, "first chunk") {
			continue
		}
		if r, err := OpenFile(File{FileID: fixtureFileID, Key: mustHex(t, f.Key)}, bytes.NewReader(mustHex(t, c.Stream)), fixtureContext); r != nil || !errors.Is(err, ErrFileOpen) {
			t.Errorf("%s: OpenFile returned a reader (%v)", c.Name, err)
		}
	}
}

func TestAFileOpensOnlyInItsOwnContext(t *testing.T) {
	f := load[streamFixture](t, "file-stream.json")
	stream := mustHex(t, f.Cases[1].Stream)
	for name, c := range map[string]FileContext{
		"another key name": {BusinessID: "org_0123", CustomerID: "cus_0123", Record: "rec_0123", Name: "utility_bill"},
		"another record":   {BusinessID: "org_0123", CustomerID: "cus_0123", Record: "rec_9999", Name: "id_document"},
		"another customer": {BusinessID: "org_0123", CustomerID: "cus_9999", Record: "rec_0123", Name: "id_document"},
		"another business": {BusinessID: "org_9999", CustomerID: "cus_0123", Record: "rec_0123", Name: "id_document"},
	} {
		if _, err := OpenFile(File{FileID: fixtureFileID, Key: mustHex(t, f.Key)}, bytes.NewReader(stream), c); !errors.Is(err, ErrFileOpen) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := OpenFile(File{FileID: "file_9999", Key: mustHex(t, f.Key)}, bytes.NewReader(stream), fixtureContext); !errors.Is(err, ErrFileOpen) {
		t.Errorf("another file id: %v", err)
	}
}

func zstdText(n int) []byte {
	return bytes.Repeat([]byte("a value the server must never read. "), n/36+1)[:n]
}

func TestTheZstdRecordsOfTheFixtureDecode(t *testing.T) {
	f := load[zstdFixture](t, "zstd-records.json")
	if f.BlockSize != zstdBlockSize || f.MaxFrame != zstdMaxFrame {
		t.Fatalf("block %d and frame %d, the fixture says %d and %d", zstdBlockSize, zstdMaxFrame, f.BlockSize, f.MaxFrame)
	}
	for _, c := range f.Cases {
		got, err := io.ReadAll(&recordReader{in: bytes.NewReader(mustHex(t, c.Records))})
		if err != nil || !bytes.Equal(got, zstdText(c.Bytes)) {
			t.Errorf("%s: %d bytes, %v", c.Name, len(got), err)
		}
	}
	errs := map[string]error{"frame": ErrFileFrame, "format": ErrFileRecords}
	for _, c := range f.MustFail {
		if _, err := io.ReadAll(&recordReader{in: bytes.NewReader(mustHex(t, c.Records))}); !errors.Is(err, errs[c.Error]) {
			t.Errorf("%s: want %s, got %v", c.Name, c.Error, err)
		}
	}
}

// sealedZstd seals the record list of a zstd fixture case with the zstd flag, as a page would upload it.
func sealedZstd(t *testing.T, key []byte, c FileContext, fileID string, records []byte) []byte {
	t.Helper()
	salt, prefix := bytes.Repeat([]byte{7}, fileSaltSize), bytes.Repeat([]byte{9}, filePrefixSize)
	return seal(t, key, fileKeyID, c, fileID, fileFlagZstd, fileMinChunk, salt, prefix, records)
}

func TestACompressedFileOpensEndToEndAndTheKeyIsClearedOnClose(t *testing.T) {
	f := load[zstdFixture](t, "zstd-records.json")
	key := bytes.Repeat([]byte{0x42}, 32)
	for _, c := range f.Cases {
		stream := sealedZstd(t, key, fixtureContext, fixtureFileID, mustHex(t, c.Records))
		grant := fileOf(key)
		r, err := OpenFile(grant, iotest.OneByteReader(bytes.NewReader(stream)), fixtureContext)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		got, err := io.ReadAll(iotest.OneByteReader(r))
		if err != nil || !bytes.Equal(got, zstdText(c.Bytes)) {
			t.Errorf("%s: %d bytes, %v", c.Name, len(got), err)
		}
		if _, err := r.Read(make([]byte, 1)); err != io.EOF {
			t.Errorf("%s: a read after the end gives %v", c.Name, err)
		}
		r.Close()
		if !bytes.Equal(grant.Key, make([]byte, 32)) {
			t.Errorf("%s: Close left the file key in place", c.Name)
		}
		if _, err := r.Read(make([]byte, 1)); err == nil || err == io.EOF {
			t.Errorf("%s: a read after Close gives %v", c.Name, err)
		}
	}
}

func TestAHostileFrameInsideAGoodStreamIsRefused(t *testing.T) {
	f := load[zstdFixture](t, "zstd-records.json")
	key := bytes.Repeat([]byte{0x42}, 32)
	errs := map[string]error{"frame": ErrFileFrame, "format": ErrFileRecords}
	for _, c := range f.MustFail {
		r, err := OpenFile(fileOf(key), bytes.NewReader(sealedZstd(t, key, fixtureContext, fixtureFileID, mustHex(t, c.Records))), fixtureContext)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		if _, err := io.ReadAll(r); !errors.Is(err, errs[c.Error]) {
			t.Errorf("%s: want %s, got %v", c.Name, c.Error, err)
		}
	}
}

func TestAFileCutAtAChunkBorderIsTruncated(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	plain, streams := sealedFiles(t, key)
	for name, stream := range streams {
		if len(stream) < fileHeaderSize+3*(fileMinChunk+fileTagSize) {
			t.Fatalf("%s: the stream has fewer than three chunks", name)
		}
		r, err := OpenFile(fileOf(key), bytes.NewReader(stream), fixtureContext)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := io.ReadAll(r); err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("%s: the whole stream: %v", name, err)
		}
		cut := stream[:fileHeaderSize+2*(fileMinChunk+fileTagSize)]
		r, err = OpenFile(fileOf(key), bytes.NewReader(cut), fixtureContext)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(r); !errors.Is(err, ErrFileTruncated) {
			t.Errorf("%s: want truncated, got %v", name, err)
		}
	}
}

func TestAFileFromAnOpenedEnvelopeOpensWithItsGrant(t *testing.T) {
	c := loadFixture(t)[2]
	opened, err := OpenEnvelope(c.Envelope, c.expected())
	if err != nil {
		t.Fatal(err)
	}
	g := opened.Files["selfie"]
	plain := seeded("selfie", 3000)
	ctx := FileContext{BusinessID: c.BusinessID, CustomerID: c.CustomerID, Record: c.Record, Name: "selfie"}
	stream := seal(t, g.Key, fileKeyID, ctx, g.FileID, 0, fileMinChunk, bytes.Repeat([]byte{1}, fileSaltSize), bytes.Repeat([]byte{2}, filePrefixSize), plain)

	if _, err := opened.OpenFile("passport", bytes.NewReader(stream)); !errors.Is(err, ErrFileCommitment) {
		t.Errorf("the selfie opened as the passport: %v", err)
	}
	if _, err := opened.OpenFile("full_name", bytes.NewReader(stream)); err == nil {
		t.Error("a value name opened a file")
	}
	r, err := opened.OpenFile("selfie", bytes.NewReader(stream))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("%d bytes, %v", len(got), err)
	}
	r.Close()
	if !bytes.Equal(opened.Files["selfie"].Key, make([]byte, 32)) {
		t.Error("Close left the key in Opened.Files")
	}
	if _, err := opened.OpenFile("selfie", bytes.NewReader(stream)); !errors.Is(err, ErrFileKeyCleared) {
		t.Errorf("a second open after Close: %v", err)
	}
}

func TestAReadErrorOfTheDownloadIsNotHiddenAsAChangedFile(t *testing.T) {
	f := load[streamFixture](t, "file-stream.json")
	stream := mustHex(t, f.Refusal.Stream)
	broken := io.MultiReader(bytes.NewReader(stream[:fileHeaderSize+100]), iotest.ErrReader(errors.New("connection reset")))
	if _, err := OpenFile(File{FileID: fixtureFileID, Key: mustHex(t, f.Key)}, broken, fixtureContext); err == nil || err.Error() != "connection reset" {
		t.Errorf("got %v", err)
	}
}

func TestAFileWithTooManyChunksIsRefused(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	stream := seal(t, key, fileKeyID, fixtureContext, fixtureFileID, 0, fileMinChunk, bytes.Repeat([]byte{7}, fileSaltSize), bytes.Repeat([]byte{9}, filePrefixSize), seeded("long", 3*fileMinChunk))
	r, err := OpenFile(File{FileID: fixtureFileID, Key: key}, bytes.NewReader(stream), fixtureContext)
	if err != nil {
		t.Fatal(err)
	}
	r.(*fileReader).chunks.counter = fileMaxChunks
	if _, err := io.ReadAll(r); !errors.Is(err, ErrFileTooLong) {
		t.Fatalf("want ErrFileTooLong, got %v", err)
	}
}
