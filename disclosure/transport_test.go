package disclosure

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// download serves stream with a Content-Length for all of it but sends only the first cut bytes, then drops the connection. net/http then
// gives the reader io.ErrUnexpectedEOF, as it does for a real download that is cut short.
func download(t *testing.T, stream []byte, cut int) io.ReadCloser {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(stream)))
		w.Write(stream[:cut])
		w.(http.Flusher).Flush()
	}))
	t.Cleanup(server.Close)
	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp.Body
}

func sealedFiles(t *testing.T, key []byte) map[string][]byte {
	t.Helper()
	plain := seeded("transport", 3*fileMinChunk+10)
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
	if err != nil {
		t.Fatal(err)
	}
	frame := enc.EncodeAll(plain, nil)
	records := append(binary.BigEndian.AppendUint32(nil, uint32(len(frame))), frame...)
	salt, prefix := bytes.Repeat([]byte{7}, fileSaltSize), bytes.Repeat([]byte{9}, filePrefixSize)
	return map[string][]byte{
		"plain":      seal(t, key, fileKeyID, fixtureContext, fixtureFileID, 0, fileMinChunk, salt, prefix, plain),
		"compressed": seal(t, key, fileKeyID, fixtureContext, fixtureFileID, fileFlagZstd, fileMinChunk, salt, prefix, records),
	}
}

func notAFileError(t *testing.T, name string, err error) {
	t.Helper()
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("%s: want the cut connection (io.ErrUnexpectedEOF), got %v", name, err)
	}
	for _, wrong := range []error{ErrFileFormat, ErrFileOpen, ErrFileTruncated, ErrFileRecords, ErrFileFrame} {
		if errors.Is(err, wrong) {
			t.Errorf("%s: a cut connection was reported as %v", name, wrong)
		}
	}
}

func TestACutConnectionIsNotReportedAsAChangedOrMalformedFile(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	chunk := fileMinChunk + fileTagSize
	for name, stream := range sealedFiles(t, key) {
		open := func(body io.Reader) (io.ReadCloser, error) {
			return OpenFile(File{FileID: fixtureFileID, Key: append([]byte{}, key...)}, body, fixtureContext)
		}

		_, err := open(download(t, stream, 40))
		notAFileError(t, name+", cut in the header", err)

		_, err = open(download(t, stream, fileHeaderSize+500))
		notAFileError(t, name+", cut in the first chunk", err)

		r, err := open(download(t, stream, fileHeaderSize+chunk+200))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		_, err = io.ReadAll(r)
		notAFileError(t, name+", cut in a later chunk", err)

		r, err = open(download(t, stream, fileHeaderSize+2*chunk))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		_, err = io.ReadAll(r)
		notAFileError(t, name+", cut at a chunk border", err)
	}
}

func TestACleanEndInsideAChunkIsStillAChangedFile(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	chunk := fileMinChunk + fileTagSize
	for name, stream := range sealedFiles(t, key) {
		r, err := OpenFile(File{FileID: fixtureFileID, Key: append([]byte{}, key...)}, bytes.NewReader(stream[:fileHeaderSize+chunk+200]), fixtureContext)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := io.ReadAll(r); !errors.Is(err, ErrFileOpen) {
			t.Errorf("%s: want ErrFileOpen, got %v", name, err)
		}
		if _, err := OpenFile(File{FileID: fixtureFileID, Key: append([]byte{}, key...)}, bytes.NewReader(stream[:40]), fixtureContext); !errors.Is(err, ErrFileFormat) {
			t.Errorf("%s: a clean end inside the header: want ErrFileFormat, got %v", name, err)
		}
	}
}
