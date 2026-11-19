package disclosure

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
)

// The reasons OpenFile, or a Read of the file it returns, refuses a file. Check them with errors.Is. No plaintext comes out of a part of
// the file that did not check.
var (
	ErrFileFormat     = errors.New("disclosure: the file is not in the expected encrypted format")
	ErrFileCommitment = errors.New("disclosure: the file was encrypted with another key")
	ErrFileOpen       = errors.New("disclosure: the file was changed, or it is not the file for this name and record")
	// ErrFileTruncated means the encrypted file ended early. A download that was cut short gives it.
	ErrFileTruncated = errors.New("disclosure: the encrypted file ended early")
	// ErrFileTooLong means the stream has more chunks than the wire format allows (2^32-1).
	ErrFileTooLong = errors.New("disclosure: the encrypted file is too long")
	// ErrFileRecords and ErrFileFrame mean the compressed content of the file is not well formed.
	ErrFileRecords = errors.New("disclosure: the compressed file is damaged")
	ErrFileFrame   = errors.New("disclosure: the compressed file has a part that is not allowed")
	// ErrFileKeyCleared means the key was cleared, by Close or Opened.Discard. Fetch and open the envelope again before you acknowledge it.
	ErrFileKeyCleared = errors.New("disclosure: the file key was cleared; open the envelope again to get it")
)

const (
	fileVersion    byte = 0x01
	fileSuiteAES   byte = 0x01
	fileFlagZstd   byte = 0x01
	fileHeaderSize      = 70
	fileSaltSize        = 16
	filePrefixSize      = 7
	fileCommitSize      = 32
	fileTagSize         = 16
	fileNonceSize       = filePrefixSize + 4 + 1
	fileMinChunk        = 1 << 10
	fileMaxChunk        = 1 << 20
	// fileMaxChunks is the most chunks a stream has (counters 0 to 2^32-2), as the wire format says.
	fileMaxChunks = 1<<32 - 1
)

// FileContext names where a file belongs. It is checked when the file is opened, so the vault cannot show one customer's file, or a file
// uploaded under another name, as the file you asked for.
type FileContext struct {
	// BusinessID is your organization's public id (org_...), CustomerID the customer (cus_...), Record the record token and Name the
	// file's key name, as in the request.
	BusinessID string
	CustomerID string
	Record     string
	Name       string
}

func (c FileContext) aad(fileID string) []byte {
	out := []byte("cdv/v1/file-value")
	for _, part := range []string{c.BusinessID, c.CustomerID, c.Record, c.Name, fileID} {
		out = append(append(out, 0), part...)
	}
	return out
}

// OpenFile decrypts the file called name, read from ciphertext (the body of client.DownloadDisclosedFile, or a copy you saved). The file
// must be whole: a byte range alone does not open. See the package OpenFile for what it checks and how the key is cleared.
func (o *Opened) OpenFile(name string, ciphertext io.Reader) (io.ReadCloser, error) {
	f, ok := o.Files[name]
	if !ok {
		return nil, errors.New("disclosure: no file of that name was disclosed")
	}
	return OpenFile(f, ciphertext, FileContext{BusinessID: o.businessID, CustomerID: o.customerID, Record: o.Record, Name: name})
}

// OpenFile decrypts one disclosed file as you read it. It holds at most one chunk (1 MiB) and one compressed block at a time, so a large
// file never sits in memory whole.
//
// Before it returns, it checks the header and the key commitment and opens the first chunk, which proves the header and the context.
// Each later Read gives plaintext only from chunks that checked, and the last chunk is told from the end of the input, so a file cut
// short gives ErrFileTruncated at the end. Read to io.EOF before you trust or keep the result: an error can still come near the end.
//
// Close clears the plaintext the reader holds and the file key in f (and so in Opened.Files). After Close the key cannot open the file
// again: to retry, fetch the envelope again before you acknowledge it. Close does not close ciphertext. The file type the customer
// uploaded is not checked here: check it again before you use the file.
func OpenFile(f File, ciphertext io.Reader, c FileContext) (io.ReadCloser, error) {
	if len(f.Key) != fileKeySize {
		return nil, errors.New("disclosure: a file key is 32 bytes")
	}
	if subtle.ConstantTimeCompare(f.Key, make([]byte, fileKeySize)) == 1 {
		return nil, ErrFileKeyCleared
	}
	src := &source{r: ciphertext}
	in := bufio.NewReaderSize(src, 64<<10)
	header := make([]byte, fileHeaderSize)
	if _, err := io.ReadFull(in, header); err != nil {
		if src.err != nil {
			return nil, &readError{src.err}
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, ErrFileFormat
		}
		return nil, err
	}
	size := int(binary.BigEndian.Uint32(header[11:15]))
	if header[0] != fileVersion || header[1] != fileSuiteAES || header[2]&^fileFlagZstd != 0 || size < fileMinChunk || size > fileMaxChunk {
		return nil, ErrFileFormat
	}
	salt := header[15 : 15+fileSaltSize]
	aead, commit, err := fileKeys(f.Key, salt)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(commit, header[fileHeaderSize-fileCommitSize:]) != 1 {
		return nil, ErrFileCommitment
	}
	s := &chunkReader{
		in: in, src: src, aead: aead, header: header, prefix: header[15+fileSaltSize : 15+fileSaltSize+filePrefixSize], aad: c.aad(f.FileID),
		sealed: make([]byte, size+fileTagSize), plain: make([]byte, 0, size),
	}
	if err := s.next(); err != nil {
		s.wipe()
		return nil, err
	}
	out := &fileReader{key: f.Key, chunks: s, content: s}
	if header[2]&fileFlagZstd != 0 {
		out.records = &recordReader{in: s}
		out.content = out.records
	}
	return out, nil
}

func fileKeys(fileKey, salt []byte) (cipher.AEAD, []byte, error) {
	encKey, err := hkdf.Key(sha256.New, fileKey, nil, "cdv/v1/file-enc"+string(salt), 32)
	if err != nil {
		return nil, nil, err
	}
	defer clear(encKey)
	commit, err := hkdf.Key(sha256.New, fileKey, nil, "cdv/v1/file-commit"+string(salt), fileCommitSize)
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	return aead, commit, err
}

// source remembers the first error of the reader below the file that is not the clean end. io.ReadFull gives io.ErrUnexpectedEOF both for a
// clean end inside a chunk and for a connection that net/http cut short, and only the first is the end of the file.
type source struct {
	r   io.Reader
	err error
}

func (s *source) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if err != nil && err != io.EOF && s.err == nil {
		s.err = err
	}
	return n, err
}

// readError is an error of the reader below the file, such as a cut connection. It is not the end of the file and not a changed file.
type readError struct{ err error }

func (e *readError) Error() string { return e.err.Error() }
func (e *readError) Unwrap() error { return e.err }

type fileReader struct {
	key     []byte
	chunks  *chunkReader
	records *recordReader
	content io.Reader
	err     error
}

var errClosed = errors.New("disclosure: read after close")

func (r *fileReader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	n, err := r.content.Read(p)
	if err != nil {
		r.err = err
		r.wipe()
	}
	return n, err
}

func (r *fileReader) wipe() {
	r.chunks.wipe()
	if r.records != nil {
		r.records.wipe()
	}
}

func (r *fileReader) Close() error {
	r.err = errClosed
	r.wipe()
	clear(r.key)
	return nil
}

// chunkReader opens the chunks of the stream, in order.
type chunkReader struct {
	in      *bufio.Reader
	src     *source
	aead    cipher.AEAD
	header  []byte
	prefix  []byte
	aad     []byte
	sealed  []byte
	plain   []byte
	pending []byte
	counter uint64
	done    bool
	err     error
}

func (s *chunkReader) nonce(last bool) []byte {
	out := make([]byte, fileNonceSize)
	copy(out, s.prefix)
	binary.BigEndian.PutUint32(out[filePrefixSize:], uint32(s.counter))
	if last {
		out[fileNonceSize-1] = 1
	}
	return out
}

func (s *chunkReader) next() error {
	if s.counter >= fileMaxChunks {
		return ErrFileTooLong
	}
	n, err := io.ReadFull(s.in, s.sealed)
	last := false
	if err != nil && s.src.err != nil {
		return &readError{s.src.err}
	}
	switch {
	case err == nil:
		// A full chunk is the last one only if nothing follows it.
		if _, peek := s.in.Peek(1); errors.Is(peek, io.EOF) {
			last = true
		} else if peek != nil {
			return &readError{peek}
		}
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		if n < fileTagSize {
			return ErrFileTruncated
		}
		last = true
	default:
		return err
	}
	chunk := s.sealed[:n]
	aad := s.aad
	if s.counter == 0 {
		aad = append(append([]byte{}, s.header...), s.aad...)
	}
	plain, err := s.aead.Open(s.plain[:0], s.nonce(last), chunk, aad)
	if err != nil {
		// A chunk that opens as a middle chunk but ends the input means the stream was cut at a chunk border.
		if last {
			if probe, err := s.aead.Open(nil, s.nonce(false), chunk, aad); err == nil {
				clear(probe)
				return ErrFileTruncated
			}
		}
		return ErrFileOpen
	}
	s.counter++
	s.done = last
	s.pending = plain
	return nil
}

func (s *chunkReader) Read(p []byte) (int, error) {
	for len(s.pending) == 0 {
		if s.err != nil {
			return 0, s.err
		}
		if s.done {
			return 0, io.EOF
		}
		if s.err = s.next(); s.err != nil {
			return 0, s.err
		}
	}
	n := copy(p, s.pending)
	s.pending = s.pending[n:]
	return n, nil
}

func (s *chunkReader) wipe() {
	clear(s.plain[:cap(s.plain)])
	s.pending = nil
}
