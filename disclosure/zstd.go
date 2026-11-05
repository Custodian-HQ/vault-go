package disclosure

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"

	"github.com/klauspost/compress/zstd"
)

const (
	zstdBlockSize = 1 << 20
	// zstdMaxFrame is the longest frame a reader accepts: zstd can make a block a little longer than it was.
	zstdMaxFrame = zstdBlockSize + zstdBlockSize/64
)

var zstdDecoder = sync.OnceValues(func() (*zstd.Decoder, error) {
	return zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(zstdBlockSize), zstd.WithDecoderMaxWindow(zstdBlockSize))
})

// recordReader reads the zstd record list in the plaintext of a file: a 4-byte length, then one frame that holds one block.
type recordReader struct {
	in      io.Reader
	frame   []byte
	block   []byte
	pending []byte
	err     error
}

// endsAfterOneFrame walks the block headers and says whether the frame ends at the last byte of the input. The decoder alone would
// accept more frames after the first, such as an empty one or a skippable one.
func endsAfterOneFrame(in []byte, h zstd.Header) bool {
	pos := h.HeaderSize
	for {
		if pos < 0 || len(in)-pos < 3 {
			return false
		}
		bh := uint32(in[pos]) | uint32(in[pos+1])<<8 | uint32(in[pos+2])<<16
		size := int(bh >> 3)
		switch (bh >> 1) & 3 {
		case 0, 2:
		case 1:
			size = 1
		default:
			return false
		}
		pos += 3 + size
		if bh&1 == 1 {
			break
		}
	}
	if h.HasCheckSum {
		pos += 4
	}
	return pos == len(in)
}

// decodeBlock checks the frame header before it decodes, so a hostile frame cannot make it allocate more than one block.
func decodeBlock(frame, dst []byte) ([]byte, error) {
	var h zstd.Header
	if err := h.Decode(frame); err != nil || h.Skippable || !h.HasFCS || h.FrameContentSize == 0 || h.FrameContentSize > zstdBlockSize || h.WindowSize > zstdBlockSize {
		return nil, ErrFileFrame
	}
	if !endsAfterOneFrame(frame, h) {
		return nil, ErrFileFrame
	}
	d, err := zstdDecoder()
	if err != nil {
		return nil, err
	}
	out, err := d.DecodeAll(frame, dst[:0])
	if err != nil || uint64(len(out)) != h.FrameContentSize {
		clear(out)
		return nil, ErrFileFrame
	}
	return out, nil
}

// short reports a read that ended inside a record. Errors of the layer below, such as ErrFileOpen, pass through.
func short(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return ErrFileRecords
	}
	return err
}

func (r *recordReader) next() error {
	var length [4]byte
	n, err := io.ReadFull(r.in, length[:])
	switch {
	case n == 0 && errors.Is(err, io.EOF):
		return io.EOF
	case err != nil:
		return short(err)
	}
	size := binary.BigEndian.Uint32(length[:])
	if size == 0 || size > zstdMaxFrame {
		return ErrFileRecords
	}
	if r.frame == nil {
		r.frame = make([]byte, zstdMaxFrame)
		r.block = make([]byte, 0, zstdBlockSize)
	}
	frame := r.frame[:size]
	if _, err := io.ReadFull(r.in, frame); err != nil {
		return short(err)
	}
	r.pending, err = decodeBlock(frame, r.block)
	clear(frame)
	return err
}

func (r *recordReader) Read(p []byte) (int, error) {
	for len(r.pending) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		r.err = r.next()
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

func (r *recordReader) wipe() {
	clear(r.frame)
	clear(r.block[:cap(r.block)])
	r.pending = nil
}
