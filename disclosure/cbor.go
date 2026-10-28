package disclosure

import (
	"bytes"
	"errors"
	"sort"
	"unicode/utf8"
)

// A small deterministic CBOR (RFC 8949, section 4.2), only as much as an envelope needs. Writing: a map with text keys whose values are
// unsigned numbers, text or byte strings. Reading: unsigned numbers, text and maps with text keys. Everything else is refused, and so is any
// form that is not the shortest, so each statement has one encoding.

var errCBOR = errors.New("disclosure: not deterministic CBOR")

func head(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n <= 0xff:
		return []byte{major<<5 | 24, byte(n)}
	case n <= 0xffff:
		return []byte{major<<5 | 25, byte(n >> 8), byte(n)}
	case n <= 0xffffffff:
		return []byte{major<<5 | 26, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
	return []byte{major<<5 | 27, byte(n >> 56), byte(n >> 48), byte(n >> 40), byte(n >> 32), byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

func text(s string) []byte  { return append(head(3, uint64(len(s))), s...) }
func bstr(b []byte) []byte  { return append(head(2, uint64(len(b))), b...) }
func uint_(n uint64) []byte { return head(0, n) }

type pair struct{ key, value []byte }

// encodeMap writes a map with its keys in the bytewise order of their encodings.
func encodeMap(pairs []pair) []byte {
	sort.Slice(pairs, func(i, j int) bool { return bytes.Compare(pairs[i].key, pairs[j].key) < 0 })
	out := head(5, uint64(len(pairs)))
	for _, p := range pairs {
		out = append(append(out, p.key...), p.value...)
	}
	return out
}

// encodeArray writes an array of text.
func encodeTextArray(items []string) []byte {
	out := head(4, uint64(len(items)))
	for _, s := range items {
		out = append(out, text(s)...)
	}
	return out
}

// value is what the reader returns: a number, text or a map.
type value struct {
	num  uint64
	str  string
	kind byte // 'n', 's', 'm'
	m    []entry
}

type entry struct {
	key string
	val value
}

type reader struct {
	b []byte
}

func (r *reader) take(n uint64) ([]byte, error) {
	if n > uint64(len(r.b)) {
		return nil, errCBOR
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out, nil
}

func (r *reader) argument(info byte) (uint64, error) {
	if info < 24 {
		return uint64(info), nil
	}
	var size uint64
	switch info {
	case 24:
		size = 1
	case 25:
		size = 2
	case 26:
		size = 4
	case 27:
		size = 8
	default:
		return 0, errCBOR // indefinite lengths and reserved values
	}
	raw, err := r.take(size)
	if err != nil {
		return 0, err
	}
	var n uint64
	for _, c := range raw {
		n = n<<8 | uint64(c)
	}
	// The shortest form only.
	if (size == 1 && n < 24) || (size == 2 && n <= 0xff) || (size == 4 && n <= 0xffff) || (size == 8 && n <= 0xffffffff) {
		return 0, errCBOR
	}
	return n, nil
}

func (r *reader) item(depth int) (value, error) {
	if depth > 8 || len(r.b) == 0 {
		return value{}, errCBOR
	}
	first := r.b[0]
	r.b = r.b[1:]
	major, info := first>>5, first&31
	n, err := r.argument(info)
	if err != nil {
		return value{}, err
	}
	switch major {
	case 0:
		return value{kind: 'n', num: n}, nil
	case 3:
		raw, err := r.take(n)
		if err != nil || !utf8.Valid(raw) {
			return value{}, errCBOR
		}
		return value{kind: 's', str: string(raw)}, nil
	case 5:
		if n > 1000 {
			return value{}, errCBOR
		}
		var out []entry
		var last []byte
		for i := uint64(0); i < n; i++ {
			start := r.b
			k, err := r.item(depth + 1)
			if err != nil || k.kind != 's' {
				return value{}, errCBOR
			}
			encoded := start[:len(start)-len(r.b)]
			// Keys strictly ascending by their encodings: this also refuses a repeated key.
			if last != nil && bytes.Compare(last, encoded) >= 0 {
				return value{}, errCBOR
			}
			last = encoded
			v, err := r.item(depth + 1)
			if err != nil {
				return value{}, err
			}
			out = append(out, entry{k.str, v})
		}
		return value{kind: 'm', m: out}, nil
	}
	return value{}, errCBOR
}

func decode(data []byte) (value, error) {
	r := reader{b: data}
	v, err := r.item(0)
	if err != nil || len(r.b) != 0 {
		return value{}, errCBOR
	}
	return v, nil
}
