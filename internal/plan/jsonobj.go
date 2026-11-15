package plan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// jsonObject is a JSON object that keeps its keys in file order and every
// value as written (numbers, nested objects, their whitespace), so a merge
// changes only the keys it sets.
type jsonObject struct {
	keys   []string
	values map[string]json.RawMessage
	// changed marks keys set by the merge; only those are reformatted.
	changed map[string]bool
}

// parseObject reads one JSON object. Duplicate keys are refused: which one
// a program honours is unclear, and a plan must not guess.
func parseObject(b []byte) (*jsonObject, error) {
	o := &jsonObject{values: map[string]json.RawMessage{}, changed: map[string]bool{}}
	if len(bytes.TrimSpace(b)) == 0 {
		return o, nil
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("not a JSON object")
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := tok.(string)
		if !ok {
			return nil, errors.New("object key is not a string")
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, err
		}
		if _, dup := o.values[key]; dup {
			return nil, fmt.Errorf("key %q appears twice", key)
		}
		o.keys = append(o.keys, key)
		o.values[key] = raw
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err == nil {
		return nil, errors.New("data after the object")
	}
	return o, nil
}

// get returns the raw value of key.
func (o *jsonObject) get(key string) (json.RawMessage, bool) {
	v, ok := o.values[key]
	return v, ok
}

// set replaces the value of key in place, or appends key at the end.
func (o *jsonObject) set(key string, v json.RawMessage) {
	if _, ok := o.values[key]; !ok {
		o.keys = append(o.keys, key)
	}
	o.values[key] = v
	o.changed[key] = true
}

// encode writes the object with one key per line, indented by indent. A
// value the merge set is indented to match; any other value is written
// exactly as it was read, so a pretty printed file only changes where the
// merge did. The result ends with a newline.
func (o *jsonObject) encode(indent string) ([]byte, error) {
	var b bytes.Buffer
	if len(o.keys) == 0 {
		return []byte("{}\n"), nil
	}
	b.WriteString("{\n")
	for i, k := range o.keys {
		name, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		val := []byte(o.values[k])
		if o.changed[k] {
			var ind bytes.Buffer
			if err := json.Indent(&ind, val, indent, indent); err != nil {
				return nil, err
			}
			val = ind.Bytes()
		}
		b.WriteString(indent)
		b.Write(name)
		b.WriteString(": ")
		b.Write(val)
		if i < len(o.keys)-1 {
			b.WriteByte(',')
		}
		b.WriteByte('\n')
	}
	b.WriteString("}\n")
	return b.Bytes(), nil
}

// detectIndent returns the indentation of the first indented line of a
// JSON document, or two spaces when it has none (one line JSON).
func detectIndent(s string) string {
	for _, l := range strings.Split(s, "\n") {
		trimmed := strings.TrimLeft(l, " \t")
		if trimmed != "" && len(trimmed) < len(l) {
			return l[:len(l)-len(trimmed)]
		}
	}
	return "  "
}
