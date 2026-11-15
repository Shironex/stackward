package facts

import (
	"encoding/json"
	"fmt"
	"io"
)

// Load reads a Facts JSON document (a --dump-facts file or a test fixture).
// Unknown fields are an error, so a typo in a fixture cannot silently turn
// into "not inspected".
func Load(r io.Reader) (*Facts, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	var f Facts
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("facts: %w", err)
	}
	if f.Schema != SchemaVersion {
		return nil, fmt.Errorf("facts: schema %q, this build reads %q", f.Schema, SchemaVersion)
	}
	return &f, nil
}
