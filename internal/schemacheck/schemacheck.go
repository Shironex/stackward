// Package schemacheck validates JSON against the subset of JSON Schema
// (draft 2020-12) that schema/report.v1.json uses: type, const, enum,
// required, properties, additionalProperties false, items, pattern,
// minimum and local $ref. Tests use it to keep the schema and the Go types
// honest without a validator dependency. Unknown keywords fail loudly, so
// the schema cannot quietly grow beyond what is checked.
package schemacheck

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var knownKeywords = map[string]bool{
	"$schema": true, "$id": true, "$defs": true, "$ref": true, "title": true, "description": true,
	"type": true, "const": true, "enum": true, "required": true, "properties": true,
	"additionalProperties": true, "items": true, "pattern": true, "minimum": true,
}

// Validate checks doc against schema and returns every violation found.
func Validate(schema, doc []byte) []error {
	var s, d any
	if err := decode(schema, &s); err != nil {
		return []error{fmt.Errorf("schema: %w", err)}
	}
	if err := decode(doc, &d); err != nil {
		return []error{fmt.Errorf("document: %w", err)}
	}
	root, ok := s.(map[string]any)
	if !ok {
		return []error{fmt.Errorf("schema: not an object")}
	}
	v := &validator{root: root}
	v.check(root, d, "$")
	return v.errs
}

func decode(b []byte, out *any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	return dec.Decode(out)
}

type validator struct {
	root map[string]any
	errs []error
}

func (v *validator) fail(path, format string, a ...any) {
	v.errs = append(v.errs, fmt.Errorf("%s: %s", path, fmt.Sprintf(format, a...)))
}

func (v *validator) check(s map[string]any, d any, path string) {
	for k := range s {
		if !knownKeywords[k] {
			v.fail(path, "schema keyword %q is not supported by schemacheck", k)
		}
	}
	if ref, ok := s["$ref"].(string); ok {
		name, found := strings.CutPrefix(ref, "#/$defs/")
		defs, _ := v.root["$defs"].(map[string]any)
		target, ok := defs[name].(map[string]any)
		if !found || !ok {
			v.fail(path, "unresolvable $ref %q", ref)
			return
		}
		v.check(target, d, path)
		return
	}
	if c, ok := s["const"]; ok && !equal(c, d) {
		v.fail(path, "want %v, got %v", c, d)
	}
	if e, ok := s["enum"].([]any); ok {
		match := false
		for _, x := range e {
			match = match || equal(x, d)
		}
		if !match {
			v.fail(path, "%v not in %v", d, e)
		}
	}
	if t, ok := s["type"].(string); ok && !hasType(d, t) {
		v.fail(path, "want type %s, got %T", t, d)
		return
	}
	switch dv := d.(type) {
	case map[string]any:
		v.object(s, dv, path)
	case []any:
		if items, ok := s["items"].(map[string]any); ok {
			for i, e := range dv {
				v.check(items, e, fmt.Sprintf("%s[%d]", path, i))
			}
		}
	case string:
		if p, ok := s["pattern"].(string); ok && !regexp.MustCompile(p).MatchString(dv) {
			v.fail(path, "%q does not match %s", dv, p)
		}
	case json.Number:
		if m, ok := s["minimum"].(json.Number); ok {
			mf, _ := m.Float64()
			df, _ := dv.Float64()
			if df < mf {
				v.fail(path, "%v below minimum %v", dv, m)
			}
		}
	}
}

func (v *validator) object(s map[string]any, d map[string]any, path string) {
	props, _ := s["properties"].(map[string]any)
	if req, ok := s["required"].([]any); ok {
		for _, r := range req {
			if _, present := d[r.(string)]; !present {
				v.fail(path, "missing required %q", r)
			}
		}
	}
	keys := make([]string, 0, len(d))
	for k := range d {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		ps, known := props[k].(map[string]any)
		if !known {
			if ap, ok := s["additionalProperties"].(bool); ok && !ap {
				v.fail(path, "unexpected property %q", k)
			}
			continue
		}
		v.check(ps, d[k], path+"."+k)
	}
}

func hasType(d any, t string) bool {
	switch t {
	case "object":
		_, ok := d.(map[string]any)
		return ok
	case "array":
		_, ok := d.([]any)
		return ok
	case "string":
		_, ok := d.(string)
		return ok
	case "boolean":
		_, ok := d.(bool)
		return ok
	case "integer":
		n, ok := d.(json.Number)
		if !ok {
			return false
		}
		_, err := n.Int64()
		return err == nil
	case "number":
		_, ok := d.(json.Number)
		return ok
	}
	return false
}

func equal(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
