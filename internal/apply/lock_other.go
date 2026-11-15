//go:build !unix

package apply

import "errors"

// apply only runs on Linux; this keeps the package building elsewhere.
func (h *dirHost) Lock(string, string) (func() error, error) {
	return nil, errors.New("locking needs a unix host")
}
