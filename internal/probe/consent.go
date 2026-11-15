package probe

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
)

// LegalNotice is printed before every probe, confirmed or not.
const LegalNotice = "stackward probe: probing a host you do not own may be illegal. Only probe hosts you own or have written permission to test."

// Confirm is the consent guard. It always prints LegalNotice to out. With
// owned (--i-own-this) it returns nil; otherwise it asks on an interactive
// terminal and accepts only y or yes, and refuses outright when there is
// no terminal to ask on.
func Confirm(target string, owned, interactive bool, in io.Reader, out io.Writer) error {
	fmt.Fprintln(out, LegalNotice)
	if owned {
		return nil
	}
	if !interactive {
		return errors.New("not running on a terminal: pass --i-own-this to confirm you own " + target + " or may test it")
	}
	fmt.Fprintf(out, "Probe %s? This confirms you own it or may test it. [y/N] ", target)
	line, err := bufio.NewReader(io.LimitReader(in, 64)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("reading the answer: %w", err)
	}
	if errors.Is(err, io.EOF) && strings.TrimSpace(line) == "" {
		fmt.Fprintln(out)
		return errors.New("no answer; nothing was probed (pass --i-own-this when stdin is not a terminal)")
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return nil
	}
	return errors.New("not confirmed; nothing was probed")
}
