package openflags

import "os"

func f(flag int) {
	_, _ = os.OpenFile("a", os.O_RDONLY, 0)
	_, _ = os.OpenFile("a", os.O_RDONLY|os.O_SYNC, 0)
	_, _ = os.OpenFile("a", os.O_WRONLY|os.O_CREATE, 0o600) // want `os.OpenFile opens a file for writing`
	_, _ = os.OpenFile("a", os.O_RDWR, 0)                   // want `os.OpenFile opens a file for writing`
	_, _ = os.OpenFile("a", os.O_APPEND, 0)                 // want `os.OpenFile opens a file for writing`
	_, _ = os.OpenFile("a", flag, 0)                        // want `os.OpenFile opens a file for writing`
}
