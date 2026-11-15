//go:build windows

package probe

import (
	"errors"

	"golang.org/x/sys/windows"
)

func isRefused(err error) bool { return errors.Is(err, windows.WSAECONNREFUSED) }

func isNoRoute(err error) bool {
	return errors.Is(err, windows.WSAENETUNREACH) || errors.Is(err, windows.WSAEHOSTUNREACH) ||
		errors.Is(err, windows.WSAEADDRNOTAVAIL) || errors.Is(err, windows.WSAEAFNOSUPPORT)
}
