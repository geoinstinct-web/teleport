// Code generated by 'go generate'; DO NOT EDIT.

package webauthnwin

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var _ unsafe.Pointer

// Do the interface allocations only once for common
// Errno values.
const (
	errnoERROR_IO_PENDING = 997
)

var (
	errERROR_IO_PENDING error = syscall.Errno(errnoERROR_IO_PENDING)
	errERROR_EINVAL     error = syscall.EINVAL
)

// errnoErr returns common boxed Errno values, to prevent
// allocations at runtime.
func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return errERROR_EINVAL
	case errnoERROR_IO_PENDING:
		return errERROR_IO_PENDING
	}
	// TODO: add more here, after collecting data on the common
	// error values see on Windows. (perhaps when running
	// all.bat?)
	return e
}

var (
	modWebAuthn = windows.NewLazySystemDLL("WebAuthn.dll")

	procWebAuthNGetApiVersionNumber = modWebAuthn.NewProc("WebAuthNGetApiVersionNumber")
)

func webAuthNGetApiVersionNumber() (ret int, err error) {
	r0, _, e1 := syscall.Syscall(procWebAuthNGetApiVersionNumber.Addr(), 0, 0, 0, 0)
	ret = int(r0)
	if ret == 0 {
		err = errnoErr(e1)
	}
	return
}
