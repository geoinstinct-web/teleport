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

	procWebAuthNAuthenticatorGetAssertion                     = modWebAuthn.NewProc("WebAuthNAuthenticatorGetAssertion")
	procWebAuthNAuthenticatorMakeCredential                   = modWebAuthn.NewProc("WebAuthNAuthenticatorMakeCredential")
	procWebAuthNFreeAssertion                                 = modWebAuthn.NewProc("WebAuthNFreeAssertion")
	procWebAuthNFreeCredentialAttestation                     = modWebAuthn.NewProc("WebAuthNFreeCredentialAttestation")
	procWebAuthNGetApiVersionNumber                           = modWebAuthn.NewProc("WebAuthNGetApiVersionNumber")
	procWebAuthNIsUserVerifyingPlatformAuthenticatorAvailable = modWebAuthn.NewProc("WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable")
)

func webAuthNAuthenticatorGetAssertion(hwnd syscall.Handle, rpID *uint16, clientData *webauthnClientData, opts *webauthnAuthenticatorGetAssertionOptions, out **webauthnAssertion) (ret uintptr, err error) {
	r0, _, e1 := syscall.Syscall6(procWebAuthNAuthenticatorGetAssertion.Addr(), 5, uintptr(hwnd), uintptr(unsafe.Pointer(rpID)), uintptr(unsafe.Pointer(clientData)), uintptr(unsafe.Pointer(opts)), uintptr(unsafe.Pointer(out)), 0)
	ret = uintptr(r0)
	if ret != 0 {
		err = errnoErr(e1)
	}
	return
}

func webAuthNAuthenticatorMakeCredential(hwnd syscall.Handle, rp *webauthnRPEntityInformation, user *webauthnUserEntityInformation, pubKeyCredParams *webauthnCoseCredentialParameters, clientData *webauthnClientData, opts *webauthnAuthenticatorMakeCredentialOptions, out **webauthnCredentialAttestation) (ret uintptr, err error) {
	r0, _, e1 := syscall.Syscall9(procWebAuthNAuthenticatorMakeCredential.Addr(), 7, uintptr(hwnd), uintptr(unsafe.Pointer(rp)), uintptr(unsafe.Pointer(user)), uintptr(unsafe.Pointer(pubKeyCredParams)), uintptr(unsafe.Pointer(clientData)), uintptr(unsafe.Pointer(opts)), uintptr(unsafe.Pointer(out)), 0, 0)
	ret = uintptr(r0)
	if ret != 0 {
		err = errnoErr(e1)
	}
	return
}

func webAuthNFreeAssertion(in *webauthnAssertion) {
	syscall.Syscall(procWebAuthNFreeAssertion.Addr(), 1, uintptr(unsafe.Pointer(in)), 0, 0)
	return
}

func webAuthNFreeCredentialAttestation(in *webauthnCredentialAttestation) {
	syscall.Syscall(procWebAuthNFreeCredentialAttestation.Addr(), 1, uintptr(unsafe.Pointer(in)), 0, 0)
	return
}

func webAuthNGetApiVersionNumber() (ret int, err error) {
	r0, _, e1 := syscall.Syscall(procWebAuthNGetApiVersionNumber.Addr(), 0, 0, 0, 0)
	ret = int(r0)
	if ret == 0 {
		err = errnoErr(e1)
	}
	return
}

func webAuthNIsUserVerifyingPlatformAuthenticatorAvailable(out *bool) (ret uintptr, err error) {
	var _p0 uint32
	if *out {
		_p0 = 1
	}
	r0, _, e1 := syscall.Syscall(procWebAuthNIsUserVerifyingPlatformAuthenticatorAvailable.Addr(), 1, uintptr(unsafe.Pointer(&_p0)), 0, 0)
	*out = _p0 != 0
	ret = uintptr(r0)
	if ret != 0 {
		err = errnoErr(e1)
	}
	return
}
