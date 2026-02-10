//go:build windows
// +build windows

package win

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// HCERTSTORE represents a handle to a certificate store.
// See: https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certopenstore
type HCERTSTORE windows.Handle

// HCRYPTPROV_LEGACY represents a handle to a cryptographic service provider (legacy).
// This type is used for backward compatibility with older Windows APIs.
type HCRYPTPROV_LEGACY uintptr

var (
	modcrypt32         = windows.NewLazySystemDLL("crypt32.dll")
	procCertOpenStore  = modcrypt32.NewProc("CertOpenStore")
	procCertCloseStore = modcrypt32.NewProc("CertCloseStore")
)

// CertOpenStore opens a certificate store by using a specified store provider type.
//
// Parameters:
//   - lpszStoreProvider: A pointer to a null-terminated ANSI string that contains the store provider type.
//     Common values include CERT_STORE_PROV_SYSTEM, CERT_STORE_PROV_MEMORY, CERT_STORE_PROV_FILE, etc.
//     For Go strings, convert using stringToAnsiPtr() and pass &bytes[0] where bytes is the returned slice.
//   - dwEncodingType: The encoding type. Use windows.X509_ASN_ENCODING or windows.PKCS_7_ASN_ENCODING. Can be 0 for most providers.
//   - hCryptProv: Handle to a cryptographic service provider. Can be NULL (0) to use the default.
//   - dwFlags: Flags that control the store opening behavior. Use windows.CERT_SYSTEM_STORE_* and windows.CERT_STORE_* constants.
//   - pvPara: Additional parameter whose meaning depends on lpszStoreProvider. Can be NULL for some providers.
//
// Returns:
//   - HCERTSTORE: Handle to the opened certificate store on success.
//   - error: Error if the function fails. The function returns NULL (0) on failure, and GetLastError() is called.
//
// See: https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certopenstore
//
// Note: When finished using the store, release the handle by calling CertCloseStore.
func CertOpenStore(
	lpszStoreProvider *byte,
	dwEncodingType uint32,
	hCryptProv HCRYPTPROV_LEGACY,
	dwFlags uint32,
	pvPara unsafe.Pointer,
) (HCERTSTORE, error) {
	ret, _, _ := procCertOpenStore.Call(
		uintptr(unsafe.Pointer(lpszStoreProvider)),
		uintptr(dwEncodingType),
		uintptr(hCryptProv),
		uintptr(dwFlags),
		uintptr(pvPara),
	)
	if ret == 0 {
		return HCERTSTORE(0), windows.GetLastError()
	}
	return HCERTSTORE(ret), nil
}

// CertCloseStore closes a certificate store handle and reduces the reference count on the store.
//
// Parameters:
//   - hCertStore: Handle of the certificate store to be closed.
//   - dwFlags: Flags that control the store closing behavior. Typically 0 for default behavior.
//     Use CERT_CLOSE_STORE_CHECK_FLAG to check for non-freed contexts (diagnostic tool).
//     Use CERT_CLOSE_STORE_FORCE_FLAG to force freeing of memory for all contexts.
//     Can be combined: CERT_CLOSE_STORE_CHECK_FLAG | CERT_CLOSE_STORE_FORCE_FLAG
//
// Returns:
//   - error: Error if the function fails. Returns nil on success.
//     If CERT_CLOSE_STORE_CHECK_FLAG is set and contexts remain allocated,
//     GetLastError() returns CRYPT_E_PENDING_CLOSE, but the store is still closed.
//
// See: https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certclosestore
//
// Note: There must be a corresponding call to CertCloseStore for each successful call to
// CertOpenStore or CertDuplicateStore. The store is always closed even if the function returns an error.
func CertCloseStore(hCertStore HCERTSTORE, dwFlags uint32) error {
	ret, _, _ := procCertCloseStore.Call(
		uintptr(hCertStore),
		uintptr(dwFlags),
	)
	if ret == 0 {
		return windows.GetLastError()
	}
	return nil
}
