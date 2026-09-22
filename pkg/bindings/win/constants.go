// Copyright 2026 Riccardo Raccuia
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build windows
// +build windows

package win

// Certificate store provider types as ANSI strings.
// These are string constants used with CertOpenStore's lpszStoreProvider parameter.
// Note: golang.org/x/sys/windows defines numeric constants for these (CERT_STORE_PROV_MSG = 1, etc.),
// but CertOpenStore expects ANSI string pointers, not numeric values.
const (
	CERT_STORE_PROV_MSG             = "Msg"
	CERT_STORE_PROV_MEMORY          = "Memory"
	CERT_STORE_PROV_FILE            = "File"
	CERT_STORE_PROV_REG             = "Registry"
	CERT_STORE_PROV_PKCS7           = "PKCS7"
	CERT_STORE_PROV_SERIALIZED      = "Serialized"
	CERT_STORE_PROV_FILENAME_A      = "CERT_STORE_PROV_FILENAME_A"
	CERT_STORE_PROV_FILENAME_W      = "CERT_STORE_PROV_FILENAME_W"
	CERT_STORE_PROV_FILENAME        = CERT_STORE_PROV_FILENAME_W
	CERT_STORE_PROV_SYSTEM          = "System"
	CERT_STORE_PROV_COLLECTION      = "Collection"
	CERT_STORE_PROV_SYSTEM_REGISTRY = "SystemRegistry"
	CERT_STORE_PROV_PHYSICAL        = "Physical"
	CERT_STORE_PROV_SMART_CARD_W    = "SmartCardW"
	CERT_STORE_PROV_SMART_CARD      = CERT_STORE_PROV_SMART_CARD_W
	CERT_STORE_PROV_LDAP_W          = "LdapW"
	CERT_STORE_PROV_LDAP            = CERT_STORE_PROV_LDAP_W
)

// Re-export commonly used constants from golang.org/x/sys/windows for convenience.
// All flag and encoding constants are available from the windows package.

// Certificate store close flags.
// These constants control the behavior of CertCloseStore.
// Note: These are not available in golang.org/x/sys/windows, so they are defined here.
const (
	// CERT_CLOSE_STORE_FORCE_FLAG forces the freeing of memory for all contexts associated with the store.
	// This flag can be safely used only when the store is opened in a function and neither the store handle
	// nor any of its contexts are passed to any called functions.
	CERT_CLOSE_STORE_FORCE_FLAG = 0x00000001

	// CERT_CLOSE_STORE_CHECK_FLAG checks for non-freed certificate, CRL, and CTL contexts.
	// A returned error code indicates that one or more store elements is still in use.
	// This flag should only be used as a diagnostic tool in the development of applications.
	CERT_CLOSE_STORE_CHECK_FLAG = 0x00000002
)

// Certificate encoding types - use windows.X509_ASN_ENCODING and windows.PKCS_7_ASN_ENCODING
// Certificate store flags - use windows.CERT_STORE_* constants
// Certificate system store location flags - use windows.CERT_SYSTEM_STORE_* constants
// Certificate file store commit flags - use windows.CERT_FILE_STORE_COMMIT_ENABLE_FLAG
// Certificate LDAP store flags - use windows.CERT_LDAP_STORE_* constants

// NL_NEIGHBOR_STATE values for MIB_IPNET_ROW2.State.
// Not available in golang.org/x/sys/windows; defined in Nldef.h.
// See: https://learn.microsoft.com/en-us/windows/win32/api/nldef/ne-nldef-nl_neighbor_state
const (
	NlnsUnreachable = 0
	NlnsIncomplete  = 1
	NlnsProbe       = 2
	NlnsDelay       = 3
	NlnsStale       = 4
	NlnsReachable   = 5
	NlnsPermanent   = 6
	NlnsMaximum     = 7
)
