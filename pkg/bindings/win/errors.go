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

package win

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// APIError describes a failed Windows API call.
// It always includes the API name and the return code.
type APIError struct {
	APIName    string
	ReturnCode uintptr
	Cause      error
}

// Error formats the API name and return code with optional wrapped detail.
func (e *APIError) Error() string {
	if e == nil {
		return "<nil>"
	}

	if e.Cause == nil {
		return fmt.Sprintf("%s failed with return code 0x%X (%d)", e.APIName, e.ReturnCode, e.ReturnCode)
	}

	return fmt.Sprintf(
		"%s failed with return code 0x%X (%d): %v",
		e.APIName,
		e.ReturnCode,
		e.ReturnCode,
		e.Cause,
	)
}

// Unwrap returns the underlying cause.
func (e *APIError) Unwrap() error {
	if e.ReturnCode == uintptr(windows.ERROR_OBJECT_ALREADY_EXISTS) {
		return fmt.Errorf("%w: %w", os.ErrExist, e.Cause)
	}
	return e.Cause
}

// newReturnCodeError builds an APIError from an API return value code.
func newReturnCodeError(apiName string, returnCode uintptr) error {
	return &APIError{
		APIName:    apiName,
		ReturnCode: returnCode,
		Cause:      windows.Errno(returnCode),
	}
}

// newLastErrorCode builds an APIError from GetLastError().
func newLastErrorCode(apiName string) error {
	lastError := windows.GetLastError()
	var returnCode uintptr
	var errno windows.Errno

	if errors.As(lastError, &errno) {
		returnCode = uintptr(errno)
	}

	return &APIError{
		APIName:    apiName,
		ReturnCode: returnCode,
		Cause:      lastError,
	}
}
