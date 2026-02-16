//go:build windows
// +build windows

package win

import (
	"errors"
	"fmt"

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
	if e == nil {
		return nil
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
