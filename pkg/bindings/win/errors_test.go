//go:build windows

package win

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

func TestAPIErrorObjectAlreadyExistsIsExist(t *testing.T) {
	err := newReturnCodeError("CreateIpForwardEntry2", uintptr(windows.ERROR_OBJECT_ALREADY_EXISTS))

	if !os.IsExist(err) {
		t.Fatalf("os.IsExist(err) = false, want true; err=%v", err)
	}
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("errors.Is(err, os.ErrExist) = false, want true")
	}

	other := newReturnCodeError("CreateIpForwardEntry2", uintptr(windows.ERROR_INVALID_PARAMETER))
	if os.IsExist(other) {
		t.Fatalf("os.IsExist(other) = true, want false; err=%v", other)
	}
}
