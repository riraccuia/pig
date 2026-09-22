//go:build windows

package win

import (
	"errors"
	"io/fs"
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

func TestAPIErrorObjectAlreadyExistsIsExist(t *testing.T) {
	err := newReturnCodeError("CreateIpForwardEntry2", uintptr(windows.ERROR_OBJECT_ALREADY_EXISTS))

	if !errors.Is(err, fs.ErrExist) {
		t.Fatalf("errors.Is(err, fs.ErrExist) = false, want true; err=%v", err)
	}
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("errors.Is(err, os.ErrExist) = false, want true")
	}

	other := newReturnCodeError("CreateIpForwardEntry2", uintptr(windows.ERROR_INVALID_PARAMETER))
	if errors.Is(other, fs.ErrExist) {
		t.Fatalf("errors.Is(other, fs.ErrExist) = true, want false; err=%v", other)
	}
}
