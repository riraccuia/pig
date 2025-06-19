package log

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileWriter_Rotation(t *testing.T) {
	var (
		dir string
		err error
	)
	dir, err = os.MkdirTemp("", "logrotationtest")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() {
		// Clean up all test artifacts and the temp directory
		_ = os.RemoveAll(dir)
	}()

	var (
		logPath    string = filepath.Join(dir, "pig_rotation_test.log")
		rotateSize int64  = 100 // bytes
		fw         *FileWriter
	)

	fw, err = NewFileWriter(logPath)
	if err != nil {
		t.Fatalf("failed to create FileWriter: %v", err)
	}
	fw = fw.WithRotateSize(rotateSize)
	defer fw.Close()

	var (
		msg         string = strings.Repeat("A", 50) + "\n"
		totalWrites int    = 5
		totalLength int
	)
	for range totalWrites {
		_, err = fw.Write([]byte(msg))
		if err != nil {
			t.Fatalf("write failed: %v", err)
		}
		totalLength += len(msg)
		time.Sleep(time.Second)
	}

	var (
		filePaths []os.DirEntry
		logFiles  []string
		logData   []byte
	)

	filePaths, err = os.ReadDir(dir)
	if err != nil {
		t.Fatalf("failed to read dir: %v", err)
	}

	for _, f := range filePaths {
		t.Logf("file: %s", f.Name())
		if !strings.HasPrefix(f.Name(), "pig_rotation_test.log") {
			continue
		}
		logFiles = append(logFiles, filepath.Join(dir, f.Name()))
		var data []byte
		data, err = os.ReadFile(filepath.Join(dir, f.Name()))
		if err != nil {
			t.Fatalf("failed to read log file: %v", err)
		}
		logData = append(logData, data...)
	}

	if len(logFiles) <= 1 {
		t.Fatalf("unexpected number of log files: got %d, want at least 2", len(logFiles))
	}

	if len(logData) != totalLength {
		t.Errorf("total length mismatch: got %d, want %d", len(logData), totalLength)
	}
}
