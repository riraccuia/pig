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

package log

import (
	"os"
	"runtime"
	"sync/atomic"
	"time"
)

// FileWriter is a logger that writes to a file.
type FileWriter struct {
	*os.File
	path         string
	rotateSize   int64
	bytesWritten atomic.Int64
	rotating     atomic.Bool
}

// NewFileWriter creates a new FileLogger.
func NewFileWriter(path string) (*FileWriter, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}

	fw := &FileWriter{
		File:         file,
		path:         path,
		bytesWritten: atomic.Int64{},
		rotating:     atomic.Bool{},
	}

	fw.bytesWritten.Store(info.Size())

	return fw, nil
}

// WithRotateSize sets the rotate size for the FileLogger.
func (l *FileWriter) WithRotateSize(bytes int64) *FileWriter {
	l.rotateSize = bytes
	return l
}

// Write writes the log message to the file and rotates the file if it exceeds the rotate size.
func (l *FileWriter) Write(p []byte) (n int, err error) {
	for l.rotating.Load() {
		runtime.Gosched()
	}
	n, err = l.File.Write(p)
	if err != nil {
		return
	}
	l.bytesWritten.Add(int64(n))
	if l.rotateSize > 0 {
		err = l.Rotate(l.rotateSize)
	}
	return
}

// Rotate rotates the file if it exceeds the rotate size.
func (l *FileWriter) Rotate(maxSize int64) error {
	if l.bytesWritten.Load() < maxSize {
		return nil
	}
	info, err := l.File.Stat()
	if err != nil {
		return err
	}
	if info.Size() < maxSize {
		return nil
	}
	if !l.rotating.CompareAndSwap(false, true) {
		return nil
	}
	defer l.rotating.Store(false)
	l.File.Close()
	err = os.Rename(l.path, l.path+"."+time.Now().Format("20060102150405"))
	if err != nil {
		return err
	}
	file, err := os.OpenFile(l.path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	l.File = file
	l.bytesWritten.Store(0)
	return nil
}

// Close closes the file.
func (l *FileWriter) Close() error {
	return l.File.Close()
}
