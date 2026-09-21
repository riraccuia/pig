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
	"context"
	"fmt"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/diode"
)

// Logger wraps zerolog.Logger to provide simplified logging methods.
type Logger struct {
	log zerolog.Logger
}

// NewLogger creates a new Logger instance.
func NewLogger() *Logger {
	wr := diode.NewWriter(os.Stdout, 1024, 10*time.Millisecond, func(missed int) {
		fmt.Printf("Logger Dropped %d messages", missed)
	})
	output := zerolog.ConsoleWriter{
		Out:        wr, //zerolog.SyncWriter(NewBufferedWriter(ctx, 1024)),
		NoColor:    noColor,
		TimeFormat: time.RFC3339,
	}
	zl := zerolog.New(output).Level(zerolog.InfoLevel).With().Timestamp().Logger()
	return &Logger{
		log: zl,
	}
}

func NewFileLogger(path string, rotateSizeAny any) (*Logger, error) {
	rotateSize, err := RotateSizeFromRotateString(rotateSizeAny)
	if err != nil {
		return nil, err
	}
	fw, err := NewFileWriter(path)
	if err != nil {
		return nil, err
	}
	if rotateSize > 0 {
		fw = fw.WithRotateSize(rotateSize)
	}
	output := &zerolog.ConsoleWriter{
		Out:        fw,
		NoColor:    true,
		TimeFormat: time.RFC3339,
	}
	zl := zerolog.New(output).Level(zerolog.InfoLevel).With().Timestamp().Logger()
	return &Logger{
		log: zl,
	}, nil
}

// NewBlockingLogger creates a new Logger instance that writes directly to stdout
// without buffering. This logger will block until each message is written.
func NewBlockingLogger() *Logger {
	output := zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: time.RFC3339,
	}
	zl := zerolog.New(output).Level(zerolog.InfoLevel).With().Timestamp().Logger()
	return &Logger{
		log: zl,
	}
}

func (l *Logger) SetLevel(level string) {
	lvl, err := zerolog.ParseLevel(level)
	if err != nil {
		panic(fmt.Sprintf("cannot parse log level %s: %v", level, err))
	}
	l.log = l.log.Level(lvl)
}

func (l *Logger) PrintLevel(level string, args ...any) {
	lvl, err := zerolog.ParseLevel(level)
	if err != nil {
		panic(fmt.Sprintf("cannot parse log level %s: %v", level, err))
	}
	l.log.WithLevel(lvl).Msg(fmt.Sprint(args...))
}

func (l *Logger) Info(args ...any) {
	l.log.Info().Msg(fmt.Sprint(args...))
}

func (l *Logger) Infof(format string, args ...any) {
	l.log.Info().Msg(fmt.Sprintf(format, args...))
}

func (l *Logger) Error(args ...any) {
	l.log.Error().Msg(fmt.Sprint(args...))
}

func (l *Logger) Errorf(format string, args ...any) {
	l.log.Error().Msg(fmt.Sprintf(format, args...))
}

func (l *Logger) Debug(args ...any) {
	l.log.Debug().Msg(fmt.Sprint(args...))
}

func (l *Logger) Debugf(format string, args ...any) {
	l.log.Debug().Msg(fmt.Sprintf(format, args...))
}

func (l *Logger) Trace(args ...any) {
	l.log.Trace().Msg(fmt.Sprint(args...))
}

func (l *Logger) Tracef(format string, args ...any) {
	l.log.Trace().Msg(fmt.Sprintf(format, args...))
}

func (l *Logger) Fatal(args ...any) {
	l.log.Fatal().Msg(fmt.Sprint(args...))
	os.Exit(1)
}

func (l *Logger) Fatalf(format string, args ...any) {
	l.log.Fatal().Msg(fmt.Sprintf(format, args...))
	//os.Exit(1)
}

// bufferedWriter is a channel that buffers log messages.
type bufferedWriter chan []byte

func NewBufferedWriter(ctx context.Context, n int) bufferedWriter {
	w := make(bufferedWriter, n)
	go func() {
		for {
			var (
				b  []byte
				ok bool
			)
			select {
			case b, ok = <-w:
				if !ok {
					continue
				}
				os.Stdout.Write(b)
			case <-ctx.Done():
				return
			}
		}
	}()
	return w
}

func (w bufferedWriter) Write(b []byte) (int, error) {
	select {
	case w <- b:
		return len(b), nil
	default:
		return 0, fmt.Errorf("buffer is full")
	}
}
