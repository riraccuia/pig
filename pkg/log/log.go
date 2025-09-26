package log

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/diode"
)

// Logger wraps zerolog.Logger to provide simplified logging methods
type Logger struct {
	log zerolog.Logger
}

// parseLevel parses a log level string and returns the corresponding zerolog.Level
func parseLevel(level string) zerolog.Level {
	switch level {
	case "trace":
		return zerolog.TraceLevel
	case "debug":
		return zerolog.DebugLevel
	case "info":
		return zerolog.InfoLevel
	case "warn":
		return zerolog.WarnLevel
	case "error":
		return zerolog.ErrorLevel
	case "fatal":
		return zerolog.FatalLevel
	case "panic":
		return zerolog.PanicLevel
	case "nolevel":
		return zerolog.NoLevel
	default:
		return zerolog.InfoLevel
	}
}

// NewLogger creates a new Logger instance
func NewLogger() *Logger {
	wr := diode.NewWriter(os.Stdout, 1024, 10*time.Millisecond, func(missed int) {
		fmt.Printf("Logger Dropped %d messages", missed)
	})
	output := zerolog.ConsoleWriter{
		Out:        wr, //zerolog.SyncWriter(NewBufferedWriter(ctx, 1024)),
		TimeFormat: time.RFC3339,
	}
	zl := zerolog.New(output).Level(zerolog.InfoLevel).With().Timestamp().Logger()
	return &Logger{
		log: zl,
	}
}

func NewFileLogger(path string, rotateSize int64) (*Logger, error) {
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
	l.log = l.log.Level(parseLevel(level))
}

func (l *Logger) Info(args ...interface{}) {
	l.log.Info().Msg(fmt.Sprint(args...))
}

func (l *Logger) Infof(format string, args ...interface{}) {
	l.log.Info().Msg(fmt.Sprintf(format, args...))
}

func (l *Logger) Error(args ...interface{}) {
	l.log.Error().Msg(fmt.Sprint(args...))
}

func (l *Logger) Errorf(format string, args ...interface{}) {
	l.log.Error().Msg(fmt.Sprintf(format, args...))
}

func (l *Logger) Debug(args ...interface{}) {
	l.log.Debug().Msg(fmt.Sprint(args...))
}

func (l *Logger) Debugf(format string, args ...interface{}) {
	l.log.Debug().Msg(fmt.Sprintf(format, args...))
}

func (l *Logger) Trace(args ...interface{}) {
	l.log.Trace().Msg(fmt.Sprint(args...))
}

func (l *Logger) Tracef(format string, args ...interface{}) {
	l.log.Trace().Msg(fmt.Sprintf(format, args...))
}

func (l *Logger) Fatal(args ...interface{}) {
	l.log.Fatal().Msg(fmt.Sprint(args...))
	os.Exit(1)
}

func (l *Logger) Fatalf(format string, args ...interface{}) {
	l.log.Fatal().Msg(fmt.Sprintf(format, args...))
	//os.Exit(1)
}

// bufferedWriter is a channel that buffers log messages
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
