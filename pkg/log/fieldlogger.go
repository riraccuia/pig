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

import "github.com/riraccuia/pig/pkg/common"

var _ common.Logger = (*FieldLogger)(nil)

// FieldLogger is a child of Logger with predefined fields added to every message.
type FieldLogger struct {
	*Logger
	parent *Logger
}

// WithFields returns a FieldLogger derived from the logger that will add the given fields to every message.
func (l *Logger) WithFields(fields []common.LoggerField) common.Logger {
	ctx := l.log.With()
	for _, f := range fields {
		ctx = ctx.Any(f.Key, f.Value)
	}
	return &FieldLogger{
		parent: l,
		Logger: &Logger{
			log:    ctx.Logger(),
			output: l.output,
		},
	}
}

// WithFields returns a FieldLogger that inherits the existing context fields and adds the given fields.
func (l *FieldLogger) WithFields(fields []common.LoggerField) common.Logger {
	ctx := l.log.With() // inherit existing context fields
	for _, f := range fields {
		ctx = ctx.Any(f.Key, f.Value)
	}
	return &FieldLogger{
		parent: l.parent,
		Logger: &Logger{
			log:    ctx.Logger(),
			output: l.output,
		},
	}
}

func (l *FieldLogger) SetLevel(level string) {
	// SetLevel is a no-op for FieldLogger
}

func (f *FieldLogger) Flush() {
	// Flush is a no-op for FieldLogger
}
