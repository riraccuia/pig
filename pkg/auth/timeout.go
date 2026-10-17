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

package auth

import (
	"context"
	"io"
	"time"
)

// DefaultAuthTimeout bounds Authenticate when no method-specific timeout is configured.
const DefaultAuthTimeout = time.Minute

type deadLiner interface {
	SetDeadline(t time.Time) error
}

// BindAuthTimeout bounds authentication with duration d (DefaultAuthTimeout when d <= 0).
// It returns a child context and, when rw supports SetDeadline, it sets a matching connection deadline.
// The returned cancel clears the deadline and cancels the child context. Always defer it to avoid context
// leaks and a broken connection.
func BindAuthTimeout(ctx context.Context, d time.Duration, rw io.ReadWriter) (context.Context, context.CancelFunc) {
	if d <= 0 {
		d = DefaultAuthTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, d)
	dl, ok := rw.(deadLiner)
	if ok {
		_ = dl.SetDeadline(time.Now().Add(d))
	}
	return ctx, func() {
		if ok {
			_ = dl.SetDeadline(time.Time{})
		}
		cancel()
	}
}
