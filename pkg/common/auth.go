package common

import (
	"context"
	"io"
)

// Authenticator defines the interface for authentication methods
type Authenticator interface {
	// Authenticate performs authentication on the given connection
	// Returns error if authentication fails
	Authenticate(ctx context.Context, rw io.ReadWriter) error
}
