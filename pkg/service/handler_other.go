//go:build !windows

package service

import "errors"

type Callback func() error

type Handler struct {
	name    string
	onStart Callback
	onStop  Callback
}

func New(name string, onStart Callback, onStop Callback) (*Handler, error) {
	if name == "" {
		return nil, errors.New("service name is required")
	}

	handler := &Handler{
		name:    name,
		onStart: onStart,
		onStop:  onStop,
	}
	return handler, nil
}

func (h *Handler) Run() error {
	if h == nil {
		return errors.New("service handler is nil")
	}

	return errors.New("windows service handler is only available on Windows")
}
