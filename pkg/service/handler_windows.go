//go:build windows

package service

import (
	"errors"

	"golang.org/x/sys/windows/svc"
)

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

	serviceRunner := windowsService{handler: h}
	err := svc.Run(h.name, &serviceRunner)
	if err != nil {
		return err
	}

	return nil
}

func (h *Handler) runStart() error {
	if h.onStart == nil {
		return nil
	}

	return h.onStart()
}

func (h *Handler) runStop() error {
	if h.onStop == nil {
		return nil
	}

	return h.onStop()
}

type windowsService struct {
	handler *Handler
}

func (s *windowsService) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	var status svc.Status
	status.State = svc.StartPending
	changes <- status

	if s.handler == nil {
		return false, 1
	}

	startErr := s.handler.runStart()
	if startErr != nil {
		return false, 1
	}

	status.State = svc.Running
	status.Accepts = svc.AcceptStop
	changes <- status

	for request := range requests {
		if request.Cmd == svc.Interrogate {
			changes <- status
			continue
		}

		if request.Cmd != svc.Stop {
			continue
		}

		status.State = svc.StopPending
		changes <- status

		stopErr := s.handler.runStop()
		if stopErr != nil {
			return false, 1
		}

		status.State = svc.Stopped
		changes <- status
		return false, 0
	}

	status.State = svc.Stopped
	changes <- status
	return false, 0
}
