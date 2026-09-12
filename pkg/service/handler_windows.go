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
