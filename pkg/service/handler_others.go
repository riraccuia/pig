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
