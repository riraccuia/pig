// Copyright 2026 Riccardo Raccuia
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package controller

import (
	"sync"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/route"
)

type Tunneler interface {
	Name() string
	Config() *config.TunnelConfig
	GetAdapter() common.TunnelAdapter
}

type TunnelInfo struct {
	Logger       common.Logger
	Tunnel       Tunneler
	ActiveRoutes sync.Map
}

func (t *TunnelInfo) NewActiveRoute(r *route.Route) {
	if r == nil {
		return
	}
	t.ActiveRoutes.Store(r.String(), r)
}

func (t *TunnelInfo) DeleteActiveRoute(r *route.Route) bool {
	if r == nil {
		return false
	}
	return t.ActiveRoutes.CompareAndDelete(r.String(), r)
}
