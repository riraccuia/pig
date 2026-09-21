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

package adapter

import (
	"fmt"

	"github.com/riraccuia/pig/pkg/common"
	"golang.org/x/sys/windows"
)

const tunName = "pig"

func newAdapter(config AdapterConfig) (common.TunnelAdapter, error) {
	//wintun.SetLogger(nil)

	adapter, err := CreateTUNWithRequestedGUID(tunName, WintunStaticRequestedGUID)
	if err != nil {
		return nil, fmt.Errorf("failed to create wintun adapter: %v", err)
	}

	err = configureWinTun(adapter, config)
	if err != nil {
		adapter.Close()
		return nil, fmt.Errorf("failed to configure adapter: %v", err)
	}

	_, ipNet, err := getAdapterAddress(adapter.Name(), windows.AF_INET)
	if err != nil {
		return nil, fmt.Errorf("failed to get INET adapter address: %v", err)
	}
	adapter.ip = ipNet

	_, ipNet, err = getAdapterAddress(adapter.Name(), windows.AF_INET6)
	if err != nil {
		return nil, fmt.Errorf("failed to get INET6 adapter address: %v", err)
	}
	adapter.ipv6 = ipNet

	return adapter, nil
}
