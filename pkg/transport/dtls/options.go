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

package dtls

import (
	"crypto/tls"

	"github.com/pion/dtls/v3"
)

func getClientOptions(tlsConfig *tls.Config, mtu int) (opts []dtls.ClientOption) {
	if tlsConfig.InsecureSkipVerify {
		opts = append(opts, dtls.WithInsecureSkipVerify(true))
	}
	if tlsConfig.ServerName != "" {
		opts = append(opts, dtls.WithServerName(tlsConfig.ServerName))
	}

	if len(tlsConfig.Certificates) > 0 {
		opts = append(opts, dtls.WithCertificates(tlsConfig.Certificates...))
	}

	if tlsConfig.RootCAs != nil {
		opts = append(opts, dtls.WithRootCAs(tlsConfig.RootCAs))
	}

	opts = append(opts, dtls.WithMTU(mtu))
	return
}

func getServerOptions(tlsConfig *tls.Config, mtu int) (opts []dtls.ServerOption) {
	if tlsConfig.InsecureSkipVerify {
		opts = append(opts, dtls.WithInsecureSkipVerify(true))
	}
	if tlsConfig.ServerName != "" {
		opts = append(opts, dtls.WithServerName(tlsConfig.ServerName))
	}

	if len(tlsConfig.Certificates) > 0 {
		opts = append(opts, dtls.WithCertificates(tlsConfig.Certificates...))
	}

	if tlsConfig.ClientCAs != nil {
		opts = append(opts, dtls.WithClientCAs(tlsConfig.ClientCAs))
	}

	opts = append(opts, dtls.WithMTU(mtu))
	return
}
