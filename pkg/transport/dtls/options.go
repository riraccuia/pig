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

	"github.com/pion/dtls/v4"
)

// ConvertToDTLSServerOptions produces a slice of ServerOption suitable for dtls.ServerWithOptions
func ConvertToDTLSServerOptions(tlsCfg *tls.Config, mtu int) []dtls.ServerOption {
	var opts []dtls.ServerOption

	commonOpts := convertToDTLSCommonOptions(tlsCfg, mtu)
	for _, opt := range commonOpts {
		opts = append(opts, dtls.ServerOption(opt))
	}

	// Server-specific options
	if tlsCfg.ClientCAs != nil {
		opts = append(opts, dtls.WithClientCAs(tlsCfg.ClientCAs))
	}
	if tlsCfg.ClientAuth != tls.NoClientCert {
		opts = append(opts, dtls.WithClientAuth(dtls.ClientAuthType(tlsCfg.ClientAuth)))
	}

	return opts
}

// ConvertToDTLSClientOptions produces a slice of ClientOption suitable for dtls.ClientWithOptions
func ConvertToDTLSClientOptions(tlsCfg *tls.Config, mtu int) []dtls.ClientOption {
	var opts []dtls.ClientOption

	commonOpts := convertToDTLSCommonOptions(tlsCfg, mtu)
	for _, opt := range commonOpts {
		opts = append(opts, dtls.ClientOption(opt))
	}

	// Client-specific option
	if tlsCfg.RootCAs != nil {
		opts = append(opts, dtls.WithRootCAs(tlsCfg.RootCAs))
	}

	return opts
}

func convertToDTLSCommonOptions(tlsCfg *tls.Config, mtu int) []dtls.Option {
	var opts []dtls.Option

	if len(tlsCfg.Certificates) > 0 {
		opts = append(opts, dtls.WithCertificates(tlsCfg.Certificates...))
	}
	if tlsCfg.InsecureSkipVerify {
		opts = append(opts, dtls.WithInsecureSkipVerify(tlsCfg.InsecureSkipVerify))
	}
	if tlsCfg.ServerName != "" {
		opts = append(opts, dtls.WithServerName(tlsCfg.ServerName))
	}
	if len(tlsCfg.NextProtos) > 0 {
		opts = append(opts, dtls.WithSupportedProtocols(tlsCfg.NextProtos...))
	}

	opts = append(opts, dtls.WithMTU(mtu))
	return opts
}
