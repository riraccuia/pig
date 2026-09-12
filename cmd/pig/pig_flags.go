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

package main

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"flag"
	"fmt"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/log"
)

const (
	FLAG_MAIN_CONNECT = "c"
	FLAG_MAIN_LISTEN  = "l"
	FLAG_MAIN_CONFIG  = "config"
	FLAG_MAIN_STUN    = "stun"
	FLAG_MAIN_DOCS    = "docs"

	FLAG_TO_CFG   = "to-cfg"
	FLAG_SIMPLE   = "s"
	FLAG_ID       = "id"
	FLAG_ADDR     = "a"
	FLAG_BIND     = "I"
	FLAG_PROTO    = "P"
	FLAG_SPORT    = "p"
	FLAG_TADDR    = "ta"
	FLAG_RETRY    = "r"
	FLAG_ROUTE    = "R"
	FLAG_SCRIPT   = "S"
	FLAG_VERBOSE  = "v"
	FLAG_CERT     = "cert"
	FLAG_KEY      = "key"
	FLAG_INSECURE = "k"
	FLAG_CA       = "ca"
	FLAG_AUTH     = "A"
	FLAG_JWK      = "jwk"
	FLAG_TOKEN    = "T"
	FLAG_STUN     = "stun"
	FLAG_MQTT     = "mqtt"
	FLAG_SIGKEY   = "sk"
	FLAG_MTU      = "mtu"
	FLAG_STREAMS  = "os"
	FLAG_QSIZE    = "qs"
	FLAG_WRED_WF  = "wf"
	FLAG_WRED_DP  = "wd"
	FLAG_WRED_TH  = "wt"

	FLAG_DOCS_CONFIG = FLAG_MAIN_CONFIG
	FLAG_DOCS_ENV    = "env"
	FLAG_DOCS_PROTOS = "protos"

	FLAG_OUT_MARKDOWN = "md"
)

var (
	// map values for all flags: flag name, [supported mode (c=connect, l=listen, a=all), description]
	pigFlags = map[string][3]string{
		// output settings
		FLAG_TO_CFG: {FLAG_TO_CFG, "a", "Takes either 'json' or 'toml'. Outputs the config in the specified format and exits."},
		// general settings
		FLAG_SIMPLE: {FLAG_SIMPLE, "a", "Simple mode. Disables NAT traversal to establish direct connections, in which case ports need to be opened manually on edge routers and/or firewalls."},
		FLAG_ID:     {FLAG_ID, "a", "ID or friendly name for a listening node. This identifier is registered for signaling during NAT traversal. When the connecting side uses it, it doesn't need to know the other node's address."},
		FLAG_ADDR:   {FLAG_ADDR, "a", "Address host[:port]. Or use -id in NAT traversal mode. In simple mode, this is the connect node's target address and the listen node's bind address."},
		FLAG_BIND:   {FLAG_BIND, "a", "The adapter/interface to bind to, required only when '-P' is *-ICMP."},
		FLAG_PROTO:  {FLAG_PROTO, "a", "Transport protocol for the tunnel. See '" + binaryName + " -list-protos' for the list of supported ones. The special '.' option selects all available protocols for candidate generation when NAT traversal is used."},
		FLAG_SPORT:  {FLAG_SPORT, "c", "Source port to use for the connection."},
		FLAG_TADDR:  {FLAG_TADDR, "a", "Tunnel address. Multiple addresses (IPv4 and/or IPv6) can be specified as a comma separated CIDR values. Defaults to 172.31.254.1/29 for connect nodes and 172.31.255.1/24 for listening nodes."},
		FLAG_RETRY:  {FLAG_RETRY, "c", "Reconnect interval in seconds. Defaults to " + strconv.Itoa(config.DefaultRetryInterval) + "."},
		FLAG_ROUTE:  {FLAG_ROUTE, "c", "Route subnets through the tunnel. Provide 'full' to route all traffic, or a comma separated list of CIDR prefixes, e.g. '192.168.1.0/24,10.0.0.0/8'."},
		// scripting settings
		FLAG_SCRIPT: {FLAG_SCRIPT, "c", "Takes the path to an executable file that will be called on tunnel events. See '" + binaryName + " -env' for the list of environment variables that are passed to the script."},
		// logging settings
		FLAG_VERBOSE: {FLAG_VERBOSE, "a", "Print more verbose output. Use 0 (default) for info, 1 for debug, 2 for trace."},
		// certificate settings
		FLAG_CERT: {FLAG_CERT, "a", "Path to a certificate file for mTLS."},
		FLAG_KEY:  {FLAG_KEY, "a", "Path to a private key file for mTLS."},
		// trust settings
		FLAG_INSECURE: {FLAG_INSECURE, "a", "Insecure. Disable certificate verification."},
		FLAG_CA:       {FLAG_CA, "a", "Path to a CA certificate or bundle file for mTLS."},
		// auth settings
		FLAG_AUTH:  {FLAG_AUTH, "a", "Authentication type. Set to 'jwt' to enable JWT authentication. More types will be supported in future versions."},
		FLAG_JWK:   {FLAG_JWK, "l", "Path to a public key file used to verify JWT tokens. This can be a local file or a URL. PEM and JWKS (json) formats are supported."},
		FLAG_TOKEN: {FLAG_TOKEN, "c", "Sets the token string for JWT client authentication. It is recommended to populate the " + config.EnvToken.Name() + " environment variable instead of using this flag."},
		// NAT traversal settings
		FLAG_STUN:   {FLAG_STUN, "a", "STUN server to query during NAT traversal."},
		FLAG_MQTT:   {FLAG_MQTT, "a", "MQTT broker to use for NAT traversal signaling. See '" + binaryName + " -env' for additional configuration options."},
		FLAG_SIGKEY: {FLAG_SIGKEY, "a", "Encryption key for signaling messages. Connecting peers need to use the same key as the listeners."},
		// nerd settings
		FLAG_MTU:     {FLAG_MTU, "a", "MTU (Maximum Transmission Unit) size of the tunnel adapter."},
		FLAG_STREAMS: {FLAG_STREAMS, "c", "Open streams. The number of individual streams that the connecting side will open with stream based protocols like quic. Defaults to the number of CPU cores."},
		FLAG_QSIZE:   {FLAG_QSIZE, "a", "Size of the packet queues used by tunnels."},
		// WRED settings
		FLAG_WRED_WF: {FLAG_WRED_WF, "a", "Weight factor for WRED, lower values mean more weight to recent packets. Defaults to " + strconv.FormatFloat(config.DefaultWredWF, 'f', -1, 64) + "."},
		FLAG_WRED_DP: {FLAG_WRED_DP, "a", "Drop probability for WRED. Accepts decimals between 0 and 1. Defaults to " + strconv.FormatFloat(config.DefaultWredDP, 'f', -1, 64) + "."},
		FLAG_WRED_TH: {FLAG_WRED_TH, "a", "Threshold for WRED as a fraction of the queue length. Accepts decimals between 0 and 1. Defaults to " + strconv.FormatFloat(config.DefaultWredThresh, 'f', -1, 64) + "."},
	}
)

type Flags struct {
	verbose        int
	address        string
	proto          string
	srcPort        int
	tunnelAddress  string
	certFile       string
	keyFile        string
	insecure       bool
	mtu            int
	streamCount    int
	retryInterval  int
	bindAdapter    string
	wredWF         float64 // Weight factor for WRED
	wredDP         float64 // Drop probability for WRED
	wredThresh     float64 // Threshold for WRED
	scriptPath     string
	authType       string
	token          string
	jwkSource      string
	mtlsCA         string
	queueSize      int
	stunServerAddr string
	iceDisabled    bool
	iceKey         string
	iceMQTTBroker  string
	iceSignalingID string
	route          string
	toConfig       string
}

func parsePigFlags(mode Mode) *Flags {
	flagSet := flag.NewFlagSet("pig", flag.ExitOnError)
	flags := defineFlags(flagSet)
	if !strings.HasPrefix(os.Args[1], "-") {
		os.Args[1] = "-" + os.Args[1]
	}
	if len(os.Args) < 3 {
		printListenConnectUsage(mode)
		os.Exit(0)
	}
	startArg := 2
	if os.Args[1] == "-config" || os.Args[1] == "--config" {
		startArg = 1
	}
	flagSet.Usage = func() {
		printListenConnectUsage(mode)
	}
	flagSet.Parse(os.Args[startArg:])
	return flags
}

// setConfigField sets a field in the config if it is not already set
// and the value is not zero. It returns true if the field was changed.
func setConfigField[T comparable](f *T, v T) (changed bool) {
	if reflect.ValueOf(*f).IsZero() && !reflect.ValueOf(v).IsZero() {
		*f = v
		changed = true
	}
	return
}

func initPig(mode Mode) (*config.Config, *log.Logger) {
	var (
		logger *log.Logger
		cfg    *config.Config
		flags  *Flags
		err    error
	)
	flags = parsePigFlags(mode)
	//cfg, err = loadConfigFile(flags.configPath)
	//if err != nil {
	//	log.NewBlockingLogger().Fatalf("Failed to load config file: %v", err)
	//}
	//if cfg == nil {
	cfg = &config.Config{}
	applyCommandLineFlags(cfg, flags, mode, log.NewBlockingLogger())
	//}
	switch cfg.LogConfig.File {
	case "":
		logger = log.NewLogger()
		logger.SetLevel(cfg.LogConfig.Level)
	default:
		logger, err = log.NewFileLogger(cfg.LogConfig.File, cfg.LogConfig.RotateSize)
		if err != nil {
			log.NewBlockingLogger().Fatalf("Failed to create file logger: %v", err)
		}
		logger.SetLevel(cfg.LogConfig.Level)
	}

	applyICESettings(cfg, flags, logger)
	outputConfig(cfg, flags.toConfig)

	err = cfg.Initialize()
	if err != nil {
		log.NewBlockingLogger().Fatalf("Failed to initialize config: %v", err)
	}
	return cfg, logger
}

func initPigConfig() *config.Config {
	flag.Usage = printConfigUsage
	if len(os.Args) < 3 {
		printConfigUsage()
		os.Exit(1)
	}
	var configPath string
	flag.StringVar(&configPath, "config", "", "Path to configuration file to load settings from, in json or toml format.")
	flag.Parse()
	cfg, err := loadConfigFile(configPath)
	if err != nil {
		log.NewBlockingLogger().Fatalf("Failed to load config file: %v", err)
	}
	err = cfg.Initialize()
	if err != nil {
		log.NewBlockingLogger().Fatalf("Failed to initialize config: %v", err)
	}
	return cfg
}

func loadConfigFile(configPath string) (*config.Config, error) {
	if configPath == "" {
		return nil, nil
	}
	cfg, err := config.LoadConfigFromFile(configPath)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

func outputConfig(cfg *config.Config, format string) {
	if format == "" {
		return
	}
	switch format {
	case "toml":
		toml.NewEncoder(os.Stdout).Encode(cfg)
	default:
		out, err := json.Marshal(cfg, json.Deterministic(true), json.OmitZeroStructFields(true))
		if err != nil {
			log.NewBlockingLogger().Fatalf("Failed to marshal config: %v", err)
		}
		v := jsontext.Value(out)
		v.Indent(jsontext.WithIndent("  "))
		os.Stdout.Write([]byte(v))
	}
	os.Exit(0)
}

func defineFlags(flagSet *flag.FlagSet) *Flags {
	flags := &Flags{}

	// output settings
	flagSet.StringVar(&flags.toConfig, pigFlags[FLAG_TO_CFG][0], "", pigFlags[FLAG_TO_CFG][2])
	// general settings
	flagSet.BoolVar(&flags.iceDisabled, pigFlags[FLAG_SIMPLE][0], false, pigFlags[FLAG_SIMPLE][2])
	flagSet.StringVar(&flags.iceSignalingID, pigFlags[FLAG_ID][0], "", pigFlags[FLAG_ID][2])
	flagSet.StringVar(&flags.address, pigFlags[FLAG_ADDR][0], "", pigFlags[FLAG_ADDR][2])
	flagSet.StringVar(&flags.bindAdapter, pigFlags[FLAG_BIND][0], "", pigFlags[FLAG_BIND][2])
	flagSet.StringVar(&flags.proto, pigFlags[FLAG_PROTO][0], string(config.DefaultICEProtocol), pigFlags[FLAG_PROTO][2])
	flagSet.IntVar(&flags.srcPort, pigFlags[FLAG_SPORT][0], 0, pigFlags[FLAG_SPORT][2])
	flagSet.StringVar(&flags.tunnelAddress, pigFlags[FLAG_TADDR][0], "", pigFlags[FLAG_TADDR][2])
	flagSet.IntVar(&flags.retryInterval, pigFlags[FLAG_RETRY][0], config.DefaultRetryInterval, pigFlags[FLAG_RETRY][2])
	flagSet.StringVar(&flags.route, pigFlags[FLAG_ROUTE][0], "", pigFlags[FLAG_ROUTE][2])
	// scripting settings
	flagSet.StringVar(&flags.scriptPath, pigFlags[FLAG_SCRIPT][0], "", pigFlags[FLAG_SCRIPT][2])
	// logging settings
	flagSet.IntVar(&flags.verbose, pigFlags[FLAG_VERBOSE][0], 0, pigFlags[FLAG_VERBOSE][2])
	// certificate settings
	flagSet.StringVar(&flags.certFile, pigFlags[FLAG_CERT][0], "", pigFlags[FLAG_CERT][2])
	flagSet.StringVar(&flags.keyFile, pigFlags[FLAG_KEY][0], "", pigFlags[FLAG_KEY][2])
	// trust settings
	flagSet.BoolVar(&flags.insecure, pigFlags[FLAG_INSECURE][0], false, pigFlags[FLAG_INSECURE][2])
	flagSet.StringVar(&flags.mtlsCA, pigFlags[FLAG_CA][0], "", pigFlags[FLAG_CA][2])
	// auth settings
	flagSet.StringVar(&flags.authType, pigFlags[FLAG_AUTH][0], string(config.AuthTypeNone), pigFlags[FLAG_AUTH][2])
	flagSet.StringVar(&flags.jwkSource, pigFlags[FLAG_JWK][0], "", pigFlags[FLAG_JWK][2])
	flagSet.StringVar(&flags.token, pigFlags[FLAG_TOKEN][0], "", pigFlags[FLAG_TOKEN][2])
	// NAT traversal settings
	flagSet.StringVar(&flags.stunServerAddr, pigFlags[FLAG_STUN][0], config.DefaultICESTUNServer, pigFlags[FLAG_STUN][2])
	flagSet.StringVar(&flags.iceMQTTBroker, pigFlags[FLAG_MQTT][0], config.DefaultICEBrokerAddress, pigFlags[FLAG_MQTT][2])
	flagSet.StringVar(&flags.iceKey, pigFlags[FLAG_SIGKEY][0], "", pigFlags[FLAG_SIGKEY][2])
	// nerd settings
	flagSet.IntVar(&flags.mtu, pigFlags[FLAG_MTU][0], config.DefaultMTU, pigFlags[FLAG_MTU][2])
	flagSet.IntVar(&flags.streamCount, pigFlags[FLAG_STREAMS][0], config.DefaultStreamCount, pigFlags[FLAG_STREAMS][2])
	flagSet.IntVar(&flags.queueSize, pigFlags[FLAG_QSIZE][0], config.DefaultQueueSize, pigFlags[FLAG_QSIZE][2])
	flagSet.Float64Var(&flags.wredWF, pigFlags[FLAG_WRED_WF][0], config.DefaultWredWF, pigFlags[FLAG_WRED_WF][2])
	flagSet.Float64Var(&flags.wredDP, pigFlags[FLAG_WRED_DP][0], config.DefaultWredDP, pigFlags[FLAG_WRED_DP][2])
	flagSet.Float64Var(&flags.wredThresh, pigFlags[FLAG_WRED_TH][0], config.DefaultWredThresh, pigFlags[FLAG_WRED_TH][2])
	return flags
}

func applyCommandLineFlags(cfg *config.Config, flags *Flags, mode Mode, logger common.Logger) {
	// Ensure a single tunnel entry exists for CLI mode
	cfg.Tunnels = []config.TunnelConfig{{}}
	tc := &cfg.Tunnels[0]
	tc.Direction = directionFromMode(mode)
	adapterCfg := &cfg.Adapter
	if tc.Direction == config.TunnelDirectionListen {
		tc.Adapter = &config.AdapterConfig{}
		adapterCfg = tc.Adapter
	}

	switch flags.iceDisabled {
	case true:
		if flags.proto == "." {
			flags.proto = string(config.DefaultICEProtocol)
		}
		err := configureEndpoint(tc, flags.address, string(tc.Direction), logger)
		if err != nil {
			logger.Fatalf("Failed to configure %s address: %v", tc.Direction, err)
		}
		if flags.srcPort == 0 {
			break
		}
		if tc.Direction == config.TunnelDirectionConnect {
			tc.Connect.SrcPort = flags.srcPort
		}
	case false:
		if flags.srcPort == 0 {
			break
		}
		if tc.Direction == config.TunnelDirectionListen {
			tc.Listen.Port = flags.srcPort
			break
		}
		tc.Connect.SrcPort = flags.srcPort
	}

	tc.Proto = config.TransportType(flags.proto)

	/*if flags.iceDisabled && flags.proto == "." {
		flags.proto = DefaultICEProtocol
	}
	tc.Proto = config.TransportType(flags.proto)

	if flags.iceDisabled || tc.Direction == config.TunnelDirectionListen {
		err := configureEndpoint(tc, flags.address, string(tc.Direction), logger)
		if err != nil && flags.iceDisabled {
			logger.Fatalf("Failed to configure listen address: %v", err)
		}
	}*/

	setConfigField(&tc.TLSConfig.Insecure, flags.insecure)
	if tc.Direction == config.TunnelDirectionListen {
		setConfigField(&tc.TLSConfig.CertFile, flags.certFile)
		setConfigField(&tc.TLSConfig.KeyFile, flags.keyFile)
	}

	setConfigField(&tc.StreamCount, flags.streamCount)
	setConfigField(&tc.ReconnectInterval, flags.retryInterval)

	setConfigField(&tc.Wred.DropProbability, flags.wredDP)
	setConfigField(&tc.Wred.Threshold, flags.wredThresh)
	setConfigField(&tc.Wred.WeightFactor, flags.wredWF)

	// Adapter settings
	if flags.tunnelAddress != "" {
		adapterCfg.TunnelAddress = strings.Split(flags.tunnelAddress, ",")
	}
	// setConfigField(&adapterCfg.TunnelAddress[0], flags.tunnelAddress)

	setConfigField(&adapterCfg.BindAdapter, flags.bindAdapter)
	setConfigField(&adapterCfg.MTU, flags.mtu)
	setConfigField(&adapterCfg.QueueSize, flags.queueSize)

	setConfigField(&cfg.ScriptPath, flags.scriptPath)

	switch flags.verbose {
	case 0:
		cfg.LogConfig.Level = "info"
	case 1:
		cfg.LogConfig.Level = "debug"
	case 2:
		cfg.LogConfig.Level = "trace"
	default:
		cfg.LogConfig.Level = "info"
	}

	buildAuthSettingsFromFlags(tc, flags, logger)
	buildICESettingsFromFlags(tc, flags, logger)
	buildRouteSettingsFromFlags(cfg, tc, flags, logger)
}

func buildAuthSettingsFromFlags(tc *config.TunnelConfig, flags *Flags, logger common.Logger) {
	if tc.Auth != nil {
		return
	}

	tc.Auth = &config.AuthConfig{}
	if flags.mtlsCA != "" && !flags.insecure {
		tc.Auth.MTLS = &config.MTLSConfig{
			TrustPEM: flags.mtlsCA,
		}
	}
	if tc.Direction == config.TunnelDirectionConnect && flags.certFile != "" {
		if tc.Auth.MTLS == nil {
			tc.Auth.MTLS = &config.MTLSConfig{}
		}
		tc.Auth.MTLS.CertFile = flags.certFile
		tc.Auth.MTLS.KeyFile = flags.keyFile
	}

	if flags.authType == "" {
		return
	}

	if !config.AuthType(flags.authType).IsValid() {
		logger.Fatalf("Invalid authentication type: %s", flags.authType)
	}

	tc.Auth.Type = config.AuthType(flags.authType)

	if tc.Auth.Type == config.AuthTypeJWT {
		tc.Auth.JWT = &config.JWTAuth{
			Token:           flags.token,
			PublicKeySource: flags.jwkSource,
		}
	}
}

func buildICESettingsFromFlags(tc *config.TunnelConfig, flags *Flags, logger common.Logger) {
	if flags.iceDisabled {
		tc.ICE = &config.ICEConfig{
			Enabled: false,
		}
		return
	}

	tc.ICE = &config.ICEConfig{
		Enabled: true,
		//STUNAddress: flags.stunServerAddr,
	}

	tc.ICE.Signaling = &config.ICESignalingOpts{
		EncryptionKey: flags.iceKey,
	}

	id := flags.iceSignalingID
	if id != "" {
		tc.ICE.Signaling.ServerID = id
		return
	}

	tc.ICE.Signaling.ServerID = flags.address
}

func applyICESettings(cfg *config.Config, flags *Flags, logger common.Logger) {
	for i := range cfg.Tunnels {
		tc := &cfg.Tunnels[i]
		if tc.ICE == nil || !tc.ICE.Enabled {
			continue
		}
		//setConfigField(&tc.ICE.STUNAddress, flags.stunServerAddr)
		setConfigField(&cfg.STUNAddress, flags.stunServerAddr)
		if tc.ICE.Signaling == nil {
			tc.ICE.Signaling = &config.ICESignalingOpts{}
		}
		setConfigField(&cfg.MQTTBroker.Address, flags.iceMQTTBroker)
	}
}

func configureEndpoint(tc *config.TunnelConfig, addr string, addrType string, logger common.Logger) error {
	/*if addr == "." {
		tc.Listen.Address = "0.0.0.0"
		tc.Listen.Port = 0
		return nil
	}*/
	address, strPort, err := net.SplitHostPort(addr)
	if err != nil && strings.Contains(err.Error(), "missing port") {
		address = addr
		err = nil
	}
	if err != nil {
		return fmt.Errorf("failed to parse %s address: %v", addrType, err)
	}
	if address == "" {
		address = "0.0.0.0"
	}
	if strPort == "" {
		strPort = "0"
	}
	port, err := strconv.Atoi(strPort)
	if err != nil {
		return fmt.Errorf("failed to parse %s address port: %v", addrType, err)
	}
	if net.ParseIP(address) == nil {
		ips, err := net.LookupIP(address)
		if err != nil {
			return fmt.Errorf("failed to resolve %s address: %v", addrType, err)
		}
		if len(ips) == 0 {
			return fmt.Errorf("no IP addresses found for %s address: %s", addrType, address)
		}
		address = ips[0].String()
	}
	switch addrType {
	case "listen":
		tc.Listen.Address = address
		tc.Listen.Port = port
	default:
		tc.Connect.Address = address
		tc.Connect.Port = port
	}
	return nil
}

func directionFromMode(mode Mode) config.TunnelDirection {
	switch mode {
	case ModeListen:
		return config.TunnelDirectionListen
	default:
		return config.TunnelDirectionConnect
	}
}

func buildRouteSettingsFromFlags(cfg *config.Config, tc *config.TunnelConfig, flags *Flags, logger common.Logger) {
	if flags.route == "" {
		return
	}
	if tc.Direction != config.TunnelDirectionConnect {
		return
	}
	if flags.route == "full" {
		cfg.RouteConfig.Enabled = true
		tc.Routes = buildFullTunnelRoutes()
		return
	}
	// expecting a comma separated list of CIDR prefixes
	for prefix := range strings.SplitSeq(flags.route, ",") {
		// validate the prefix
		_, _, err := net.ParseCIDR(prefix)
		if err != nil {
			logger.Fatalf("Invalid CIDR prefix: %s", prefix)
		}
		tc.Routes = append(tc.Routes, config.Route{
			Destination: prefix,
			Type:        config.RouteTypeTunnel,
		})
	}
	if len(tc.Routes) != 0 {
		cfg.RouteConfig.Enabled = true
	}
}

func buildFullTunnelRoutes() []config.Route {
	return []config.Route{
		{
			Destination: "0.0.0.0/1",
			Type:        config.RouteTypeTunnel,
		},
		{
			Destination: "128.0.0.0/1",
			Type:        config.RouteTypeTunnel,
		},
		{
			Destination: "2000::/3",
			Type:        config.RouteTypeTunnel,
		},
		{
			Destination: "64:ff9b::/96",
			Type:        config.RouteTypeTunnel,
		},
	}
}
