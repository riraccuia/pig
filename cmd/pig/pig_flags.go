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
	"errors"
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
	FLAG_MAIN_VERSION = "version"

	FLAG_TO_CFG       = "to-cfg"
	FLAG_SIMPLE       = "s"
	FLAG_ID           = "id"
	FLAG_ADDR         = "a"
	FLAG_BIND         = "I"
	FLAG_PROTO        = "P"
	FLAG_SPORT        = "p"
	FLAG_TADDR        = "ta"
	FLAG_RETRY        = "r"
	FLAG_IDLE_TIMEOUT = "i"
	FLAG_ROUTE        = "R"
	FLAG_SCRIPT       = "S"
	FLAG_VERBOSE      = "v"
	FLAG_CERT         = "cert"
	FLAG_KEY          = "key"
	FLAG_INSECURE     = "k"
	FLAG_CA           = "ca"
	FLAG_AUTH         = "A"
	FLAG_JWK          = "jwk"
	FLAG_TOKEN        = "T"
	FLAG_STUN         = "stun"
	FLAG_MQTT         = "mqtt"
	FLAG_SIGKEY       = "sk"
	FLAG_MTU          = "mtu"
	FLAG_STREAMS      = "os"
	FLAG_QSIZE        = "qs"
	FLAG_WRED_WF      = "wf"
	FLAG_WRED_DP      = "wd"
	FLAG_WRED_TH      = "wt"
	FLAG_NETCAT       = "nc"
	FLAG_ACCEPT_ONCE  = "o"
	FLAG_HTTP_PROXY   = "http-proxy"
	FLAG_SOCKS_PROXY  = "socks-proxy"

	FLAG_DOCS_CONFIG = FLAG_MAIN_CONFIG
	FLAG_DOCS_ENV    = "env"
	FLAG_DOCS_PROTOS = "protos"

	FLAG_OUT_MARKDOWN = "md"
)

// map values for all flags: flag name, argument, [supported mode (c=connect, l=listen, a=all), description]
var pigFlags = map[string][4]string{
	// output settings
	FLAG_TO_CFG: {FLAG_TO_CFG, "<format> (string)", "a", "Takes either 'json' or 'toml'. Turns the current CLI options into a config file and exits."},
	// adapters
	FLAG_NETCAT:      {FLAG_NETCAT, "", "a", "Stdio adapter. Enables netcat mode: stdin is redirected to the stdout of the connected peer (and vice versa) over the encrypted tunnel."},
	FLAG_HTTP_PROXY:  {FLAG_HTTP_PROXY, "<[host]:port> (string)", "c", "Http proxy adapter. Exposes a local http proxy server over the specified address whose outgoing traffic always traverses the tunnel."},
	FLAG_SOCKS_PROXY: {FLAG_SOCKS_PROXY, "<[host]:port> (string)", "c", "Socks proxy adapter. Exposes a local socks proxy server over the specified address whose outgoing traffic always traverses the tunnel."},
	// general settings
	FLAG_SIMPLE:       {FLAG_SIMPLE, "", "a", "Simple mode. Disables NAT traversal to establish direct connections, in which case ports need to be opened manually on edge routers and/or firewalls."},
	FLAG_ID:           {FLAG_ID, "<id> (string)", "a", "ID or friendly name for a listening node. This identifier is registered for signaling during NAT traversal. When the connecting side uses it, it doesn't need to know the other node's address."},
	FLAG_ADDR:         {FLAG_ADDR, "<[host]:port> (string)", "a", "Listen or connect address for simple mode. Use -id in NAT traversal mode."},
	FLAG_BIND:         {FLAG_BIND, "<adapter> (string)", "a", "The adapter/interface to bind to, required only when '-P' is *-ICMP."},
	FLAG_PROTO:        {FLAG_PROTO, "<protocol> (string)", "a", "Transport protocol for the tunnel. See '" + binaryName + " -docs protos' for the list of supported ones. The special '.' option selects all available protocols for candidate generation with NAT traversal."},
	FLAG_SPORT:        {FLAG_SPORT, "<port> (int)", "c", "Source port to use for the connection."},
	FLAG_TADDR:        {FLAG_TADDR, "<addr1,addr2,...> (string)", "a", "Tunnel address. Multiple addresses (IPv4 and/or IPv6) can be specified as a comma separated CIDR values. Defaults to random generated /" + strconv.Itoa(config.DefaultConnectPrefixLengthV4) + " within " + config.DefaultConnectBasePrefixV4 + " for connect nodes and /" + strconv.Itoa(config.DefaultListenPrefixLengthV4) + " within " + config.DefaultListenBasePrefixV4 + " for listening nodes."},
	FLAG_RETRY:        {FLAG_RETRY, "<seconds> (int)", "c", "Reconnect interval in seconds. Defaults to " + strconv.Itoa(config.DefaultRetryInterval) + "."},
	FLAG_IDLE_TIMEOUT: {FLAG_IDLE_TIMEOUT, "<seconds> (int)", "a", "Idle timeout in seconds for tunnels. Defaults to " + strconv.Itoa(config.DefaultIdleTimeout) + "."},
	FLAG_ROUTE:        {FLAG_ROUTE, "<cidr1,cidr2,...> (string)", "c", "Route subnets through the tunnel. Use 'full4', 'full6', 'full' (as shortcuts for full tunnel routing) or a comma separated list of CIDR prefixes, e.g. '192.168.1.0/24,10.0.0.0/8'."},
	FLAG_ACCEPT_ONCE:  {FLAG_ACCEPT_ONCE, "", "l", "Accept one client, then exit after it disconnects."},
	// scripting settings
	FLAG_SCRIPT: {FLAG_SCRIPT, "<path> (string)", "c", "Takes the path to an executable file that will be called on tunnel events. See '" + binaryName + " -docs env' for the list of environment variables that are passed to the script."},
	// logging settings
	FLAG_VERBOSE: {FLAG_VERBOSE, "<level> (int)", "a", "Print more verbose output. Use 1 (default) for info, 2 for debug, 3 for trace. 0 disables logging."},
	// certificate settings
	FLAG_CERT: {FLAG_CERT, "<path> (string)", "a", "Path to a certificate file for mTLS."},
	FLAG_KEY:  {FLAG_KEY, "<path> (string)", "a", "Path to a private key file for mTLS."},
	// trust settings
	FLAG_INSECURE: {FLAG_INSECURE, "", "a", "Insecure. Disable certificate verification."},
	FLAG_CA:       {FLAG_CA, "<path> (string)", "a", "Path to a CA certificate or bundle file for mTLS."},
	// auth settings
	FLAG_AUTH:  {FLAG_AUTH, "<type> (string)", "a", "Authentication type. Set to 'jwt' to enable JWT authentication. More types will be supported in future versions."},
	FLAG_JWK:   {FLAG_JWK, "<path> (string)", "l", "Path to a public key file used to verify JWT tokens. This can be a local file or a URL. PEM and JWKS (json) formats are supported."},
	FLAG_TOKEN: {FLAG_TOKEN, "<token> (string)", "c", "Sets the token string for JWT client authentication. It is recommended to populate the " + config.EnvToken.Name() + " environment variable instead of using this flag."},
	// NAT traversal settings
	FLAG_STUN:   {FLAG_STUN, "<host:port> (string)", "a", "STUN server to query during NAT traversal."},
	FLAG_MQTT:   {FLAG_MQTT, "<proto://host:port> (string)", "a", "MQTT broker to use for NAT traversal signaling. See '" + binaryName + " -docs env' for additional configuration options."},
	FLAG_SIGKEY: {FLAG_SIGKEY, "<key> (string)", "a", "Encryption key for signaling messages. Connecting peers need to use the same key as the listeners."},
	// nerd settings
	FLAG_MTU:     {FLAG_MTU, "<mtu> (int)", "a", "MTU (Maximum Transmission Unit) size of the tunnel adapter. Defaults to " + strconv.Itoa(config.DefaultMTU) + "."},
	FLAG_STREAMS: {FLAG_STREAMS, "<streams> (int)", "c", "Open streams. The number of individual streams that the connecting side will open with stream based protocols like quic. Defaults to the number of CPU cores."},
	FLAG_QSIZE:   {FLAG_QSIZE, "<size> (int)", "a", "Size of the packet queues used by tunnels. Defaults to " + strconv.Itoa(config.DefaultQueueSize) + "."},
	// WRED settings
	FLAG_WRED_WF: {FLAG_WRED_WF, "<value> (float)", "a", "Weight factor for WRED, lower values mean more weight to recent packets. Defaults to " + strconv.FormatFloat(config.DefaultWredWF, 'f', -1, 64) + "."},
	FLAG_WRED_DP: {FLAG_WRED_DP, "<value> (float)", "a", "Drop probability for WRED. Accepts decimals between 0 and 1. Defaults to " + strconv.FormatFloat(config.DefaultWredDP, 'f', -1, 64) + "."},
	FLAG_WRED_TH: {FLAG_WRED_TH, "<value> (float)", "a", "Threshold for WRED as a fraction of the queue length. Accepts decimals between 0 and 1. Defaults to " + strconv.FormatFloat(config.DefaultWredThresh, 'f', -1, 64) + "."},
}

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
	idleTimeout    int
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
	netcat         bool
	acceptOnce     bool
	proxy          string
}

func parsePigFlags(mode Mode, flagSet *flag.FlagSet) *Flags {
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
	// check for unexpected extra arguments
	if flagSet.NArg() > 0 {
		printListenConnectUsage(mode)
		os.Exit(1)
	}
	// validate that passed flags are valid for the given mode
	flagSet.Visit(func(f *flag.Flag) {
		err := validatePassedFlag(f, mode)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Illegal flag '-%s' used in '%s' mode.\n\n", f.Name, mode)
			printListenConnectUsage(mode)
			os.Exit(1)
		}
	})
	if isFlagPassed(flagSet, FLAG_HTTP_PROXY) && isFlagPassed(flagSet, FLAG_NETCAT) {
		fmt.Fprintf(os.Stderr, "The '-%s' and '-%s' flags cannot be used together.\n\n", FLAG_HTTP_PROXY, FLAG_NETCAT)
		printListenConnectUsage(mode)
		os.Exit(1)
	}
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

func initPig(mode Mode) (*config.Config, common.Logger) {
	var (
		logger  common.Logger
		cfg     *config.Config
		flags   *Flags
		err     error
		flagSet = flag.NewFlagSet("pig", flag.ExitOnError)
	)
	flags = parsePigFlags(mode, flagSet)
	cfg = &config.Config{}
	applyCommandLineFlags(cfg, flags, mode, log.NewBlockingLogger())
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
	setupAdapterMode(cfg, flags, flagSet, logger)
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
	var (
		configPath string
		toConfig   string
	)
	flag.StringVar(&configPath, FLAG_MAIN_CONFIG, "", "")
	flag.StringVar(&toConfig, FLAG_TO_CFG, "", "")
	flag.Parse()
	// check for unexpected extra arguments
	if flag.NArg() > 0 {
		printConfigUsage()
		os.Exit(1)
	}
	// this will initialize the config with proper defaults
	cfg, err := config.LoadConfigFromFile(configPath)
	if err != nil {
		log.NewBlockingLogger().Fatalf("Failed to load config file: %v", err)
	}
	if toConfig != "" {
		outputConfig(cfg, toConfig)
	}
	return cfg
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

// validatePassedFlag validates that the passed flag is valid for the given mode
func validatePassedFlag(f *flag.Flag, mode Mode) error {
	wantMode := "c"
	if mode == ModeListen {
		wantMode = "l"
	}
	fd, ok := pigFlags[f.Name]
	if !ok {
		// flagSet.Parse() will return an error if the flag is not defined
		return nil
	}
	if fd[2] == wantMode || fd[2] == "a" {
		return nil
	}
	return errors.New("illegal flag")
}

func defineFlags(flagSet *flag.FlagSet) *Flags {
	flags := &Flags{}

	// output settings
	flagSet.StringVar(&flags.toConfig, pigFlags[FLAG_TO_CFG][0], "", "")
	// adapters
	flagSet.BoolVar(&flags.netcat, pigFlags[FLAG_NETCAT][0], false, "")
	flagSet.StringVar(&flags.proxy, pigFlags[FLAG_HTTP_PROXY][0], "", "")
	flagSet.StringVar(&flags.proxy, pigFlags[FLAG_SOCKS_PROXY][0], "", "")
	// general settings
	flagSet.BoolVar(&flags.iceDisabled, pigFlags[FLAG_SIMPLE][0], false, "")
	flagSet.StringVar(&flags.iceSignalingID, pigFlags[FLAG_ID][0], "", "")
	flagSet.StringVar(&flags.address, pigFlags[FLAG_ADDR][0], "", "")
	flagSet.StringVar(&flags.bindAdapter, pigFlags[FLAG_BIND][0], "", "")
	flagSet.StringVar(&flags.proto, pigFlags[FLAG_PROTO][0], string(config.DefaultICEProtocol), "")
	flagSet.IntVar(&flags.srcPort, pigFlags[FLAG_SPORT][0], 0, "")
	flagSet.StringVar(&flags.tunnelAddress, pigFlags[FLAG_TADDR][0], "", "")
	flagSet.IntVar(&flags.retryInterval, pigFlags[FLAG_RETRY][0], config.DefaultRetryInterval, "")
	flagSet.IntVar(&flags.idleTimeout, pigFlags[FLAG_IDLE_TIMEOUT][0], config.DefaultIdleTimeout, "")
	flagSet.StringVar(&flags.route, pigFlags[FLAG_ROUTE][0], "", "")
	flagSet.BoolVar(&flags.acceptOnce, pigFlags[FLAG_ACCEPT_ONCE][0], false, "")
	// scripting settings
	flagSet.StringVar(&flags.scriptPath, pigFlags[FLAG_SCRIPT][0], "", "")
	// logging settings
	flagSet.IntVar(&flags.verbose, pigFlags[FLAG_VERBOSE][0], 1, "")
	// certificate settings
	flagSet.StringVar(&flags.certFile, pigFlags[FLAG_CERT][0], "", "")
	flagSet.StringVar(&flags.keyFile, pigFlags[FLAG_KEY][0], "", "")
	// trust settings
	flagSet.BoolVar(&flags.insecure, pigFlags[FLAG_INSECURE][0], false, "")
	flagSet.StringVar(&flags.mtlsCA, pigFlags[FLAG_CA][0], "", "")
	// auth settings
	flagSet.StringVar(&flags.authType, pigFlags[FLAG_AUTH][0], string(config.AuthTypeNone), "")
	flagSet.StringVar(&flags.jwkSource, pigFlags[FLAG_JWK][0], "", "")
	flagSet.StringVar(&flags.token, pigFlags[FLAG_TOKEN][0], "", "")
	// NAT traversal settings
	flagSet.StringVar(&flags.stunServerAddr, pigFlags[FLAG_STUN][0], config.DefaultICESTUNServer, "")
	flagSet.StringVar(&flags.iceMQTTBroker, pigFlags[FLAG_MQTT][0], config.DefaultICEBrokerAddress, "")
	flagSet.StringVar(&flags.iceKey, pigFlags[FLAG_SIGKEY][0], "", "")
	// nerd settings
	flagSet.IntVar(&flags.mtu, pigFlags[FLAG_MTU][0], config.DefaultMTU, "")
	flagSet.IntVar(&flags.streamCount, pigFlags[FLAG_STREAMS][0], config.DefaultStreamCount, "")
	flagSet.IntVar(&flags.queueSize, pigFlags[FLAG_QSIZE][0], config.DefaultQueueSize, "")
	flagSet.Float64Var(&flags.wredWF, pigFlags[FLAG_WRED_WF][0], config.DefaultWredWF, "")
	flagSet.Float64Var(&flags.wredDP, pigFlags[FLAG_WRED_DP][0], config.DefaultWredDP, "")
	flagSet.Float64Var(&flags.wredThresh, pigFlags[FLAG_WRED_TH][0], config.DefaultWredThresh, "")
	return flags
}

func applyCommandLineFlags(cfg *config.Config, flags *Flags, mode Mode, logger common.Logger) {
	// Ensure a single tunnel entry exists for CLI mode
	cfg.Tunnels = []config.TunnelConfig{{}}
	tc := &cfg.Tunnels[0]
	tc.Direction = directionFromMode(mode)
	// adapterCfg := &cfg.Adapter
	//if tc.Direction == config.TunnelDirectionListen {
	tc.Adapter = &config.AdapterConfig{}
	//adapterCfg := tc.Adapter
	//}

	switch flags.iceDisabled {
	case true:
		if flags.proto == "." {
			logger.Fatalf("A protocol must be specified in simple mode")
		}
		err := configureEndpoint(tc, flags.address, string(tc.Direction), logger)
		if err != nil {
			logger.Fatalf("Failed to configure %s address: %v", tc.Direction, err)
		}
		if tc.Direction == config.TunnelDirectionConnect {
			tc.Connect.SrcPort = flags.srcPort
			break
		}
	case false:
		if tc.Direction == config.TunnelDirectionConnect {
			tc.Connect.SrcPort = flags.srcPort
			break
		}
		//tc.Listen.Port = flags.srcPort
		if flags.address == "" {
			break
		}
		err := configureEndpoint(tc, flags.address, string(tc.Direction), logger)
		if err != nil {
			logger.Fatalf("Failed to configure %s address: %v", tc.Direction, err)
		}
	}

	tc.Proto = config.TransportType(flags.proto)

	setConfigField(&tc.TLSConfig.Insecure, flags.insecure)
	if tc.Direction == config.TunnelDirectionListen {
		setConfigField(&tc.TLSConfig.CertFile, flags.certFile)
		setConfigField(&tc.TLSConfig.KeyFile, flags.keyFile)
	}

	setConfigField(&tc.StreamCount, flags.streamCount)
	setConfigField(&tc.AcceptOnce, flags.acceptOnce)
	setConfigField(&tc.ReconnectInterval, flags.retryInterval)
	setConfigField(&tc.IdleTimeout, flags.idleTimeout)

	setConfigField(&tc.Wred.MaxDropProbability, flags.wredDP)
	setConfigField(&tc.Wred.MaxThreshold, flags.wredThresh)
	setConfigField(&tc.Wred.WeightFactor, flags.wredWF)

	// Adapter settings
	/*if !flags.netcat && flags.tunnelAddress != "" {
		adapterCfg.SetTunAdapter()
		tunCfg := &config.AdapterTunConfig{}
		tunCfg.TunnelAddress = strings.Split(flags.tunnelAddress, ",")
		setConfigField(&tunCfg.MTU, flags.mtu)
		adapterCfg.AdapterConfig = tunCfg
	}*/
	// setConfigField(&adapterCfg.TunnelAddress[0], flags.tunnelAddress)

	setConfigField(&tc.BindAdapter, flags.bindAdapter)
	setConfigField(&tc.QueueSize, flags.queueSize)

	setConfigField(&cfg.ScriptPath, flags.scriptPath)

	switch flags.verbose {
	case 0:
		cfg.LogConfig.Level = "disabled"
	case 1:
		cfg.LogConfig.Level = "info"
	case 2:
		cfg.LogConfig.Level = "debug"
	case 3:
		cfg.LogConfig.Level = "trace"
	default:
		cfg.LogConfig.Level = "info"
	}

	buildTrustSettingsFromFlags(tc, flags, logger)
	buildAuthSettingsFromFlags(tc, flags, logger)
	buildICESettingsFromFlags(tc, flags, logger)
	buildRouteSettingsFromFlags(cfg, tc, flags, logger)
}

func buildTrustSettingsFromFlags(tc *config.TunnelConfig, flags *Flags, logger common.Logger) {
	if tc.Trust != nil {
		return
	}
	tc.Trust = &config.TrustConfig{}
	if flags.mtlsCA != "" && !flags.insecure {
		tc.Trust.MTLS = &config.MTLSConfig{
			TrustPEM: flags.mtlsCA,
		}
	}
	if tc.Direction == config.TunnelDirectionConnect && flags.certFile != "" {
		if tc.Trust.MTLS == nil {
			tc.Trust.MTLS = &config.MTLSConfig{}
		}
		tc.Trust.MTLS.CertFile = flags.certFile
		tc.Trust.MTLS.KeyFile = flags.keyFile
	}
}

func buildAuthSettingsFromFlags(tc *config.TunnelConfig, flags *Flags, logger common.Logger) {
	if tc.Auth != nil || flags.authType == "" {
		return
	}

	tc.Auth = &config.AuthConfig{}

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
		// STUNAddress: flags.stunServerAddr,
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

		if len(cfg.STUNAddress) == 0 {
			cfg.STUNAddress = []string{flags.stunServerAddr}
		}

		if tc.ICE.Signaling == nil {
			tc.ICE.Signaling = &config.ICESignalingOpts{}
		}
		setConfigField(&cfg.MQTTBroker.Address, flags.iceMQTTBroker)
	}
}

func configureEndpoint(tc *config.TunnelConfig, addr string, addrType string, logger common.Logger) error {
	address, strPort, err := net.SplitHostPort(addr)
	if err != nil && strings.Contains(err.Error(), "missing port") {
		address = addr
		err = nil
	}
	if err != nil {
		return fmt.Errorf("failed to parse %s address: %v", addrType, err)
	}
	if strPort == "" {
		strPort = "0"
	}
	port, err := strconv.Atoi(strPort)
	if err != nil {
		return fmt.Errorf("failed to parse %s address port: %v", addrType, err)
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
	if strings.HasPrefix(flags.route, "full") {
		cfg.RouteConfig.Enabled = true
		var err error
		tc.Routes, err = tunnelRoutesFromKeyWord(flags.route)
		if err != nil {
			logger.Fatal(err)
		}
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

func tunnelRoutesFromKeyWord(k string) ([]config.Route, error) {
	fullV4 := []config.Route{
		{
			Destination: "0.0.0.0/1",
			Type:        config.RouteTypeTunnel,
		},
		{
			Destination: "128.0.0.0/1",
			Type:        config.RouteTypeTunnel,
		},
	}
	fullV6 := []config.Route{
		{
			Destination: "2000::/3",
			Type:        config.RouteTypeTunnel,
		},
		{
			Destination: "64:ff9b::/96",
			Type:        config.RouteTypeTunnel,
		},
	}
	switch k {
	case "full4":
		return fullV4, nil
	case "full6":
		return fullV6, nil
	case "full":
		return append(fullV4, fullV6...), nil
	default:
		return nil, fmt.Errorf("invalid route keyword: %s", k)
	}
}

func setupAdapterMode(cfg *config.Config, flags *Flags, flagSet *flag.FlagSet, logger common.Logger) {
	if setupNetcatMode(cfg, flags, flagSet, logger) {
		return
	}
	if setupProxyMode(cfg, flags, flagSet, logger) {
		return
	}
	setupTunMode(cfg, flags, flagSet, logger)
}

func setupNetcatMode(cfg *config.Config, flags *Flags, flagSet *flag.FlagSet, logger common.Logger) (configured bool) {
	if !flags.netcat {
		return
	}
	var tc *config.TunnelConfig

	if len(cfg.Tunnels) == 0 {
		logger.Fatalf("Netcat mode requires a tunnel")
		return
	}

	tc = &cfg.Tunnels[0]

	tc.Adapter.SetStdIOAdapter()
	stdioCfg := &config.AdapterStdIOConfig{}
	setConfigField(&stdioCfg.MTU, flags.mtu)
	tc.Adapter.AdapterConfig = stdioCfg
	tc.ReconnectInterval = -1
	tc.Wred.MaxDropProbability = -1

	cfg.RouteConfig.Enabled = false

	if !isFlagPassed(flagSet, FLAG_VERBOSE) {
		cfg.LogConfig.Level = "disabled"
		logger.SetLevel("disabled")
	}
	return true
}

func setupProxyMode(cfg *config.Config, flags *Flags, flagSet *flag.FlagSet, logger common.Logger) (configured bool) {
	if flags.proxy == "" {
		return
	}

	var tc *config.TunnelConfig

	if len(cfg.Tunnels) == 0 {
		logger.Fatalf("HTTP proxy mode requires a tunnel")
		return
	}

	if isFlagPassed(flagSet, FLAG_ROUTE) {
		logger.Fatalf("HTTP proxy mode does not support the '-%s' flag", FLAG_ROUTE)
		return
	}

	tc = &cfg.Tunnels[0]

	proxyType := "http"
	if isFlagPassed(flagSet, FLAG_SOCKS_PROXY) {
		proxyType = "socks"
	}

	switch proxyType {
	case "http":
		tc.Adapter.SetHTTPProxyAdapter()
		proxyCfg := &config.AdapterHTTPProxyConfig{}
		setConfigField(&proxyCfg.MTU, flags.mtu)
		tc.Adapter.AdapterConfig = proxyCfg
		proxyCfg.ListenAddress = flags.proxy
	case "socks":
		tc.Adapter.SetSocksProxyAdapter()
		proxyCfg := &config.AdapterSocksProxyConfig{}
		setConfigField(&proxyCfg.MTU, flags.mtu)
		tc.Adapter.AdapterConfig = proxyCfg
		proxyCfg.ListenAddress = flags.proxy
	}

	cfg.RouteConfig.Enabled = false
	return true
}

func setupTunMode(cfg *config.Config, flags *Flags, flagSet *flag.FlagSet, logger common.Logger) {
	var tc *config.TunnelConfig

	if len(cfg.Tunnels) == 0 {
		logger.Fatalf("Tun mode requires a tunnel")
		return
	}

	tc = &cfg.Tunnels[0]

	tc.Adapter.SetTunAdapter()
	tunCfg := &config.AdapterTunConfig{}
	setConfigField(&tunCfg.MTU, flags.mtu)
	if flags.tunnelAddress != "" {
		tunCfg.TunnelAddress = strings.Split(flags.tunnelAddress, ",")
	}
	tc.Adapter.AdapterConfig = tunCfg

}
