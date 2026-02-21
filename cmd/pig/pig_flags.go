package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/log"
)

var (
	// [flag name, description]
	flagConfig      = [2]string{"config", "Path to configuration file"}
	flagVerbose     = [2]string{"v", "Print more verbose output"}
	flagLogFile     = [2]string{"log-file", "Enables logging to a file. Optionally specify the path to the log file, otherwise './pig.log' is used"}
	flagConnect     = [2]string{"c", "Connect address host[:port]"}
	flagListen      = [2]string{"l", "Listen address host[:port]"}
	flagInterface   = [2]string{"I", "The adapter/interface to bind to, useful for icmp based protos"}
	flagProto       = [2]string{"proto", "Transport protocol for the tunnel, valid values are: quic, udp, tls, ws, icmp, tls-in-icmp, dtls"}
	flagPort        = [2]string{"p", "Source port to use for the connection"}
	flagTunnel      = [2]string{"tunnel", "Tunnel address, defaults to 172.31.254.1/29 for clients and 172.31.255.1/24 for servers"}
	flagCert        = [2]string{"cert", "Path to certificate file"}
	flagKey         = [2]string{"key", "Path to private key file"}
	flagInsecure    = [2]string{"k", "Insecure: disable certificate verification"}
	flagMTU         = [2]string{"mtu", "MTU size"}
	flagStreams     = [2]string{"streams", "Number of streams to use, if the transport supports it, defaults to the number of CPUs"}
	flagRetry       = [2]string{"retry", "Reconnect interval in seconds"}
	flagFactor      = [2]string{"factor", "Weight factor for WRED, lower values mean more weight to recent packets"}
	flagDrop        = [2]string{"drop", "Drop probability for WRED, valid values are between 0 and 1"}
	flagThresh      = [2]string{"thresh", "Threshold for WRED as a fraction of the queue length, valid values are between 0 and 1"}
	flagStartScript = [2]string{"start-script", "Path to script to execute when a tunnel connection is established"}
	flagStopScript  = [2]string{"stop-script", "Path to script to execute when a tunnel connection is disconnected"}
	flagAuth        = [2]string{"a", "Authentication type, valid values are: jwt. Leave empty for no authentication."}
	flagToken       = [2]string{"tok", "Token for client authentication"}
	flagJWK         = [2]string{"jwk", "Path to public key file used to verify JWT tokens. This can be a local file or a URL. The file can be in PEM format or JWKS format."}
	flagMTLSCA      = [2]string{"mtls-ca", "Path to CA certificate file for MTLS"}
	flagQueueSize   = [2]string{"qs", "Size of packet queues"}
	flagSTUN        = [2]string{"stun-srv", "STUN server to query"}
	flagICE         = [2]string{"ice", "Enable ICE based hole punching, set to true (-ice true) or provide the MQTT broker address in the form of mqtt://host:port or ssl://host:port. When 'true' is passed, pig defaults to using ssl://test.mosquitto.org:8883 as the broker"}
	flagICEKey      = [2]string{"ice-key", "Encryption key for ICE signaling over MQTT"}
)

type pigFlags struct {
	configPath     string
	verbose        int
	logFile        string
	remoteAddr     string
	serverAddr     string
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
	startScript    string
	stopScript     string
	authType       string
	token          string
	jwkSource      string
	mtlsCA         string
	queueSize      int
	stunServerAddr string
	iceEnabled     bool
	iceKey         string
	iceMQTTBroker  string
}

func parsePigFlags() *pigFlags {
	flagSet := flag.NewFlagSet("pig", flag.ExitOnError)
	flags := defineFlags(flagSet)
	if !strings.HasPrefix(os.Args[1], "-") {
		os.Args[1] = "-" + os.Args[1]
	}
	if len(os.Args) < 3 || strings.HasPrefix(os.Args[2], "-") {
		flagSet.Usage()
		os.Exit(0)
	}
	flagSet.Parse(os.Args[1:])
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

func initPig(mode config.Mode) (*config.Config, *log.Logger) {
	var (
		logger *log.Logger
		cfg    *config.Config
		flags  *pigFlags
		err    error
	)
	flags = parsePigFlags()
	cfg, err = loadConfigFile(flags.configPath)
	if err != nil {
		log.NewBlockingLogger().Fatalf("Failed to load config file: %v", err)
	}
	if cfg == nil {
		cfg = &config.Config{}
		applyCommandLineFlags(cfg, flags, mode, logger)
	}
	err = cfg.Initialize()
	if err != nil {
		log.NewBlockingLogger().Fatalf("Failed to initialize config: %v", err)
	}
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
	return cfg, logger
}

func loadConfigFile(configPath string) (*config.Config, error) {
	if configPath == "" {
		return nil, nil
	}
	cfg, err := config.LoadConfigFromFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config file: %v", err)
	}
	if cfg.TunnelConfig.ICE == nil {
		cfg.TunnelConfig.ICE = &config.ICEConfig{Enabled: false}
	}
	if cfg.TunnelConfig.Auth == nil {
		cfg.TunnelConfig.Auth = &config.AuthConfig{}
	}
	return cfg, nil
}

func defineFlags(flagSet *flag.FlagSet) *pigFlags {
	flags := &pigFlags{}

	flagSet.StringVar(&flags.configPath, flagConfig[0], "", flagConfig[1])
	flagSet.IntVar(&flags.verbose, flagVerbose[0], 0, flagVerbose[1])
	flagSet.StringVar(&flags.remoteAddr, flagConnect[0], "", flagConnect[1])
	flagSet.StringVar(&flags.serverAddr, flagListen[0], "", flagListen[1])
	flagSet.StringVar(&flags.bindAdapter, flagInterface[0], "", flagInterface[1])
	flagSet.StringVar(&flags.proto, flagProto[0], DefaultICEProtocol, flagProto[1])
	flagSet.IntVar(&flags.srcPort, flagPort[0], 0, flagPort[1])
	flagSet.StringVar(&flags.tunnelAddress, flagTunnel[0], "", flagTunnel[1])
	flagSet.StringVar(&flags.certFile, flagCert[0], "", flagCert[1])
	flagSet.StringVar(&flags.keyFile, flagKey[0], "", flagKey[1])
	flagSet.BoolVar(&flags.insecure, flagInsecure[0], false, flagInsecure[1])
	flagSet.IntVar(&flags.mtu, flagMTU[0], DefaultMTU, flagMTU[1])
	flagSet.IntVar(&flags.streamCount, flagStreams[0], DefaultStreamCount, flagStreams[1])
	flagSet.IntVar(&flags.retryInterval, flagRetry[0], DefaultRetryInterval, flagRetry[1])
	flagSet.Float64Var(&flags.wredWF, flagFactor[0], DefaultWredWF, flagFactor[1])
	flagSet.Float64Var(&flags.wredDP, flagDrop[0], DefaultWredDP, flagDrop[1])
	flagSet.Float64Var(&flags.wredThresh, flagThresh[0], DefaultWredThresh, flagThresh[1])
	flagSet.StringVar(&flags.startScript, flagStartScript[0], "", flagStartScript[1])
	flagSet.StringVar(&flags.stopScript, flagStopScript[0], "", flagStopScript[1])
	flagSet.StringVar(&flags.authType, flagAuth[0], "", flagAuth[1])
	flagSet.StringVar(&flags.token, flagToken[0], "", flagToken[1])
	flagSet.StringVar(&flags.jwkSource, flagJWK[0], "", flagJWK[1])
	flagSet.StringVar(&flags.mtlsCA, flagMTLSCA[0], "", flagMTLSCA[1])
	flagSet.IntVar(&flags.queueSize, flagQueueSize[0], 256, flagQueueSize[1])
	flagSet.StringVar(&flags.stunServerAddr, flagSTUN[0], DefaultICESTUNServer, flagSTUN[1])
	flagSet.StringVar(&flags.iceKey, flagICEKey[0], "", flagICEKey[1])

	flags.iceMQTTBroker = DefaultICEBroker
	flagSet.Func(flagICE[0], flagICE[1],
		func(s string) error {
			if s == "false" {
				return nil
			}
			// If the flag is provided without an argument, it is equivalent to "-ice true"
			if strings.HasPrefix(s, "-") || s == "" {
				s = "true"
			}
			flags.iceEnabled = true
			if s == "true" {
				return nil
			}
			flags.iceMQTTBroker = s
			return nil
		},
	)
	flagSet.Func(flagLogFile[0], flagLogFile[1],
		func(s string) error {
			if strings.HasPrefix(s, "-") || s == "" {
				s = "pig.log"
			}
			flags.logFile = s
			return nil
		},
	)
	return flags
}

func applyCommandLineFlags(cfg *config.Config, flags *pigFlags, mode config.Mode, logger common.Logger) {
	if mode != "" {
		cfg.Mode = mode
	}

	if flags.proto != "" {
		cfg.TunnelConfig.Proto = config.TransportType(flags.proto)
	}

	if flags.serverAddr != "" {
		err := configureTarget(cfg, flags.serverAddr, "listen", logger)
		if err != nil {
			logger.Fatalf("Failed to configure listen address: %v", err)
		}
	}

	if flags.remoteAddr != "" {
		err := configureTarget(cfg, flags.remoteAddr, "target", logger)
		if err != nil && !flags.iceEnabled {
			logger.Fatalf("Failed to configure target address: %v", err)
		}
		setConfigField(&cfg.TunnelConfig.Target.SrcPort, flags.srcPort)
	}

	setConfigField(&cfg.TunnelConfig.TunnelAddress, flags.tunnelAddress)

	setConfigField(&cfg.TunnelConfig.TLSConfig.Insecure, flags.insecure)

	if mode == "server" {
		setConfigField(&cfg.TunnelConfig.TLSConfig.CertFile, flags.certFile)
		setConfigField(&cfg.TunnelConfig.TLSConfig.KeyFile, flags.keyFile)
	}

	setConfigField(&cfg.TunnelConfig.BindAdapter, flags.bindAdapter)
	setConfigField(&cfg.TunnelConfig.MTU, flags.mtu)
	setConfigField(&cfg.TunnelConfig.QueueSize, flags.queueSize)
	setConfigField(&cfg.TunnelConfig.StreamCount, flags.streamCount)
	setConfigField(&cfg.TunnelConfig.ReconnectInterval, flags.retryInterval)

	setConfigField(&cfg.StartScript, flags.startScript)
	setConfigField(&cfg.StopScript, flags.stopScript)

	setConfigField(&cfg.TunnelConfig.Wred.DropProbability, flags.wredDP)
	setConfigField(&cfg.TunnelConfig.Wred.Threshold, flags.wredThresh)
	setConfigField(&cfg.TunnelConfig.Wred.WeightFactor, flags.wredWF)

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

	buildAuthSettingsFromFlags(cfg, flags, logger)
	buildICESettingsFromFlags(cfg, flags, logger)
}

func buildAuthSettingsFromFlags(cfg *config.Config, flags *pigFlags, logger common.Logger) {
	if cfg.TunnelConfig.Auth != nil {
		return
	}

	cfg.TunnelConfig.Auth = &config.AuthConfig{}

	if cfg.Mode == "client" && flags.certFile != "" {
		cfg.TunnelConfig.Auth.MTLS = &config.MTLSConfig{
			CertFile: flags.certFile,
			KeyFile:  flags.keyFile,
		}
	}

	if flags.mtlsCA != "" && !flags.insecure {
		cfg.TunnelConfig.Auth.MTLS = &config.MTLSConfig{
			TrustPEM: flags.mtlsCA,
		}
	}

	if flags.authType == "" {
		return
	}

	if !config.AuthType(flags.authType).IsValid() {
		logger.Fatalf("Invalid authentication type: %s", flags.authType)
	}

	cfg.TunnelConfig.Auth.Type = config.AuthType(flags.authType)

	if cfg.TunnelConfig.Auth.Type == config.AuthTypeJWT {
		cfg.TunnelConfig.Auth.JWT = &config.JWTAuth{
			Token:           flags.token,
			PublicKeySource: flags.jwkSource,
		}
	}
}

func buildICESettingsFromFlags(cfg *config.Config, flags *pigFlags, logger common.Logger) {
	if !flags.iceEnabled {
		cfg.TunnelConfig.ICE = &config.ICEConfig{
			Enabled: false,
		}
		return
	}

	cfg.TunnelConfig.ICE = &config.ICEConfig{
		Enabled:     true,
		STUNAddress: flags.stunServerAddr,
	}

	cfg.TunnelConfig.ICE.Signaling = &config.ICESignalingOpts{
		EncryptionKey:     flags.iceKey,
		MQTTBrokerAddress: flags.iceMQTTBroker,
	}

	cfg.TunnelConfig.ICE.Signaling.ServerID = flags.remoteAddr
	if cfg.Mode == "server" {
		cfg.TunnelConfig.ICE.Signaling.ServerID = flags.serverAddr
	}
}

func applyICESettings(cfg *config.Config, flags *pigFlags, logger common.Logger) {
	if cfg.TunnelConfig.ICE == nil || !cfg.TunnelConfig.ICE.Enabled {
		return
	}
	// apply default values if needed for stun and mqtt
	setConfigField(&cfg.TunnelConfig.ICE.STUNAddress, flags.stunServerAddr)
	if cfg.TunnelConfig.ICE.Signaling == nil {
		cfg.TunnelConfig.ICE.Signaling = &config.ICESignalingOpts{}
	}
	setConfigField(&cfg.TunnelConfig.ICE.Signaling.MQTTBrokerAddress, flags.iceMQTTBroker)
}

func configureTarget(cfg *config.Config, addr string, addrType string, logger common.Logger) error {
	if addr == "." {
		cfg.TunnelConfig.Target.Address = "0.0.0.0"
		cfg.TunnelConfig.Target.Port = 0
		return nil
	}
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
	// if the address is a domain name, resolve it to an IP address
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
	cfg.TunnelConfig.Target.Address = address
	cfg.TunnelConfig.Target.Port = port
	return nil
}
