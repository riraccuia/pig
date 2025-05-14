package main

import (
	"flag"
	"strconv"
	"strings"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
)

func parseCmdFlags() *flagSet {
	flags := defineFlags()
	flag.Parse()
	return flags
}

func initPig(flags *flagSet, logger common.Logger) *config.Config {
	cfg := loadConfigFile(flags.configPath, logger)
	applyCommandLineFlags(cfg, flags, logger)
	applyAuthSettings(cfg, flags, logger)
	applyICESettings(cfg, flags, logger)
	validateConfig(cfg, logger)
	applyOptionalSettings(cfg, flags)
	return cfg
}

type flagSet struct {
	configPath          string
	transport           string
	serverAddr          string
	tunnelAddress       string
	remoteAddr          string
	srcPort             int
	certFile            string
	keyFile             string
	insecure            bool
	mtu                 int
	streamCount         int
	reconnectInterval   int
	bindAdapter         string
	wredWeightFactor    float64
	wredDropProbability float64
	wredThreshold       float64
	verbose             int
	startScript         string
	stopScript          string
	authType            string
	token               string
	jwkSource           string
	mtlsCA              string
	queueSize           int
	stunServerAddr      string
	stunQry             string
	iceEnabled          bool
	iceKey              string
	iceMQTTBroker       string
}

func defineFlags() *flagSet {
	flags := &flagSet{}

	flag.StringVar(&flags.configPath, "config", "", "Path to configuration file")
	flag.IntVar(&flags.verbose, "v", 0, "Print more verbose output")
	flag.StringVar(&flags.transport, "proto", "quic", "Transport protocol for the tunnel, valid values are: quic, udp, tls, ws, icmp, tls-in-icmp")
	flag.StringVar(&flags.remoteAddr, "c", "", "Connect address (host:port)")
	flag.IntVar(&flags.srcPort, "p", 0, "Source port to use for the connection")
	flag.StringVar(&flags.serverAddr, "l", "", "Listen address (host:port)")
	flag.StringVar(&flags.tunnelAddress, "tunnel", "", "Tunnel address, defaults to 172.31.254.1/32 for clients and 172.31.255.1/24 for servers")
	flag.StringVar(&flags.certFile, "cert", "", "Path to certificate file")
	flag.StringVar(&flags.keyFile, "key", "", "Path to private key file")
	flag.BoolVar(&flags.insecure, "k", false, "Insecure: disable certificate verification")
	flag.IntVar(&flags.mtu, "mtu", 1400, "MTU size")
	flag.IntVar(&flags.streamCount, "streams", 0, "Number of streams to use, if the transport supports it, defaults to the number of CPUs")
	flag.IntVar(&flags.reconnectInterval, "retry", 5, "Reconnect interval in seconds")
	flag.StringVar(&flags.bindAdapter, "I", "", "The adapter/interface to bind to, useful for icmp based protos")
	flag.Float64Var(&flags.wredWeightFactor, "factor", 5, "Weight factor for WRED, lower values mean more weight to recent packets")
	flag.Float64Var(&flags.wredDropProbability, "drop", 0.25, "Drop probability for WRED, valid values are between 0 and 1")
	flag.Float64Var(&flags.wredThreshold, "thresh", 0.30, "Threshold for WRED as a fraction of the queue length, valid values are between 0 and 1")
	flag.StringVar(&flags.startScript, "start-script", "", "Path to script to execute when a tunnel connection is established")
	flag.StringVar(&flags.stopScript, "stop-script", "", "Path to script to execute when a tunnel connection is disconnected")
	flag.StringVar(&flags.authType, "a", "", "Authentication type, valid values are: jwt. Leave empty for no authentication.")
	flag.StringVar(&flags.token, "tok", "", "Token for client authentication")
	flag.StringVar(&flags.jwkSource, "jwk", "", "Path to public key file used to verify JWT tokens. This can be a local file or a URL. The file can be in PEM format or JWKS format.")
	flag.StringVar(&flags.mtlsCA, "mtls-ca", "", "Path to CA certificate file for MTLS")
	flag.IntVar(&flags.queueSize, "qs", 256, "Size of packet queues")
	flag.StringVar(&flags.stunServerAddr, "stun-srv", "stun.l.google.com:19302", "STUN server to query")
	flag.StringVar(&flags.stunQry, "stun-qry", "", "Source port to query, 'R' for random port")
	flag.Func("ice",
		"Enable ICE based hole punching, set to true (-ice true) or provide the MQTT broker address in the form of mqtt://host:port or ssl://host:port. When 'true' is passed, pig defaults to using ssl://test.mosquitto.org:8883 as the broker",
		func(s string) error {
			if s == "false" {
				return nil
			}
			// If the flag is provided without an argument, it is equivalent to "-ice true"
			if strings.HasPrefix(s, "-") || s == "" {
				s = "true"
			}
			flags.iceEnabled = true
			flags.iceMQTTBroker = "ssl://test.mosquitto.org:8883"
			if s == "true" {
				return nil
			}
			flags.iceMQTTBroker = s
			return nil
		},
	)
	flag.StringVar(&flags.iceKey, "ice-key", "", "Encryption key for ICE signaling over MQTT")
	return flags
}

func loadConfigFile(configPath string, logger common.Logger) *config.Config {
	if configPath == "" {
		return &config.Config{}
	}

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		logger.Fatalf("Failed to load config file: %v", err)
	}
	return cfg
}

func applyCommandLineFlags(cfg *config.Config, flags *flagSet, logger common.Logger) {
	cfg.Mode = "server"
	if flags.remoteAddr != "" {
		cfg.Mode = "client"
	}

	if flags.transport != "" {
		cfg.Proto = config.TransportType(flags.transport)
	}

	if flags.serverAddr != "" {
		parseAddress(cfg, flags.serverAddr, "server", logger)
	}

	if flags.remoteAddr != "" {
		parseAddress(cfg, flags.remoteAddr, "local", logger)
		cfg.Target.SrcPort = flags.srcPort
	}

	cfg.TunnelAddress = flags.tunnelAddress
	if cfg.TunnelAddress == "" {
		cfg.TunnelAddress = "172.31.254.1/32"
		if cfg.Mode == "server" {
			cfg.TunnelAddress = "172.31.255.1/24"
		}
	}

	if flags.certFile != "" {
		cfg.CertFile = flags.certFile
	}

	if flags.keyFile != "" {
		cfg.KeyFile = flags.keyFile
	}

	if flags.bindAdapter != "" {
		cfg.BindAdapter = flags.bindAdapter
	}

	if flags.startScript != "" {
		cfg.StartScript = flags.startScript
	}

	if flags.stopScript != "" {
		cfg.StopScript = flags.stopScript
	}
}

func applyAuthSettings(cfg *config.Config, flags *flagSet, logger common.Logger) {
	cfg.Auth = &config.AuthConfig{}

	if cfg.Mode == "client" && flags.certFile != "" {
		cfg.Auth.MTLS = &config.MTLSConfig{}
	}

	if flags.mtlsCA != "" && !flags.insecure {
		cfg.Auth.MTLS = &config.MTLSConfig{
			TrustPEM: flags.mtlsCA,
		}
	}

	if flags.authType == "" {
		return
	}

	if !config.AuthType(flags.authType).IsValid() {
		logger.Fatalf("Invalid authentication type: %s", flags.authType)
	}

	cfg.Auth.Type = config.AuthType(flags.authType)

	if cfg.Auth.Type == config.AuthTypeJWT {
		cfg.Auth.JWT = &config.JWTAuth{
			Token:           flags.token,
			PublicKeySource: flags.jwkSource,
		}
	}
}

func applyICESettings(cfg *config.Config, flags *flagSet, logger common.Logger) {
	if !flags.iceEnabled {
		return
	}

	cfg.ICE = config.ICEConfig{
		Enabled:     true,
		STUNAddress: flags.stunServerAddr,
	}

	cfg.ICE.Signaling = &config.ICESignalingOpts{
		EncryptionKey:     flags.iceKey,
		MQTTBrokerAddress: flags.iceMQTTBroker,
	}
	logger.Info("Enabling ICE | STUN server: ", cfg.ICE.STUNAddress, " | MQTT broker: ", cfg.ICE.Signaling.MQTTBrokerAddress)
}

func parseAddress(cfg *config.Config, addr string, addrType string, logger common.Logger) {
	if cfg.Proto == config.TransportICMP || cfg.Proto == config.TransportTLSICMP {
		// strip the port if present
		parts := strings.Split(addr, ":")
		if len(parts) > 1 {
			addr = parts[0]
		}
		cfg.Target.Address = addr
		return
	}
	parts := strings.Split(addr, ":")
	if len(parts) != 2 {
		logger.Fatalf("Invalid %s address format. Expected host:port", addrType)
	}
	address := parts[0]
	if address == "" {
		address = "0.0.0.0"
	}
	cfg.Target.Address = address
	port, err := strconv.Atoi(parts[1])
	if err != nil {
		logger.Fatalf("Failed to parse %s address port: %v", addrType, err)
	}
	cfg.Target.Port = port
}

func validateConfig(cfg *config.Config, logger common.Logger) {
	if cfg.Proto == "" {
		logger.Info("Transport not specified, defaulting to quic")
		cfg.Proto = config.TransportQUIC
	}

	if !cfg.Proto.IsValid() {
		logger.Fatalf("Invalid transport: %s", cfg.Proto)
	}

	if cfg.Proto == config.TransportICMP || cfg.Proto == config.TransportTLSICMP {
		if cfg.BindAdapter == "" {
			logger.Fatalf("Bind adapter not specified, but required for %s. Use -I flag to specify the adapter.", cfg.Proto)
		}
		// TODO: implement this properly
		// if !cfg.ICMPMode.IsValid() {
		// logger.Errorf("Invalid ICMP mode '%s', falling back to aggressive", cfg.ICMPMode)
		// cfg.ICMPMode = config.ICMPModeAggressive
		// }
	}

	if cfg.Target.Address == "" {
		if cfg.Mode == "server" && (cfg.Proto == config.TransportICMP || cfg.Proto == config.TransportTLSICMP) {
			return
		}
		logger.Fatalf("Target address not specified")
	}

	if cfg.Target.Port == 0 {
		if cfg.Proto == config.TransportICMP || cfg.Proto == config.TransportTLSICMP {
			return
		}
		logger.Fatalf("Target port not specified")
	}
}

func applyOptionalSettings(cfg *config.Config, flags *flagSet) {
	cfg.Insecure = flags.insecure
	cfg.MTU = flags.mtu
	cfg.StreamCount = flags.streamCount
	cfg.ReconnectInterval = flags.reconnectInterval
	cfg.BindAdapter = flags.bindAdapter
	cfg.Wred.DropProbability = flags.wredDropProbability
	cfg.Wred.Threshold = flags.wredThreshold
	cfg.Wred.WeightFactor = flags.wredWeightFactor
	cfg.QueueSize = flags.queueSize

	switch flags.verbose {
	case 0:
		cfg.LogLevel = "info"
	case 1:
		cfg.LogLevel = "debug"
	case 2:
		cfg.LogLevel = "trace"
	default:
		cfg.LogLevel = "info"
	}
}
