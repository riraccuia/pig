package main

import (
	"flag"
	"strconv"
	"strings"

	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/log"
)

func parseCmdFlags(logger *log.Logger) *config.Config {
	flags := defineFlags()
	flag.Parse()

	cfg := loadConfigFile(flags.configPath, logger)
	applyCommandLineFlags(cfg, flags, logger)
	applyAuthSettings(cfg, flags, logger)
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
	icmpMode            string
	startScript         string
	stopScript          string
	authType            string
	token               string
	jwkSource           string
	mtlsCA              string
}

func defineFlags() *flagSet {
	flags := &flagSet{}

	flag.StringVar(&flags.configPath, "config", "", "Path to configuration file")
	flag.IntVar(&flags.verbose, "v", 0, "Print more verbose output")
	flag.StringVar(&flags.transport, "proto", "quic", "Transport protocol for the tunnel, valid values are: quic, udp, tls, ws, icmp, tls-in-icmp")
	flag.StringVar(&flags.remoteAddr, "c", "", "Connect address (host:port)")
	flag.StringVar(&flags.serverAddr, "l", "", "Listen address (host:port)")
	flag.StringVar(&flags.tunnelAddress, "tunnel", "10.0.0.1/32", "Tunnel address")
	flag.StringVar(&flags.certFile, "cert", "", "Path to certificate file")
	flag.StringVar(&flags.keyFile, "key", "", "Path to private key file")
	flag.BoolVar(&flags.insecure, "k", false, "Insecure: disable certificate verification")
	flag.IntVar(&flags.mtu, "mtu", 1400, "MTU size")
	flag.IntVar(&flags.streamCount, "streams", 5, "Number of streams to use, if the transport supports it")
	flag.IntVar(&flags.reconnectInterval, "retry", 5, "Reconnect interval in seconds")
	flag.StringVar(&flags.bindAdapter, "I", "", "The adapter/interface to bind to")
	flag.Float64Var(&flags.wredWeightFactor, "factor", 5, "Weight factor for WRED, lower values mean more weight to recent packets")
	flag.Float64Var(&flags.wredDropProbability, "drop", 0.25, "Drop probability for WRED, valid values are between 0 and 1")
	flag.Float64Var(&flags.wredThreshold, "thresh", 0.1, "Threshold for WRED as a fraction of the queue length, valid values are between 0 and 1")
	flag.StringVar(&flags.startScript, "start-script", "", "Path to script to execute when a tunnel connection is established")
	flag.StringVar(&flags.stopScript, "stop-script", "", "Path to script to execute when a tunnel connection is disconnected")
	flag.StringVar(&flags.authType, "auth", "", "Authentication type, valid values are: jwt. Leave empty for no authentication.")
	flag.StringVar(&flags.token, "tok", "", "Token for client authentication")
	flag.StringVar(&flags.jwkSource, "jwk", "", "Path to public key file used to verify JWT tokens. This can be a local file or a URL. The file can be in PEM format or JWKS format.")
	flag.StringVar(&flags.mtlsCA, "mtls-ca", "", "Path to CA certificate file for MTLS")
	// TODO: implement this properly
	// flag.StringVar(&flags.icmpMode, "icmp-mode", "aggressive", "ICMP mode, valid values are: normal, aggressive")
	return flags
}

func loadConfigFile(configPath string, logger *log.Logger) *config.Config {
	if configPath == "" {
		return &config.Config{}
	}

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		logger.Fatalf("Failed to load config file: %v", err)
	}
	return cfg
}

func applyCommandLineFlags(cfg *config.Config, flags *flagSet, logger *log.Logger) {
	cfg.Mode = "server"
	if flags.remoteAddr != "" {
		cfg.Mode = "client"
	}

	if flags.transport != "" {
		cfg.Transport = config.TransportType(flags.transport)
	}

	if flags.serverAddr != "" {
		parseAddress(cfg, flags.serverAddr, "server", logger)
	}

	if flags.remoteAddr != "" {
		parseAddress(cfg, flags.remoteAddr, "local", logger)
	}

	if flags.tunnelAddress != "" {
		cfg.TunnelAddress = flags.tunnelAddress
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

	if flags.icmpMode != "" {
		cfg.ICMPMode = config.ICMPMode(flags.icmpMode)
	}

	if flags.startScript != "" {
		cfg.StartScript = flags.startScript
	}

	if flags.stopScript != "" {
		cfg.StopScript = flags.stopScript
	}
}

func applyAuthSettings(cfg *config.Config, flags *flagSet, logger *log.Logger) {
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

func parseAddress(cfg *config.Config, addr string, addrType string, logger *log.Logger) {
	if cfg.Transport == config.TransportICMP || cfg.Transport == config.TransportTLSICMP {
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

func validateConfig(cfg *config.Config, logger *log.Logger) {
	if cfg.Transport == "" {
		logger.Info("Transport not specified, defaulting to quic")
		cfg.Transport = config.TransportQUIC
	}

	if !cfg.Transport.IsValid() {
		logger.Fatalf("Invalid transport: %s", cfg.Transport)
	}

	if cfg.Transport == config.TransportICMP || cfg.Transport == config.TransportTLSICMP {
		if cfg.BindAdapter == "" {
			logger.Fatalf("Bind adapter not specified, but required for %s. Use -I flag to specify the adapter.", cfg.Transport)
		}
		// TODO: implement this properly
		// if !cfg.ICMPMode.IsValid() {
		// logger.Errorf("Invalid ICMP mode '%s', falling back to aggressive", cfg.ICMPMode)
		// cfg.ICMPMode = config.ICMPModeAggressive
		// }
	}

	if cfg.Target.Address == "" {
		if cfg.Mode == "server" && (cfg.Transport == config.TransportICMP || cfg.Transport == config.TransportTLSICMP) {
			return
		}
		logger.Fatalf("Target address not specified")
	}

	if cfg.Target.Port == 0 {
		if cfg.Transport == config.TransportICMP || cfg.Transport == config.TransportTLSICMP {
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
