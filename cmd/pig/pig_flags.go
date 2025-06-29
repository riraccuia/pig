package main

import (
	"flag"
	"fmt"
	"os"
	"reflect"
	"regexp"
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
	flagConnect     = [2]string{"c", "Connect address (host:port)"}
	flagListen      = [2]string{"l", "Listen address (host:port)"}
	flagInterface   = [2]string{"I", "The adapter/interface to bind to, useful for icmp based protos"}
	flagProto       = [2]string{"proto", "Transport protocol for the tunnel, valid values are: quic, udp, tls, ws, icmp, tls-in-icmp"}
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
	err = applyLogSettings(cfg, flags)
	if err != nil {
		log.NewBlockingLogger().Fatalf("Failed to apply log settings: %v", err)
	}
	switch cfg.LogConfig.File {
	case "":
		logger = log.NewLogger()
		logger.SetLevel(cfg.LogConfig.Level)
	default:
		logger, err = log.NewFileLogger(cfg.LogConfig.File, cfg.LogConfig.RotateSize.(int64))
		if err != nil {
			logger.Fatalf("Failed to create file logger: %v", err)
		}
		logger.SetLevel(cfg.LogConfig.Level)
	}
	applyCommandLineFlags(cfg, flags, mode, logger)
	applyAuthSettings(cfg, flags, logger)
	applyICESettings(cfg, flags, logger)
	validateConfig(cfg, logger)
	return cfg, logger
}

func loadConfigFile(configPath string) (*config.Config, error) {
	if configPath == "" {
		return &config.Config{}, nil
	}
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config file: %v", err)
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
	flagSet.StringVar(&flags.proto, flagProto[0], "ws", flagProto[1])
	flagSet.IntVar(&flags.srcPort, flagPort[0], 0, flagPort[1])
	flagSet.StringVar(&flags.tunnelAddress, flagTunnel[0], "", flagTunnel[1])
	flagSet.StringVar(&flags.certFile, flagCert[0], "", flagCert[1])
	flagSet.StringVar(&flags.keyFile, flagKey[0], "", flagKey[1])
	flagSet.BoolVar(&flags.insecure, flagInsecure[0], false, flagInsecure[1])
	flagSet.IntVar(&flags.mtu, flagMTU[0], 1400, flagMTU[1])
	flagSet.IntVar(&flags.streamCount, flagStreams[0], 0, flagStreams[1])
	flagSet.IntVar(&flags.retryInterval, flagRetry[0], 5, flagRetry[1])
	flagSet.Float64Var(&flags.wredWF, flagFactor[0], 5, flagFactor[1])
	flagSet.Float64Var(&flags.wredDP, flagDrop[0], 0.25, flagDrop[1])
	flagSet.Float64Var(&flags.wredThresh, flagThresh[0], 0.30, flagThresh[1])
	flagSet.StringVar(&flags.startScript, flagStartScript[0], "", flagStartScript[1])
	flagSet.StringVar(&flags.stopScript, flagStopScript[0], "", flagStopScript[1])
	flagSet.StringVar(&flags.authType, flagAuth[0], "", flagAuth[1])
	flagSet.StringVar(&flags.token, flagToken[0], "", flagToken[1])
	flagSet.StringVar(&flags.jwkSource, flagJWK[0], "", flagJWK[1])
	flagSet.StringVar(&flags.mtlsCA, flagMTLSCA[0], "", flagMTLSCA[1])
	flagSet.IntVar(&flags.queueSize, flagQueueSize[0], 256, flagQueueSize[1])
	flagSet.StringVar(&flags.stunServerAddr, flagSTUN[0], "stun.nextcloud.com:443", flagSTUN[1])
	flagSet.StringVar(&flags.iceKey, flagICEKey[0], "", flagICEKey[1])

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
			flags.iceMQTTBroker = "ssl://test.mosquitto.org:8883"
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

	if cfg.Proto == "" {
		cfg.Proto = config.TransportType(flags.proto)
	}

	if flags.serverAddr != "" {
		configureTarget(cfg, flags.serverAddr, "listen", logger)
	}

	if flags.remoteAddr != "" {
		configureTarget(cfg, flags.remoteAddr, "target", logger)
		setConfigField(&cfg.Target.SrcPort, flags.srcPort)
	}

	setConfigField(&cfg.TunnelAddress, flags.tunnelAddress)

	if cfg.TunnelAddress == "" {
		cfg.TunnelAddress = "172.31.254.1/29"
		if cfg.Mode == "server" {
			cfg.TunnelAddress = "172.31.255.1/24"
		}
	}

	setConfigField(&cfg.Insecure, flags.insecure)
	setConfigField(&cfg.CertFile, flags.certFile)
	setConfigField(&cfg.KeyFile, flags.keyFile)

	setConfigField(&cfg.BindAdapter, flags.bindAdapter)
	setConfigField(&cfg.MTU, flags.mtu)
	setConfigField(&cfg.QueueSize, flags.queueSize)
	setConfigField(&cfg.StreamCount, flags.streamCount)
	setConfigField(&cfg.ReconnectInterval, flags.retryInterval)

	setConfigField(&cfg.StartScript, flags.startScript)
	setConfigField(&cfg.StopScript, flags.stopScript)

	setConfigField(&cfg.Wred.DropProbability, flags.wredDP)
	setConfigField(&cfg.Wred.Threshold, flags.wredThresh)
	setConfigField(&cfg.Wred.WeightFactor, flags.wredWF)

}

func applyLogSettings(cfg *config.Config, flags *pigFlags) (err error) {
	if cfg.LogConfig.Level == "" {
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
	}

	if cfg.LogConfig.File == "" {
		return nil
	}

	rotateSizeStr, ok := cfg.LogConfig.RotateSize.(string)
	if !ok {
		rotateSizeInt, ok := cfg.LogConfig.RotateSize.(int64)
		if !ok {
			err = fmt.Errorf("invalid rotate size: %v", cfg.LogConfig.RotateSize)
			return
		}
		cfg.LogConfig.RotateSize = rotateSizeInt
		return
	}

	if rotateSizeStr == "" {
		cfg.LogConfig.RotateSize = 5 * 1024 * 1024
		return
	}

	re := regexp.MustCompile(`^(\d+)([kmg])$`)
	sub := re.FindStringSubmatch(rotateSizeStr)
	if len(sub) != 3 {
		err = fmt.Errorf("invalid rotate size: %s", rotateSizeStr)
		return
	}

	rotateSize, err := strconv.Atoi(sub[1])
	if err != nil {
		err = fmt.Errorf("invalid rotate size: %s", rotateSizeStr)
		return
	}

	switch sub[2] {
	case "k":
		cfg.LogConfig.RotateSize = int64(rotateSize * 1024)
	case "m":
		cfg.LogConfig.RotateSize = int64(rotateSize * 1024 * 1024)
	case "g":
		cfg.LogConfig.RotateSize = int64(rotateSize * 1024 * 1024 * 1024)
	default:
		err = fmt.Errorf("invalid rotate size: %s", cfg.LogConfig.RotateSize)
	}
	return
}

func applyAuthSettings(cfg *config.Config, flags *pigFlags, logger common.Logger) {
	if cfg.Auth != nil {
		// auth is already set in the config file, do not override it
		return
	}

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

func applyICESettings(cfg *config.Config, flags *pigFlags, logger common.Logger) {
	if cfg.ICE != nil && cfg.ICE.Enabled {
		// ICE is already set in the config file, make sure we have the right settings
		setConfigField(&cfg.ICE.STUNAddress, flags.stunServerAddr)
		if cfg.ICE.Signaling == nil {
			cfg.ICE.Signaling = &config.ICESignalingOpts{}
			setConfigField(&cfg.ICE.Signaling.EncryptionKey, flags.iceKey)
		}
		setConfigField(&cfg.ICE.Signaling.MQTTBrokerAddress, flags.iceMQTTBroker)
		return
	}

	if !flags.iceEnabled {
		cfg.ICE = &config.ICEConfig{
			Enabled: false,
		}
		return
	}

	cfg.ICE = &config.ICEConfig{
		Enabled:     true,
		STUNAddress: flags.stunServerAddr,
	}

	cfg.ICE.Signaling = &config.ICESignalingOpts{
		EncryptionKey:     flags.iceKey,
		MQTTBrokerAddress: flags.iceMQTTBroker,
	}
}

func configureTarget(cfg *config.Config, addr string, addrType string, logger common.Logger) {
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
	if !cfg.Mode.IsValid() {
		logger.Fatalf("Invalid pig mode: %s", cfg.Mode)
	}

	if !cfg.Proto.IsValid() {
		logger.Fatalf("Invalid transport: %s", cfg.Proto)
	}

	if cfg.Target.Address == "" {
		if cfg.Mode == "server" && (cfg.Proto == config.TransportICMP || cfg.Proto == config.TransportTLSICMP) {
			return
		}
		logger.Fatalf("Target address not specified")
	}

	if cfg.ICE.Enabled {
		if len(cfg.ICE.Protos) == 0 {
			cfg.ICE.Protos = []string{string(cfg.Proto)}
		}
		for _, proto := range cfg.ICE.Protos {
			if !config.TransportType(proto).IsValid() {
				logger.Fatalf("Invalid ICE protocol: %s", proto)
			}
		}
		return
	}

	if cfg.Proto == config.TransportICMP || cfg.Proto == config.TransportTLSICMP {
		if cfg.BindAdapter == "" {
			logger.Fatalf("Bind adapter not specified, but required for %s. Use -I flag to specify the adapter.", cfg.Proto)
		}
	}

	if cfg.Target.Port == 0 {
		if cfg.Proto == config.TransportICMP || cfg.Proto == config.TransportTLSICMP {
			return
		}
		logger.Fatalf("Target port not specified")
	}
}
