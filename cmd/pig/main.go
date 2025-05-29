package main

import (
	"fmt"
	"net/http"
	"os"
	"runtime"

	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/log"
)

func main() {
	handleSubCommands()
}

func handleSubCommands() {
	usage := `Usage: pig [c|l|stun] [options]

	Use -h or --help to get help for a subcommand.

	Client mode - Establish a tunnel to a server:
		pig [-c|c] host:port [options] 

	Server mode - Listen for incoming connections:
		pig [-l|l] addr:port [options]

	Client/Server mode - Load config from file:
		pig -config /path/to/config.toml

	STUN query tool - Query a STUN server:
		pig [-stun|stun] [options]
	`

	if len(os.Args) < 2 {
		fmt.Println(usage)
		os.Exit(1)
		return
	}

	switch os.Args[1] {
	case "-h", "--help":
		fmt.Println(usage)
		os.Exit(0)
	case "-config", "--config":
		if len(os.Args) < 3 {
			fmt.Println(usage)
			os.Exit(1)
		}
		pig("")
	case "c", "-c":
		pig(config.ModeClient)
	case "l", "-l":
		pig(config.ModeServer)
	case "stun", "-stun":
		stunMode()
	default:
		fmt.Println(usage)
		os.Exit(1)
	}
}

func setupPprof(logger *log.Logger) {
	runtime.SetBlockProfileRate(1)
	runtime.SetMutexProfileFraction(1)

	go func() {
		pprofAddr := ":6060"
		logger.Infof("Starting pprof server on %s", pprofAddr)
		if err := http.ListenAndServe(pprofAddr, nil); err != nil {
			logger.Errorf("Failed to start pprof server: %v", err)
		}
	}()
}
