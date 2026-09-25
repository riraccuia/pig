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
	"flag"
	"net/http"
	"os"
	"path/filepath"
	"runtime"

	//_ "net/http/pprof"

	"github.com/riraccuia/pig/pkg/log"
)

var binaryName = filepath.Base(os.Args[0])

func main() {
	handleSubCommands()
}

func handleSubCommands() {
	if len(os.Args) < 2 {
		printMainUsage()
		os.Exit(1)
		return
	}

	switch os.Args[1] {
	case "-h", "--help":
		printMainUsage()
		os.Exit(0)
	case "-" + FLAG_MAIN_CONFIG:
		pigFromConfigFileFlag()
	case "-" + FLAG_MAIN_CONNECT:
		pigFromCliFlags(ModeConnect)
	case "-" + FLAG_MAIN_LISTEN:
		pigFromCliFlags(ModeListen)
	case "-" + FLAG_MAIN_STUN:
		stunMode()
	case "-" + FLAG_MAIN_DOCS:
		pigDocs()
	default:
		printMainUsage()
		os.Exit(1)
	}
}

func pigDocs() {
	var (
		section  string
		formatMd bool
	)
	flag.StringVar(&section, FLAG_MAIN_DOCS, "", "Section of the documentation to print.")
	flag.BoolVar(&formatMd, FLAG_OUT_MARKDOWN, false, "Print in markdown format.")
	flag.Usage = printDocsUsage
	flag.Parse()

	switch section {
	case "config":
		printConfigDocHelp(formatMd)
	case "env":
		printEnvHelp()
	case "protos":
		printTransportProtocols()
	default:
		printDocsUsage()
		os.Exit(1)
	}
	os.Exit(0)
}

// enablePprof enables profiling of the application.
// In order to use, uncomment the "_ net/http/pprof" package import at the top of this file.
func enablePprof() {
	runtime.SetBlockProfileRate(1)
	runtime.SetMutexProfileFraction(1)

	go func() {
		pprofAddr := ":6060"
		log.NewBlockingLogger().Infof("Starting pprof server on %s", pprofAddr)
		if err := http.ListenAndServe(pprofAddr, nil); err != nil {
			log.NewBlockingLogger().Errorf("Failed to start pprof server: %v", err)
		}
	}()
}
