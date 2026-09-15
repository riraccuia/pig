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

//nolint:errcheck
package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/script"
)

func printMainUsage() {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	fmt.Fprintf(w, "Usage: %s [subcommand] [-h|--help] [options]\n", binaryName)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Subcommands:")
	printFlag(w, "-"+FLAG_MAIN_CONNECT, "Connect mode, establish a tunnel with a listening node.")
	printFlag(w, "-"+FLAG_MAIN_LISTEN, "Listen mode, listen for incoming connections.")
	printFlag(w, "-"+FLAG_MAIN_STUN, "STUN (Session Traversal Utilities for NAT) tools.")
	printFlag(w, "-"+FLAG_MAIN_CONFIG, "Load settings from a json or toml file.")
	printFlag(w, "-"+FLAG_MAIN_DOCS, "Pig user documentation.")
	w.Flush()
}

func printListenConnectUsage(mode Mode) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	fmt.Fprintf(w, "Usage: %s %s [options] [-%s]\n", binaryName, os.Args[1], FLAG_TO_CFG)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "OUTPUT")
	fmt.Fprintln(w)
	printFlagMode(w, mode, pigFlags[FLAG_TO_CFG])
	fmt.Fprintln(w)
	fmt.Fprintln(w, "OPTIONS")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "General options:")
	printFlagMode(w, mode, pigFlags[FLAG_SIMPLE])
	printFlagMode(w, mode, pigFlags[FLAG_ID])
	printFlagMode(w, mode, pigFlags[FLAG_ADDR])
	printFlagMode(w, mode, pigFlags[FLAG_BIND])
	printFlagMode(w, mode, pigFlags[FLAG_PROTO])
	printFlagMode(w, mode, pigFlags[FLAG_SPORT])
	printFlagMode(w, mode, pigFlags[FLAG_TADDR])
	printFlagMode(w, mode, pigFlags[FLAG_RETRY])
	printFlagMode(w, mode, pigFlags[FLAG_ROUTE])
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Scripting options:")
	printFlagMode(w, mode, pigFlags[FLAG_SCRIPT])
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Logging options:")
	printFlagMode(w, mode, pigFlags[FLAG_VERBOSE])
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Certificate options:")
	printFlagMode(w, mode, pigFlags[FLAG_CERT])
	printFlagMode(w, mode, pigFlags[FLAG_KEY])
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Trust options:")
	printFlagMode(w, mode, pigFlags[FLAG_INSECURE])
	printFlagMode(w, mode, pigFlags[FLAG_CA])
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Auth options:")
	printFlagMode(w, mode, pigFlags[FLAG_AUTH])
	printFlagMode(w, mode, pigFlags[FLAG_JWK])
	printFlagMode(w, mode, pigFlags[FLAG_TOKEN])
	fmt.Fprintln(w)
	fmt.Fprintln(w, "NAT traversal options:")
	printFlagMode(w, mode, pigFlags[FLAG_STUN])
	printFlagMode(w, mode, pigFlags[FLAG_MQTT])
	printFlagMode(w, mode, pigFlags[FLAG_SIGKEY])
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Nerd options:")
	printFlagMode(w, mode, pigFlags[FLAG_MTU])
	printFlagMode(w, mode, pigFlags[FLAG_STREAMS])
	printFlagMode(w, mode, pigFlags[FLAG_QSIZE])
	fmt.Fprintln(w)
	fmt.Fprintln(w, "WRED options:")
	printFlagMode(w, mode, pigFlags[FLAG_WRED_WF])
	printFlagMode(w, mode, pigFlags[FLAG_WRED_DP])
	printFlagMode(w, mode, pigFlags[FLAG_WRED_TH])
	w.Flush()
}

func printStunUsage() {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	fmt.Fprintf(w, "Usage: %s -%s [options]\n", binaryName, FLAG_MAIN_STUN)
	fmt.Fprintln(w)
	printFlag(w, "-"+stunModeFlags["c"][0], stunModeFlags["c"][1])
	printFlag(w, "-"+stunModeFlags["l"][0], stunModeFlags["l"][1])
	printFlag(w, "-"+stunModeFlags["proto"][0], stunModeFlags["proto"][1])
	printFlag(w, "-"+stunModeFlags["p"][0], stunModeFlags["p"][1])
	printFlag(w, "-"+stunModeFlags["v"][0], stunModeFlags["v"][1])
	w.Flush()
}

func printConfigUsage() {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	fmt.Fprintf(w, "Usage: %s -%s\n", binaryName, FLAG_MAIN_CONFIG)
	fmt.Fprintln(w)
	printFlag(w, "-"+FLAG_MAIN_CONFIG, "json or toml config file path.")
	w.Flush()
}

func printDocsUsage() {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	fmt.Fprintf(w, "Usage: %s -%s [section] [-%s]\n", binaryName, FLAG_MAIN_DOCS, FLAG_OUT_MARKDOWN)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Options:")
	printFlag(w, "-"+FLAG_OUT_MARKDOWN, "Output in markdown format.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Sections:")
	printFlag(w, FLAG_DOCS_CONFIG, "Configuration documentation")
	printFlag(w, FLAG_DOCS_ENV, "Environment variables documentation")
	printFlag(w, FLAG_DOCS_PROTOS, "List the supported transport protocols")
	w.Flush()
}

func printConfigDocHelp(formatMd bool) {
	if formatMd {
		fmt.Fprintln(os.Stdout, common.GenerateMarkdownTable(common.MapStructTypes(config.Config{})))
		return
	}
	fmt.Fprintln(os.Stdout, common.GenerateCLIDoc(common.MapStructTypes(config.Config{})))
}

func printEnvHelp() {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	printEnvBootstrapHelp(w)
	fmt.Fprintln(w)
	printEnvScriptingHelp(w)
	w.Flush()
}

func printEnvBootstrapHelp(w *tabwriter.Writer) {
	fmt.Fprintln(w, "BOOTSTRAP ENVIRONMENT VARIABLES")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "The following variables are used for bootstrapping.")
	fmt.Fprintln(w, "Configure these in your shell or in a .env file to be sourced.")
	fmt.Fprintln(w)
	rows := [][2]string{}
	for _, e := range config.EnvVars {
		rows = append(rows, [2]string{e.Name(), e.Description})
	}
	printCliHelpTable(w, rows)
}

func printEnvScriptingHelp(w *tabwriter.Writer) {
	fmt.Fprintln(w, "SCRIPTING ENVIRONMENT VARIABLES")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "The following variables are read-only and available from called script files.")
	fmt.Fprintln(w)
	rows := [][2]string{}
	for _, e := range script.EnvVars {
		rows = append(rows, [2]string{e.Name(), e.Description})
	}
	printCliHelpTable(w, rows)
}

func printTransportProtocols() {
	fmt.Fprintln(os.Stdout, "Supported transport protocols:")
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, "These protocols serve as the transport layer for tunnels.")
	fmt.Fprintln(os.Stdout, "Use the below strings in the cli ('-"+FLAG_PROTO+"' option) or in config files ('proto' field).")
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, "Example:\n\t"+binaryName+" -"+FLAG_MAIN_CONNECT+" -"+FLAG_PROTO+" "+string(config.TransportWS)+" [...]")
	fmt.Fprintln(os.Stdout)
	rows := [][2]string{}
	for proto, supported := range config.SupportedTransports {
		if !supported {
			continue
		}
		rows = append(rows, [2]string{string(proto), proto.Description()})
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	printCliHelpTable(w, rows)
}

func printCliHelpTable(w *tabwriter.Writer, rows [][2]string) {
	nameW, descW := 0, 0
	for _, r := range rows {
		nameW = max(nameW, len(r[0]))
		descW = max(descW, len(r[1]))
	}
	fmt.Fprintf(w, "+%s\t+%s\t+\n", strings.Repeat("-", nameW+2), strings.Repeat("-", descW+2))
	fmt.Fprintln(w, "| Name\t| Description\t|")
	fmt.Fprintf(w, "+%s\t+%s\t+\n", strings.Repeat("-", nameW+2), strings.Repeat("-", descW+2))
	for _, r := range rows {
		fmt.Fprintf(w, "| %s\t| %s\t|\n", r[0], r[1])
	}
	fmt.Fprintf(w, "+%s\t+%s\t+\n", strings.Repeat("-", nameW+2), strings.Repeat("-", descW+2))
	w.Flush()
}

func printFlagMode(w io.Writer, mode Mode, f [3]string) {
	if mode == ModeConnect && f[1] == FLAG_MAIN_LISTEN {
		return
	}
	if mode == ModeListen && f[1] == FLAG_MAIN_CONNECT {
		return
	}
	printFlag(w, "-"+f[0], f[2])
}

func printFlag(w io.Writer, flagName, flagDescription string) {
	lines := strings.Split(common.WrapText(flagDescription, "", false, common.TerminalWidth(11)), "\n")
	fmt.Fprintf(w, " %s\t%s\n", flagName, lines[0])
	for _, line := range lines[1:] {
		fmt.Fprintf(w, "\t%s\n", line)
	}
}
