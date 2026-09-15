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

package common

import (
	"os"
	"strconv"
	"strings"

	"golang.org/x/term"
)

func WrapText(s, prefix string, startWithPrefix bool, width int) string {
	budget := width - len(prefix)
	if budget < 20 {
		budget = 20
	}
	words := strings.Fields(s)
	if len(words) == 0 {
		return strings.TrimRight(prefix, " ")
	}
	var b strings.Builder
	if startWithPrefix {
		b.WriteString(prefix)
	}
	line := 0
	for i, w := range words {
		need := len(w)
		if i > 0 {
			need++
		}
		if i > 0 && line+need > budget {
			b.WriteByte('\n')
			b.WriteString(prefix)
			b.WriteString(w)
			line = len(w)
			continue
		}
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(w)
		line += need
	}
	return b.String()
}

func TerminalWidth(pad int) int {
	if c := os.Getenv("COLUMNS"); c != "" {
		if n, err := strconv.Atoi(c); err == nil {
			return n - pad
		}
	}
	w, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		w = 80
	}
	return w - pad
}
