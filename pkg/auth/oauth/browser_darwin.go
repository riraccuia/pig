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

//go:build darwin

package oauth

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"syscall"
)

func openURL(url string) error {
	var cmd *exec.Cmd
	// TODO: detect the console user (SCDynamicStoreCopyConsoleUser or stat("/dev/console")),
	// fork a child (see runtime.LockOSThread), call setgid/setuid to switch to that UID, then exec
	// /usr/bin/open (or run the helper binary) so the browser launches in the unprivileged user session.
	// Use an absolute path: minimal PATH under `go test`, CI, or sandboxes often breaks bare "open".
	st, err := os.Stat("/dev/console")
	if err != nil {
		return err
	}
	sys := st.Sys().(*syscall.Stat_t)
	u, err := user.LookupId(fmt.Sprint(sys.Uid))
	if err != nil {
		return err
	}
	cmd = exec.Command("sudo", "-u", u.Username, "/usr/bin/open", url)
	//cmd = exec.Command("/usr/bin/open", url)
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() {
		_ = cmd.Wait()
	}()
	return nil
}
