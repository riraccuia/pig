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

//go:build windows

package oauth

import (
	"os/exec"
)

func openURL(url string) error {
	var cmd *exec.Cmd
	// TODO: Get the active session ID via WTSGetActiveConsoleSessionId().
	// Obtain the user token for that session with WTSQueryUserToken(sessionId) (or via Lsa/SSO helper
	// in some implementations). Duplicate the token (DuplicateTokenEx), optionally create the user
	// environment (CreateEnvironmentBlock), then call CreateProcessAsUser with that token to start the
	// browser (via shellexecute) in the user's session.
	cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() {
		_ = cmd.Wait()
	}()
	return nil
}
