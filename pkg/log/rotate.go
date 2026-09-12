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

package log

import (
	"fmt"
	"regexp"
	"strconv"
)

// RotateSizeFromRotateString converts a rotate size string to an int64.
// e.g. "100k" -> 100 * 1024, "1m" -> 1 * 1024 * 1024, "1g" -> 1 * 1024 * 1024 * 1024
func RotateSizeFromRotateString(rotateSize any) (int64, error) {
	rotateSizeInt64, ok := rotateSize.(int64)
	if ok {
		return rotateSizeInt64, nil
	}
	rotateSizeStr, ok := rotateSize.(string)
	if !ok {
		return 0, fmt.Errorf("invalid rotate size: want string or int64, got %T", rotateSize)
	}
	if rotateSizeStr == "" {
		return 5 * 1024 * 1024, nil
	}

	re := regexp.MustCompile(`^(\d+)([kmg])$`)
	sub := re.FindStringSubmatch(rotateSizeStr)
	if len(sub) != 3 {
		return 0, fmt.Errorf("invalid rotate size: %s", rotateSizeStr)
	}

	rotateSizeInt64, err := strconv.ParseInt(sub[1], 10, 64)
	if err != nil || rotateSizeInt64 < 0 {
		return 0, fmt.Errorf("invalid rotate size: %s", rotateSizeStr)
	}

	switch sub[2] {
	case "k":
		return rotateSizeInt64 * 1024, nil
	case "m":
		return rotateSizeInt64 * 1024 * 1024, nil
	case "g":
		return rotateSizeInt64 * 1024 * 1024 * 1024, nil
	default:
		return 0, fmt.Errorf("invalid rotate size: %s", rotateSizeStr)
	}
}
