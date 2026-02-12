package log

import (
	"fmt"
	"regexp"
	"strconv"
)

// RotateSizeFromRotateString converts a rotate size string to an int64
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
