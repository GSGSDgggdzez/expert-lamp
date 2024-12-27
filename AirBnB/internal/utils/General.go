package utils

import (
	"fmt"
	"time"
)

func GenerateUniqueFilename(original string) string {
	timestamp := time.Now().UnixNano()
	return fmt.Sprintf("%d_%s", timestamp, original)
}
