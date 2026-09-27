package fixtures

import (
	"os"
)

// Safe: Fixed file path
func SafePath() {
	_, _ = os.Open("/etc/hosts")
}
