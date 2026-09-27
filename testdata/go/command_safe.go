package fixtures

import (
	"os/exec"
)

// Safe: Fixed arguments, no untrusted input flow
func SafeCommand() {
	cmd := exec.Command("git", "status")
	_ = cmd.Run()
}
