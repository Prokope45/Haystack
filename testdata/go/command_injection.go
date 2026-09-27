package fixtures

import (
	"net/http"
	"os/exec"
)

// Vulnerable: Command Injection via HTTP parameter
func VulnerableCommand(w http.ResponseWriter, r *http.Request) {
	cmdParam := r.URL.Query().Get("action")
	fullCmd := "run_task " + cmdParam
	exec.Command("sh", "-c", fullCmd)
}
