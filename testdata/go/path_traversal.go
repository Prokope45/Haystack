package fixtures

import (
	"net/http"
	"os"
)

// Vulnerable: Path traversal with untrusted file name
func VulnerablePath(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	target := "/var/data/" + filename
	_, _ = os.Open(target)
}
