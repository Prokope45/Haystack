package fixtures

import (
	"database/sql"
	"fmt"
	"net/http"
)

// Vulnerable: SQL Injection via fmt.Sprintf query concatenation
func VulnerableSQL(db *sql.DB, r *http.Request) {
	userId := r.URL.Query().Get("id")
	query := fmt.Sprintf("SELECT name, email FROM accounts WHERE id = '%s'", userId)
	_, _ = db.Query(query)
}
