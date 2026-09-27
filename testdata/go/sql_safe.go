package fixtures

import (
	"database/sql"
	"net/http"
)

// Safe: Parameterized SQL query
func SafeSQL(db *sql.DB, r *http.Request) {
	userId := r.URL.Query().Get("id")
	// Parameterized query using placeholder
	_, _ = db.Query("SELECT name, email FROM accounts WHERE id = ?", userId)
}
