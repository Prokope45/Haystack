package cwe

// Weakness represents an authoritative CWE definition.
type Weakness struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation"`
	References  []string `json:"references"`
}

var catalog = map[string]Weakness{
	"CWE-78": {
		ID:          "CWE-78",
		Name:        "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
		Description: "The software constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command when it is sent to a downstream component.",
		Remediation: "Avoid invoking a shell with untrusted input. Prefer direct process execution with explicit arguments list instead of shell-string interpolation.",
		References: []string{
			"https://cwe.mitre.org/data/definitions/78.html",
			"https://owasp.org/www-community/attacks/Command_Injection",
		},
	},
	"CWE-89": {
		ID:          "CWE-89",
		Name:        "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
		Description: "The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component.",
		Remediation: "Use parameterized queries or prepared statements instead of dynamic SQL string formatting and concatenation.",
		References: []string{
			"https://cwe.mitre.org/data/definitions/89.html",
			"https://owasp.org/www-community/attacks/SQL_Injection",
		},
	},
	"CWE-22": {
		ID:          "CWE-22",
		Name:        "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
		Description: "The software uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize sequences such as '..' that can resolve to a location outside of that directory.",
		Remediation: "Sanitize paths using filepath.Clean or os.path.abspath, and verify the path remains within the intended root directory.",
		References: []string{
			"https://cwe.mitre.org/data/definitions/22.html",
		},
	},
	"CWE-798": {
		ID:          "CWE-798",
		Name:        "Use of Hard-coded Credentials",
		Description: "The software contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external systems, or encryption of internal data.",
		Remediation: "Do not store secrets, passwords, or API keys directly in source code. Retrieve credentials dynamically from environment variables, secret managers, or configuration files.",
		References: []string{
			"https://cwe.mitre.org/data/definitions/798.html",
		},
	},
	"CWE-502": {
		ID:          "CWE-502",
		Name:        "Deserialization of Untrusted Data",
		Description: "The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid.",
		Remediation: "Avoid deserializing untrusted byte streams with unsafe serializers like pickle or gob without authentication and validation.",
		References: []string{
			"https://cwe.mitre.org/data/definitions/502.html",
		},
	},
}

// Lookup returns the Weakness for a given CWE ID, or a fallback if not registered.
func Lookup(cweID string) Weakness {
	if w, ok := catalog[cweID]; ok {
		return w
	}
	return Weakness{
		ID:          cweID,
		Name:        "Security Weakness " + cweID,
		Description: "Weakness identified under " + cweID,
		Remediation: "Review the code pattern and apply defense-in-depth sanitization and input validation.",
		References: []string{
			"https://cwe.mitre.org/data/definitions/" + cweID + ".html",
		},
	}
}
