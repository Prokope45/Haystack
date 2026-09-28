package analyzer

// SourceType represents the category of untrusted input.
type SourceType string

const (
	SourceHTTPInput   SourceType = "http_input"
	SourceCLIInput    SourceType = "cli_input"
	SourceEnvironment SourceType = "environment"
	SourceFileInput   SourceType = "file_input"
	SourceFuncParam   SourceType = "function_parameter"
	SourceHardcoded   SourceType = "hardcoded_secret"
)

// SinkType represents the category of security-sensitive operations.
type SinkType string

const (
	SinkShell           SinkType = "shell_execution"
	SinkSQL             SinkType = "sql_execution"
	SinkFilesystem      SinkType = "filesystem_access"
	SinkDeserialization SinkType = "deserialization"
)
