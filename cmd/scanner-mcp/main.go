package main

import (
	"fmt"
	"os"

	"haystack/internal/config"
	"haystack/internal/mcp"
)

func main() {
	if err := mcp.RunCLI("scanner-mcp", os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "MCP error: %v\n", err)
		os.Exit(config.ExitInternalError)
	}
	os.Exit(config.ExitSuccess)
}
