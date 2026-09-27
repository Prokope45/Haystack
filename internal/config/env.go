package config

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var loadEnvOnce sync.Once

// LoadDotEnv searches for a .env file starting from the current directory
// and traversing up to root, setting any environment variables that are not
// already present in the process environment.
func LoadDotEnv() {
	loadEnvOnce.Do(func() {
		dir, err := os.Getwd()
		if err != nil {
			return
		}

		// Traverse up to 5 levels to locate .env
		for i := 0; i < 5; i++ {
			envPath := filepath.Join(dir, ".env")
			if info, err := os.Stat(envPath); err == nil && !info.IsDir() {
				parseAndSetEnv(envPath)
				return
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	})
}

func parseAndSetEnv(path string) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if scanner.Err() != nil {
			return
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		line = strings.TrimPrefix(line, "export ")
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		// Handle quoted values
		if (strings.HasPrefix(val, "\"") && strings.HasSuffix(val, "\"")) ||
			(strings.HasPrefix(val, "'") && strings.HasSuffix(val, "'")) {
			if len(val) >= 2 {
				val = val[1 : len(val)-1]
			}
		}

		if key != "" && os.Getenv(key) == "" {
			_ = os.Setenv(key, val)
		}
	}
}
