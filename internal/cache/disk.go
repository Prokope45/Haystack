package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const entrySchemaVersion = 1

type diskEntry struct {
	SchemaVersion int             `json:"schema_version"`
	Metadata      Metadata        `json:"metadata"`
	Payload       json.RawMessage `json:"payload"`
}

// Disk stores entries as JSON files under an OS-specific cache directory.
type Disk struct {
	root string
}

// DefaultDir returns an OS-appropriate default cache directory. SCANNER_CACHE_DIR
// takes precedence when set.
func DefaultDir() (string, error) {
	if override := strings.TrimSpace(os.Getenv("SCANNER_CACHE_DIR")); override != "" {
		return filepath.Abs(override)
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("determine user cache directory: %w", err)
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(base, "haystack", "Cache"), nil
	}
	return filepath.Join(base, "haystack"), nil
}

// NewDisk creates the cache root if needed.
func NewDisk(root string) (*Disk, error) {
	if strings.TrimSpace(root) == "" {
		var err error
		root, err = DefaultDir()
		if err != nil {
			return nil, err
		}
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve cache directory: %w", err)
	}
	if err := os.MkdirAll(absRoot, 0o700); err != nil {
		return nil, fmt.Errorf("create cache directory: %w", err)
	}
	return &Disk{root: absRoot}, nil
}

func (d *Disk) Get(ctx context.Context, key Key) ([]byte, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	path, err := d.path(key)
	if err != nil {
		return nil, false, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read cache entry: %w", err)
	}

	var entry diskEntry
	if err := json.Unmarshal(data, &entry); err != nil || entry.SchemaVersion != entrySchemaVersion ||
		entry.Metadata.Key != string(key) || entry.Metadata.Namespace != strings.SplitN(string(key), ":", 2)[0] ||
		len(entry.Payload) == 0 || !json.Valid(entry.Payload) {
		// Persisted cache data is untrusted. Malformed and incompatible entries are
		// misses; they must never prevent a fresh security scan.
		return nil, false, nil
	}
	return append([]byte(nil), entry.Payload...), true, nil
}

func (d *Disk) Put(ctx context.Context, key Key, value []byte, metadata Metadata) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path, err := d.path(key)
	if err != nil {
		return err
	}
	keyNamespace := strings.SplitN(string(key), ":", 2)[0]
	if metadata.Namespace != "" && metadata.Namespace != keyNamespace {
		return fmt.Errorf("cache metadata namespace %q does not match key namespace %q", metadata.Namespace, keyNamespace)
	}
	if !json.Valid(value) {
		return fmt.Errorf("cache payload must be valid JSON")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create cache entry directory: %w", err)
	}
	metadata.Key = string(key)
	metadata.Namespace = keyNamespace
	if metadata.CreatedAt.IsZero() {
		metadata.CreatedAt = time.Now().UTC()
	}
	data, err := json.Marshal(diskEntry{SchemaVersion: entrySchemaVersion, Metadata: metadata, Payload: append(json.RawMessage(nil), value...)})
	if err != nil {
		return fmt.Errorf("encode cache entry: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".entry-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary cache entry: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("set cache entry permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write cache entry: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync cache entry: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close cache entry: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("publish cache entry: %w", err)
	}
	return nil
}

func (d *Disk) Delete(ctx context.Context, key Key) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path, err := d.path(key)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("delete cache entry: %w", err)
	}
	return nil
}

func (d *Disk) Clear(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	entries, err := os.ReadDir(d.root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read cache directory: %w", err)
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := os.RemoveAll(filepath.Join(d.root, entry.Name())); err != nil {
			return fmt.Errorf("clear cache entry %q: %w", entry.Name(), err)
		}
	}
	return nil
}

func (d *Disk) path(key Key) (string, error) {
	parts := strings.Split(string(key), ":")
	if len(parts) != 2 || !validNamespace(parts[0]) || !validKey(Key(parts[1])) {
		return "", fmt.Errorf("invalid cache key")
	}
	return filepath.Join(d.root, parts[0], parts[1][:2], parts[1]+".json"), nil
}

// NamespacedKey combines a namespace and digest into the filesystem-safe form
// accepted by Disk.
func NamespacedKey(namespace string, digest Key) (Key, error) {
	if !validNamespace(namespace) || !validKey(digest) {
		return "", fmt.Errorf("invalid cache namespace or digest")
	}
	return Key(namespace + ":" + string(digest)), nil
}
