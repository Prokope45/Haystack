package cache

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func testKey(t *testing.T, input any) Key {
	t.Helper()
	digest, err := KeyFor("scan", input)
	if err != nil {
		t.Fatal(err)
	}
	key, err := NamespacedKey("scan", digest)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestDiskMissPutGetDeleteAndClear(t *testing.T) {
	ctx := context.Background()
	disk, err := NewDisk(filepath.Join(t.TempDir(), "cache"))
	if err != nil {
		t.Fatal(err)
	}
	key := testKey(t, map[string]string{"source": "abc"})

	if _, hit, err := disk.Get(ctx, key); err != nil || hit {
		t.Fatalf("initial lookup = hit %v, err %v; want miss", hit, err)
	}
	if err := disk.Put(ctx, key, []byte(`{"finding":"RULE-1"}`), Metadata{Namespace: "scan"}); err != nil {
		t.Fatal(err)
	}
	got, hit, err := disk.Get(ctx, key)
	if err != nil || !hit || string(got) != `{"finding":"RULE-1"}` {
		t.Fatalf("Get() = %s, hit %v, err %v", got, hit, err)
	}
	if err := disk.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, hit, err := disk.Get(ctx, key); err != nil || hit {
		t.Fatalf("lookup after Delete = hit %v, err %v; want miss", hit, err)
	}
	if err := disk.Put(ctx, key, []byte(`{}`), Metadata{}); err != nil {
		t.Fatal(err)
	}
	if err := disk.Clear(ctx); err != nil {
		t.Fatal(err)
	}
	if _, hit, err := disk.Get(ctx, key); err != nil || hit {
		t.Fatalf("lookup after Clear = hit %v, err %v; want miss", hit, err)
	}
}

func TestDiskMalformedAndIncompatibleEntriesAreMisses(t *testing.T) {
	ctx := context.Background()
	disk, err := NewDisk(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	key := testKey(t, "corrupt")
	path, err := disk.path(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	invalidSchema, err := json.Marshal(diskEntry{
		SchemaVersion: entrySchemaVersion + 1,
		Metadata:      Metadata{Key: string(key), Namespace: "scan"},
		Payload:       json.RawMessage(`{"ok":true}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range [][]byte{[]byte("{truncated"), invalidSchema} {
		if err := os.WriteFile(path, entry, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, hit, err := disk.Get(ctx, key); err != nil || hit {
			t.Fatalf("corrupt entry lookup = hit %v, err %v; want miss", hit, err)
		}
	}
}

func TestDiskAtomicallyReplacesEntry(t *testing.T) {
	ctx := context.Background()
	disk, err := NewDisk(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	key := testKey(t, "replace")
	if err := disk.Put(ctx, key, []byte(`{"value":1}`), Metadata{}); err != nil {
		t.Fatal(err)
	}
	if err := disk.Put(ctx, key, []byte(`{"value":2}`), Metadata{}); err != nil {
		t.Fatal(err)
	}
	payload, hit, err := disk.Get(ctx, key)
	if err != nil || !hit || string(payload) != `{"value":2}` {
		t.Fatalf("replacement Get() = %s, hit %v, err %v", payload, hit, err)
	}
}

func TestDiskConcurrentWritesRemainReadable(t *testing.T) {
	ctx := context.Background()
	disk, err := NewDisk(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	key := testKey(t, "concurrent")
	const workers = 20
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			payload, _ := json.Marshal(map[string]int{"writer": i})
			if err := disk.Put(ctx, key, payload, Metadata{}); err != nil {
				t.Errorf("Put() failed: %v", err)
			}
			if _, _, err := disk.Get(ctx, key); err != nil {
				t.Errorf("Get() failed: %v", err)
			}
		}(i)
	}
	wg.Wait()
	if _, hit, err := disk.Get(ctx, key); err != nil || !hit {
		t.Fatalf("final lookup = hit %v, err %v", hit, err)
	}
}

func TestKeyForCanonicalAndBehaviorSensitive(t *testing.T) {
	first, err := KeyFor("scan", map[string]any{"source": "x", "config": map[string]int{"depth": 8, "paths": 3}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := KeyFor("scan", map[string]any{"config": map[string]int{"paths": 3, "depth": 8}, "source": "x"})
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("equivalent inputs produced different keys: %s != %s", first, second)
	}
	changed, err := KeyFor("scan", map[string]any{"source": "x", "config": map[string]int{"depth": 9, "paths": 3}})
	if err != nil {
		t.Fatal(err)
	}
	if first == changed {
		t.Fatal("changed configuration produced the same key")
	}
	otherNamespace, err := KeyFor("planner", map[string]string{"source": "x"})
	if err != nil {
		t.Fatal(err)
	}
	if first == otherNamespace {
		t.Fatal("namespace change produced the same key")
	}
}

func TestDiskRejectsUnsafeKey(t *testing.T) {
	disk, err := NewDisk(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := disk.Get(context.Background(), Key("../../etc/passwd")); err == nil {
		t.Fatal("expected unsafe key to be rejected")
	}
	if _, err := NamespacedKey("../scan", Key("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")); err == nil {
		t.Fatal("expected unsafe namespace to be rejected")
	}
}
