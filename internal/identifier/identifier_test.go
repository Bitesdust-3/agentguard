package identifier

import (
	"strings"
	"testing"
)

func TestNewReturnsUniqueOpaquePrefixedIDs(t *testing.T) {
	seen := make(map[string]struct{}, 1024)
	for range 1024 {
		id := New("audit")
		if !strings.HasPrefix(id, "audit_") {
			t.Fatalf("id = %q, want audit prefix", id)
		}
		if _, exists := seen[id]; exists {
			t.Fatalf("duplicate id %q", id)
		}
		seen[id] = struct{}{}
	}
}
