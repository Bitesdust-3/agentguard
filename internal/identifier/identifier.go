// Package identifier creates opaque process-restart-safe identifiers for
// persisted AgentGuard records.
package identifier

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync/atomic"
	"time"
)

var fallbackSequence atomic.Uint64

// New returns a prefixed identifier without embedding user or request data.
func New(prefix string) string {
	var value [12]byte
	if _, err := rand.Read(value[:]); err == nil {
		return prefix + "_" + hex.EncodeToString(value[:])
	}
	return fmt.Sprintf("%s_%x_%x", prefix, time.Now().UTC().UnixNano(), fallbackSequence.Add(1))
}
