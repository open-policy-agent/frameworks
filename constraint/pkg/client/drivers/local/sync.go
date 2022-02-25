package local

import (
	"sync/atomic"
)

// Sync generates unique identifiers to be used for calls. Threadsafe.
// Safe for use in environments where fewer than 2^64 calls are expected.
type Sync struct {
	// id is the previously-returned identifier.
	id uint64
}

// ID returns a unique identifier for a call.
// Begins at 1.
func (s *Sync) ID() uint64 {
	id := atomic.AddUint64(&s.id, 1)

	return id
}
