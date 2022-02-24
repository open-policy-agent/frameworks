package local

import (
	"hash/fnv"
	"sync"

	"github.com/open-policy-agent/frameworks/constraint/pkg/handler"
)

// SyncSize determines the maximum number of callers who may simultaneously hold
// a lock at once.
// On average, SyncSize of n serves (n-0.581) requests simultaneously, only slightly
// less than if we constructed a map of mutexes which could hold at most 32 objects.
const SyncSize = 32

// Sync distributes write calls across SyncSize mutexes. Callers for objects with
// identical storage paths are guaranteed to wait until the previous one is finished.
// While it is possible for callers of different objects to block each other; in
// practice this has very little effect on average callers handled at once.
type Sync struct {
	// mutexes is the set of preallocated Mutexes.
	// Each consumes a total of 8 bytes.
	mutexes [SyncSize]sync.Mutex
}

// ID returns the unique identifier of the mutex corresponding to key.
func (s *Sync) ID(key handler.StoragePath) uint32 {
	h := fnv.New32a()

	// This can't return an error, so we don't need to check for it.
	_, _ = h.Write([]byte(key.String()))

	return h.Sum32() % SyncSize
}

// Lock acquires the lock corresponding to id, blocking until it becomes
// available.
func (s *Sync) Lock(id uint32) {
	s.mutexes[id].Lock()
}

// Unlock releases the lock corresponding to id.
func (s *Sync) Unlock(id uint32) {
	s.mutexes[id].Unlock()
}
