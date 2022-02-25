package local

import (
	"hash/fnv"
	"sync"

	"github.com/open-policy-agent/frameworks/constraint/pkg/handler"
)

// SyncSize determines the maximum number of callers who may simultaneously hold
// a lock at once. It is set as a compiler-time constant to make arithmetic
// operations cheap and allow us to use an array of Mutexes instead of a slice.
//
// 128 is chosen as it is a power of 2 and does not cause more than a 10%
// slowdown until serving 25 calls at once.
//
// This can be calculated using formulas derived for the Coupon Collector's Problem:
// https://en.wikipedia.org/wiki/Coupon_collector%27s_problem
//
// Generally, SyncSize should be kept around 5x the expected maximum number of
// simultaneous callers to avoid this slowdown.
const SyncSize = 128

// Sync distributes write calls across SyncSize mutexes. Callers for objects with
// identical storage paths are guaranteed to wait until the previous one is finished.
// While it is possible for callers of different objects to block each other; in
// practice this has very little effect on average callers handled at once.
//
// The naive approach to this problem would be to have a map which generates a
// unique id for each distinct key, maintain reference counts for the key, and
// then cleanup the mutex once all callers for that key are done. That would be
// more expensive since it requires dynamically resizing the map, and more
// complex since we have to keep track of reference counts.
//
// This implementation experiences noticeable slowdown once number of simultaneous
// callers is 25 or more.
type Sync struct {
	// mutexes is the set of preallocated Mutexes.
	// Each sync.Mutex consumes a total of 8 bytes.
	mutexes [SyncSize]sync.Mutex
}

// ID returns the unique identifier of the Mutex corresponding to key.
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
