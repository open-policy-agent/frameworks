package handlertest

import (
	"errors"
	"fmt"
	"sync"

	"github.com/open-policy-agent/frameworks/constraint/pkg/handler"
)

var ErrInvalidObject = errors.New("invalid object")

// Cache is a threadsafe Cache for the test Handler which keeps track of
// Namespaces.
type Cache struct {
	Namespaces sync.Map
}

var _ handler.Cache = &Cache{}

// Add inserts object into Cache if object is a Namespace.
func (c *Cache) Add(key string, object interface{}) error {
	obj, ok := object.(*Object)
	if !ok {
		return fmt.Errorf("%w: got object type %T, want %T", ErrInvalidType, object, &Object{})
	}

	if obj.Name != "" {
		return nil
	}

	if obj.Namespace == "" {
		return fmt.Errorf("%w: must specify one of Name or Namespace", ErrInvalidObject)
	}

	c.Namespaces.Store(key, object)

	return nil
}

func (c *Cache) Remove(key string) error {
	c.Namespaces.Delete(key)

	return nil
}
