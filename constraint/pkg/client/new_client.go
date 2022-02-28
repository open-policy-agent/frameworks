package client

import (
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// NewClient creates a new client.
func NewClient(opts ...Opt) (*Client, error) {
	c := &Client{
		constraints: make(map[string]map[string]*unstructured.Unstructured),
		templates:   make(map[string]*templateEntry),
	}

	for _, opt := range opts {
		if err := opt(c); err != nil {
			return nil, err
		}
	}

	if len(c.targets) == 0 {
		return nil, fmt.Errorf("%w: must specify at least one target with client.Targets",
			ErrCreatingClient)
	}

	return c, nil
}
