package clienttest

import (
	"testing"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/local"
)

var defaults = []client.Opt{
	client.Targets(&Handler{}),
}

// New constructs a new Client for testing with a default-constructed local driver
// and no other Backend opts.
func New(t *testing.T, opts ...client.Opt) *client.Client {
	t.Helper()

	backend, err := client.NewBackend(client.Driver(local.New()))
	if err != nil {
		t.Fatal(err)
	}

	opts = append(defaults, opts...)

	c, err := backend.NewClient(opts...)
	if err != nil {
		t.Fatal(err)
	}

	return c
}
