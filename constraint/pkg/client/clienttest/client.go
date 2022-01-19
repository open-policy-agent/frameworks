package clienttest

import (
	"testing"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/local"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler/handlertest"
)

var defaults = []client.Opt{
	client.Targets(&handlertest.Handler{}),
}

// New constructs a new Client for testing with a default-constructed local driver
// and no other Backend opts.
func New(t testing.TB, opts ...client.Opt) *client.Client {
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
