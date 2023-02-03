package clienttest

import (
	"testing"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/rego"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler/handlertest"
)

func defaults() []client.Opt {
	d, err := rego.New()
	if err != nil {
		panic(err)
	}

	return []client.Opt{
		client.Driver(d),
		client.Targets(&handlertest.Handler{Cache: &handlertest.Cache{}}),
	}
}

// New constructs a new Client for testing with a default-constructed local driver
// and no other Backend opts.
func New(t testing.TB, opts ...client.Opt) *client.Client {
	t.Helper()

	opts = append(defaults(), opts...)

	c, err := client.NewClient(opts...)
	if err != nil {
		t.Fatal(err)
	}

	return c
}
