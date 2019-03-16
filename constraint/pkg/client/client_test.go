package client

import (
	"testing"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/local"
)

func TestClient(t *testing.T) {
	d := local.New(local.Tracing(true))
	p, err := NewProbe(d)
	if err != nil {
		t.Fatal(err)
	}
	for name, f := range p.TestFuncs() {
		t.Run(name, func(t *testing.T) {
			if err := f(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
