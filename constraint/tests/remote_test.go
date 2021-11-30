package tests

import (
	"testing"
)

func TestRemoteClientE2E(t *testing.T) {
	t.Skip("test does not work yet")

	// This code no longer compiles, but is preserved so the original intent is
	// preserved once we have a working remote to test the Client against.
	//
	// Most likely what we'd want is a TestMain function which can toggle whether
	// the local or remote Driver is used for E2E tests. If we want these to
	// execute by default when "go test" is run (including in CI) then we'd want
	// to call m.Run() twice in TestMain after the local driver tests run
	// (and pass).
	//
	// d, err := remote.New(remote.URL("http://localhost:8181"), remote.Tracing(false))
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// p, err := client.NewProbe(d)
	// if err != nil {
	// 	t.Fatal(err)
	// }
	//
	// for name, f := range p.TestFuncs() {
	// 	t.Run(name, func(t *testing.T) {
	// 		if err := f(); err != nil {
	// 			t.Fatal(err)
	// 		}
	// 	})
	// }
}
