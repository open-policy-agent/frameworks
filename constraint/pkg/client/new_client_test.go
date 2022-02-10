package client_test

import (
	"errors"
	"testing"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/local"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler/handlertest"
)

func TestNewClient(t *testing.T) {
	testCases := []struct {
		name       string
		clientOpts []client.Opt
		wantError  error
	}{
		{
			name:       "no opts",
			clientOpts: nil,
			wantError:  client.ErrCreatingClient,
		},
		{
			name:       "with handler",
			clientOpts: []client.Opt{client.Targets(&handlertest.Handler{})},
			wantError:  nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			opts := tc.clientOpts
			opts = append(opts, client.Driver(local.New()))

			_, err := client.NewClient(opts...)
			if !errors.Is(err, tc.wantError) {
				t.Fatalf("got NewClient() eror = %v, want %v",
					err, tc.wantError)
			}
		})
	}
}
