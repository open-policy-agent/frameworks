package client_test

import (
	"errors"
	"testing"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/clienttest"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/local"
)

func TestNewBackend(t *testing.T) {
	testCases := []struct {
		name      string
		opts      []client.BackendOpt
		wantError error
	}{
		{
			name:      "no args",
			opts:      nil,
			wantError: client.ErrCreatingBackend,
		},
		{
			name:      "good",
			opts:      []client.BackendOpt{client.Driver(local.New())},
			wantError: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, gotErr := client.NewBackend(tc.opts...)

			if !errors.Is(gotErr, tc.wantError) {
				t.Fatalf("got NewBackent() error = %v, want %v",
					gotErr, tc.wantError)
			}
		})
	}
}

func TestBackend_NewClient(t *testing.T) {
	testCases := []struct {
		name        string
		backendOpts []client.BackendOpt
		clientOpts  []client.Opt
		wantError   error
	}{
		{
			name:        "no opts",
			backendOpts: nil,
			clientOpts:  nil,
			wantError:   client.ErrCreatingClient,
		},
		{
			name:        "with handler",
			backendOpts: nil,
			clientOpts:  []client.Opt{client.Targets(&clienttest.Handler{})},
			wantError:   nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			opts := []client.BackendOpt{client.Driver(local.New())}
			opts = append(opts, tc.backendOpts...)

			backend, err := client.NewBackend(opts...)
			if err != nil {
				t.Fatal(err)
			}

			_, err = backend.NewClient(tc.clientOpts...)
			if !errors.Is(err, tc.wantError) {
				t.Fatalf("got NewClient() eror = %v, want %v",
					err, tc.wantError)
			}
		})
	}
}

func TestBackend_NewClient2(t *testing.T) {
	backend, err := client.NewBackend(client.Driver(local.New()))
	if err != nil {
		t.Fatal(err)
	}

	_, err = backend.NewClient(client.Targets(&clienttest.Handler{}))
	if err != nil {
		t.Fatal(err)
	}

	_, err = backend.NewClient(client.Targets(&clienttest.Handler{}))
	if !errors.Is(err, client.ErrCreatingClient) {
		t.Fatalf("got NewClient() err = %v, want %v",
			err, client.ErrCreatingClient)
	}
}
