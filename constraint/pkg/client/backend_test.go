package client

import (
	"errors"
	"testing"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/local"
)

func TestNewBackend(t *testing.T) {
	testCases := []struct {
		name      string
		opts      []BackendOpt
		wantError error
	}{
		{
			name:      "no args",
			opts:      nil,
			wantError: ErrCreatingBackend,
		},
		{
			name:      "good",
			opts:      []BackendOpt{Driver(local.New())},
			wantError: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, gotErr := NewBackend(tc.opts...)

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
		backendOpts []BackendOpt
		clientOpts  []Opt
		wantError   error
	}{
		{
			name:        "no opts",
			backendOpts: nil,
			clientOpts:  nil,
			wantError:   ErrCreatingClient,
		},
		{
			name:        "with handler",
			backendOpts: nil,
			clientOpts:  []Opt{Targets(&handler{})},
			wantError:   nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			opts := []BackendOpt{Driver(local.New())}
			opts = append(opts, tc.backendOpts...)

			backend, err := NewBackend(opts...)
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
	backend, err := NewBackend(Driver(local.New()))
	if err != nil {
		t.Fatal(err)
	}

	_, err = backend.NewClient(Targets(&handler{}))
	if err != nil {
		t.Fatal(err)
	}

	_, err = backend.NewClient(Targets(&handler{}))
	if !errors.Is(err, ErrCreatingClient) {
		t.Fatalf("got NewClient() err = %v, want %v",
			err, ErrCreatingClient)
	}
}
