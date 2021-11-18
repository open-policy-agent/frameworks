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
