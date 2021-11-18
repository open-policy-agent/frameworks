package types

import "testing"

func TestResponses_HandledCount(t *testing.T) {
	testCases := []struct {
		name      string
		responses Responses
		want      int
	}{
		{
			name:      "empty responses",
			responses: Responses{},
			want:      0,
		},
		{
			name: "one handled",
			responses: Responses{
				Handled: map[string]bool{"a": true},
			},
			want: 1,
		},
		{
			name: "two handled",
			responses: Responses{
				Handled: map[string]bool{"a": true, "b": true},
			},
			want: 2,
		},
		{
			name: "one handled and not handled",
			responses: Responses{
				Handled: map[string]bool{"a": true, "b": false},
			},
			want: 1,
		},
		{
			name: "one not handled and one handled",
			responses: Responses{
				Handled: map[string]bool{"a": false, "b": true},
			},
			want: 1,
		},
		{
			name: "none handled",
			responses: Responses{
				Handled: map[string]bool{"a": false, "b": false},
			},
			want: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.responses.HandledCount()

			if got != tc.want {
				t.Fatalf("got HandledCount() = %v, want %v", got, tc.want)
			}
		})
	}
}
