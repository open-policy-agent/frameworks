package externaldata

import (
	"reflect"
	"testing"
)

func TestNewProviderRequest(t *testing.T) {
	type args struct {
		keys []string
	}
	tests := []struct {
		name string
		args args
		want *ProviderRequest
	}{
		{
			name: "empty keys",
			args: args{
				keys: []string{},
			},
			want: &ProviderRequest{
				APIVersion: "externaldata.gatekeeper.sh/v1beta1",
				Kind:       "ProviderRequest",
				Request: Request{
					Keys: []string{},
				},
			},
		},
		{
			name: "one key",
			args: args{
				keys: []string{"key1"},
			},
			want: &ProviderRequest{
				APIVersion: "externaldata.gatekeeper.sh/v1beta1",
				Kind:       "ProviderRequest",
				Request: Request{
					Keys: []string{"key1"},
				},
			},
		},
		{
			name: "multiple keys",
			args: args{
				keys: []string{"key1", "key2"},
			},
			want: &ProviderRequest{
				APIVersion: "externaldata.gatekeeper.sh/v1beta1",
				Kind:       "ProviderRequest",
				Request: Request{
					Keys: []string{"key1", "key2"},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewProviderRequest(tt.args.keys); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewProviderRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}
