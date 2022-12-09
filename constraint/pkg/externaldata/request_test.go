package externaldata

import (
	"crypto/tls"
	"reflect"
	"testing"

	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/externaldata/unversioned"
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

func Test_getClient(t *testing.T) {
	type args struct {
		provider   *unversioned.Provider
		clientCert *tls.Certificate
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "invalid http url",
			args: args{
				provider: &unversioned.Provider{
					Spec: unversioned.ProviderSpec{
						URL: "http://foo",
					},
				},
				clientCert: nil,
			},
			wantErr: true,
		},
		{
			name: "no CA bundle",
			args: args{
				provider: &unversioned.Provider{
					Spec: unversioned.ProviderSpec{
						URL: "https://foo",
					},
				},
				clientCert: nil,
			},
			wantErr: true,
		},
		{
			name: "invalid CA bundle",
			args: args{
				provider: &unversioned.Provider{
					Spec: unversioned.ProviderSpec{
						URL:      "https://foo",
						CABundle: badCABundle,
					},
				},
				clientCert: nil,
			},
			wantErr: true,
		},
		{
			name: "valid CA bundle",
			args: args{
				provider: &unversioned.Provider{
					Spec: unversioned.ProviderSpec{
						URL:      "https://foo",
						CABundle: validCABundle,
					},
				},
				clientCert: nil,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := getClient(tt.args.provider, tt.args.clientCert)
			if (err != nil) != tt.wantErr {
				t.Errorf("getClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
