package externaldata

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/externaldata/unversioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"go.uber.org/goleak"
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

func TestDefaultSendRequestToProvider_GoroutineLeak(t *testing.T) {
	// Verifies that DefaultSendRequestToProvider does not leak goroutines.
	// The package-level defaultClientCache reuses HTTP clients per provider,
	// so only one transport (and its readLoop/writeLoop) exists at a time.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := ProviderResponse{
			APIVersion: "externaldata.gatekeeper.sh/v1beta1",
			Kind:       "ProviderResponse",
			Response: Response{
				Idempotent: true,
				Items: []Item{
					{Key: "key1", Value: "value1"},
				},
			},
		}
		json.NewEncoder(w).Encode(response)
	}))
	// Defer order is LIFO: server.Close (first) runs last,
	// goleak.VerifyNone (second) runs before it — catching leaked
	// goroutines while the server is still alive and connections idle.
	defer server.Close()
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	provider := &unversioned.Provider{
		ObjectMeta: metav1.ObjectMeta{Name: "test-provider"},
		Spec: unversioned.ProviderSpec{
			URL:      server.URL,
			Timeout:  5,
			CABundle: base64.StdEncoding.EncodeToString(pemEncodeCertificate(server.Certificate())),
		},
	}

	ctx := context.Background()
	for i := 0; i < 5; i++ {
		_, _, err := DefaultSendRequestToProvider(ctx, provider, []string{"key1"}, nil)
		if err != nil {
			t.Fatalf("Request %d failed: %v", i, err)
		}
	}

	// Clean up the cached client so idle connections are closed
	// and goleak can verify no goroutines are leaked.
	defaultClientCache.Invalidate(provider.GetName())
}

func pemEncodeCertificate(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}
