package externaldata

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"reflect"
	"sync"
	"testing"

	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/externaldata/unversioned"
	"go.uber.org/goleak"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

func TestClientCache_getOrCreate_TLSValidation(t *testing.T) {
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
					ObjectMeta: metav1.ObjectMeta{Name: "http-provider"},
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
					ObjectMeta: metav1.ObjectMeta{Name: "no-ca-provider"},
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
					ObjectMeta: metav1.ObjectMeta{Name: "bad-ca-provider"},
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
					ObjectMeta: metav1.ObjectMeta{Name: "valid-ca-provider"},
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
			cache := NewClientCache()
			client, err := cache.getOrCreate(tt.args.provider, tt.args.clientCert)
			if (err != nil) != tt.wantErr {
				t.Errorf("ClientCache.getOrCreate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && client == nil {
				t.Error("ClientCache.getOrCreate() returned nil client for successful case")
			}
		})
	}
}

func TestDefaultSendRequestToProvider_NoGoroutineLeak(t *testing.T) {
	// Verifies that DefaultSendRequestToProvider does not leak goroutines.
	// This is a regression test for a bug where each call created a new http.Transport
	// with lingering goroutines (readLoop/writeLoop) that persisted until idle timeout (90s).
	// The package-level defaultClientCache now reuses HTTP clients per provider,
	// so only one transport (and its readLoop/writeLoop) exists per provider.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
		_ = json.NewEncoder(w).Encode(response)
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

// newTLSProvider creates a provider pointing at the given TLS test server.
func newTLSProvider(name string, server *httptest.Server) *unversioned.Provider {
	return &unversioned.Provider{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: unversioned.ProviderSpec{
			URL:      server.URL,
			Timeout:  5,
			CABundle: base64.StdEncoding.EncodeToString(pemEncodeCertificate(server.Certificate())),
		},
	}
}

// newProviderResponseServer returns an httptest.NewTLSServer that responds
// with a valid ProviderResponse.
func newProviderResponseServer() *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := ProviderResponse{
			APIVersion: "externaldata.gatekeeper.sh/v1beta1",
			Kind:       "ProviderResponse",
			Response: Response{
				Idempotent: true,
				Items:      []Item{{Key: "key1", Value: "value1"}},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func TestClientCache_Reuse(t *testing.T) {
	cache := NewClientCache()

	provider := &unversioned.Provider{
		ObjectMeta: metav1.ObjectMeta{Name: "reuse-provider"},
		Spec: unversioned.ProviderSpec{
			URL:      "https://example.com",
			Timeout:  5,
			CABundle: validCABundle,
		},
	}

	client1, err := cache.getOrCreate(provider, nil)
	if err != nil {
		t.Fatalf("first getOrCreate failed: %v", err)
	}

	client2, err := cache.getOrCreate(provider, nil)
	if err != nil {
		t.Fatalf("second getOrCreate failed: %v", err)
	}

	if client1 != client2 {
		t.Error("expected same *http.Client pointer on reuse, got different pointers")
	}
}

func TestClientCache_InvalidateOnSpecChange(t *testing.T) {
	cache := NewClientCache()

	provider := &unversioned.Provider{
		ObjectMeta: metav1.ObjectMeta{Name: "spec-change-provider"},
		Spec: unversioned.ProviderSpec{
			URL:      "https://example.com",
			Timeout:  5,
			CABundle: validCABundle,
		},
	}

	client1, err := cache.getOrCreate(provider, nil)
	if err != nil {
		t.Fatalf("first getOrCreate failed: %v", err)
	}

	// Change timeout → spec change
	provider.Spec.Timeout = 10
	client2, err := cache.getOrCreate(provider, nil)
	if err != nil {
		t.Fatalf("second getOrCreate failed: %v", err)
	}

	if client1 == client2 {
		t.Error("expected different *http.Client after spec change, got same pointer")
	}
}

func TestClientCache_Invalidate(t *testing.T) {
	cache := NewClientCache()

	provider := &unversioned.Provider{
		ObjectMeta: metav1.ObjectMeta{Name: "invalidate-provider"},
		Spec: unversioned.ProviderSpec{
			URL:      "https://example.com",
			Timeout:  5,
			CABundle: validCABundle,
		},
	}

	client1, err := cache.getOrCreate(provider, nil)
	if err != nil {
		t.Fatalf("first getOrCreate failed: %v", err)
	}

	cache.Invalidate(provider.GetName())

	client2, err := cache.getOrCreate(provider, nil)
	if err != nil {
		t.Fatalf("second getOrCreate failed: %v", err)
	}

	if client1 == client2 {
		t.Error("expected different *http.Client after Invalidate, got same pointer")
	}
}

func TestClientCache_ConcurrentAccess(t *testing.T) {
	cache := NewClientCache()

	provider := &unversioned.Provider{
		ObjectMeta: metav1.ObjectMeta{Name: "concurrent-provider"},
		Spec: unversioned.ProviderSpec{
			URL:      "https://example.com",
			Timeout:  5,
			CABundle: validCABundle,
		},
	}

	var wg sync.WaitGroup
	errs := make(chan error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := cache.getOrCreate(provider, nil)
			if err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent getOrCreate failed: %v", err)
	}
}

func TestClientCache_ConnectionReuse(t *testing.T) {
	server := newProviderResponseServer()
	defer server.Close()

	cache := NewClientCache()
	provider := newTLSProvider("conn-reuse-provider", server)

	client, err := cache.getOrCreate(provider, nil)
	if err != nil {
		t.Fatalf("getOrCreate failed: %v", err)
	}

	ctx := context.Background()
	body := []byte(`{"apiVersion":"externaldata.gatekeeper.sh/v1beta1","kind":"ProviderRequest","request":{"keys":["key1"]}}`)

	// Make first request to establish connection
	req, err := http.NewRequest(http.MethodPost, provider.Spec.URL, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		t.Fatalf("first request failed: %v", err)
	}
	// Drain body fully to allow connection reuse
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	// Second request: use httptrace to verify connection was reused
	var gotReused bool
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			gotReused = info.Reused
		},
	}
	req2, err := http.NewRequest(http.MethodPost, provider.Spec.URL, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req2.Header.Set("Content-Type", "application/json")
	req2 = req2.WithContext(httptrace.WithClientTrace(ctx, trace))
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("second request failed: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp2.Body)
	_ = resp2.Body.Close()

	if !gotReused {
		t.Error("expected TCP connection to be reused on second request, but it was not")
	}
}

func TestClientCache_NilCert(t *testing.T) {
	cache := NewClientCache()

	provider := &unversioned.Provider{
		ObjectMeta: metav1.ObjectMeta{Name: "nil-cert-provider"},
		Spec: unversioned.ProviderSpec{
			URL:      "https://example.com",
			Timeout:  5,
			CABundle: validCABundle,
		},
	}

	// Create with nil cert
	client1, err := cache.getOrCreate(provider, nil)
	if err != nil {
		t.Fatalf("getOrCreate with nil cert failed: %v", err)
	}

	// Same provider, still nil cert → same client
	client2, err := cache.getOrCreate(provider, nil)
	if err != nil {
		t.Fatalf("second getOrCreate with nil cert failed: %v", err)
	}
	if client1 != client2 {
		t.Error("expected same client on second call with nil cert")
	}

	// Now supply a cert → same client returned (spec didn't change), but cert stored
	cert := &tls.Certificate{}
	client3, err := cache.getOrCreate(provider, cert)
	if err != nil {
		t.Fatalf("getOrCreate with cert failed: %v", err)
	}
	if client1 != client3 {
		t.Error("expected same client when adding cert (spec unchanged)")
	}

	// Verify the cert was stored in the atomic pointer
	cache.mu.Lock()
	entry := cache.clients[provider.GetName()]
	cache.mu.Unlock()
	if stored := entry.cert.Load(); stored != cert {
		t.Error("expected stored cert to match the one passed in")
	}
}

func TestClientCache_NoGoroutineLeak(t *testing.T) {
	server := newProviderResponseServer()
	defer server.Close()
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	cache := NewClientCache()
	provider := newTLSProvider("no-leak-provider", server)

	ctx := context.Background()
	for i := 0; i < 5; i++ {
		client, err := cache.getOrCreate(provider, nil)
		if err != nil {
			t.Fatalf("getOrCreate failed: %v", err)
		}

		body := []byte(`{"apiVersion":"externaldata.gatekeeper.sh/v1beta1","kind":"ProviderRequest","request":{"keys":["key1"]}}`)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, provider.Spec.URL, nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		_ = resp.Body.Close()
	}

	// Invalidate to close idle connections before goleak checks
	cache.Invalidate(provider.GetName())
}

func TestDefaultSendRequestToProvider_Integration(t *testing.T) {
	server := newProviderResponseServer()
	defer server.Close()

	provider := newTLSProvider("integration-provider", server)

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		resp, statusCode, err := DefaultSendRequestToProvider(ctx, provider, []string{"key1"}, nil)
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		if statusCode != http.StatusOK {
			t.Errorf("request %d: expected status 200, got %d", i, statusCode)
		}
		if len(resp.Response.Items) != 1 || resp.Response.Items[0].Key != "key1" {
			t.Errorf("request %d: unexpected response items: %+v", i, resp.Response.Items)
		}
	}

	// Clean up to avoid polluting other tests via the package-level cache
	defaultClientCache.Invalidate(provider.GetName())
}
