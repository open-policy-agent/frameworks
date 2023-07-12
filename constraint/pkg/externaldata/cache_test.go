package externaldata

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/externaldata/unversioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	validCABundle   = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUIwekNDQVgyZ0F3SUJBZ0lKQUkvTTdCWWp3Qit1TUEwR0NTcUdTSWIzRFFFQkJRVUFNRVV4Q3pBSkJnTlYKQkFZVEFrRlZNUk13RVFZRFZRUUlEQXBUYjIxbExWTjBZWFJsTVNFd0h3WURWUVFLREJoSmJuUmxjbTVsZENCWAphV1JuYVhSeklGQjBlU0JNZEdRd0hoY05NVEl3T1RFeU1qRTFNakF5V2hjTk1UVXdPVEV5TWpFMU1qQXlXakJGCk1Rc3dDUVlEVlFRR0V3SkJWVEVUTUJFR0ExVUVDQXdLVTI5dFpTMVRkR0YwWlRFaE1COEdBMVVFQ2d3WVNXNTAKWlhKdVpYUWdWMmxrWjJsMGN5QlFkSGtnVEhSa01Gd3dEUVlKS29aSWh2Y05BUUVCQlFBRFN3QXdTQUpCQU5MSgpoUEhoSVRxUWJQa2xHM2liQ1Z4d0dNUmZwL3Y0WHFoZmRRSGRjVmZIYXA2TlE1V29rLzR4SUErdWkzNS9NbU5hCnJ0TnVDK0JkWjF0TXVWQ1BGWmNDQXdFQUFhTlFNRTR3SFFZRFZSME9CQllFRkp2S3M4UmZKYVhUSDA4VytTR3YKelF5S24wSDhNQjhHQTFVZEl3UVlNQmFBRkp2S3M4UmZKYVhUSDA4VytTR3Z6UXlLbjBIOE1Bd0dBMVVkRXdRRgpNQU1CQWY4d0RRWUpLb1pJaHZjTkFRRUZCUUFEUVFCSmxmZkpIeWJqREd4Uk1xYVJtRGhYMCs2djAyVFVLWnNXCnI1UXVWYnBRaEg2dSswVWdjVzBqcDlRd3B4b1BUTFRXR1hFV0JCQnVyeEZ3aUNCaGtRK1YKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="
	badBase64String = "!"
	badCABundle     = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCmhlbGxvCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"
)

type cacheTestCase struct {
	Name          string
	Provider      *unversioned.Provider
	ErrorExpected bool
}

func createProvider(name string, url string, timeout int, caBundle string) *unversioned.Provider {
	return &unversioned.Provider{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: unversioned.ProviderSpec{
			URL:      url,
			Timeout:  timeout,
			CABundle: caBundle,
		},
	}
}

func TestUpsert(t *testing.T) {
	tc := []cacheTestCase{
		{
			Name:          "http provider",
			Provider:      createProvider("test", "http://test", 1, ""),
			ErrorExpected: true,
		},
		{
			Name:          "http provider with caBundle",
			Provider:      createProvider("test", "http://test", 1, validCABundle),
			ErrorExpected: true,
		},
		{
			Name:          "valid https provider",
			Provider:      createProvider("test", "https://test", 1, validCABundle),
			ErrorExpected: false,
		},
		{
			Name:          "https provider with no caBundle",
			Provider:      createProvider("test", "https://test", 1, ""),
			ErrorExpected: true,
		},
		{
			Name:          "https provider with bad base64 caBundle",
			Provider:      createProvider("test", "https://test", 1, badBase64String),
			ErrorExpected: true,
		},
		{
			Name:          "https provider with bad caBundle",
			Provider:      createProvider("test", "https://test", 1, badCABundle),
			ErrorExpected: true,
		},
		{
			Name:          "empty name",
			Provider:      createProvider("", "http://test", 1, ""),
			ErrorExpected: true,
		},
		{
			Name:          "empty url",
			Provider:      createProvider("test", "", 1, ""),
			ErrorExpected: true,
		},
		{
			Name:          "url with invalid scheme",
			Provider:      createProvider("test", "gopher://test", 1, ""),
			ErrorExpected: true,
		},
		{
			Name:          "invalid url",
			Provider:      createProvider("test", " http://foo.com", 1, ""),
			ErrorExpected: true,
		},
		{
			Name:          "invalid timeout",
			Provider:      createProvider("test", "http://test", -1, ""),
			ErrorExpected: true,
		},
		{
			Name:          "empty provider",
			Provider:      &unversioned.Provider{},
			ErrorExpected: true,
		},
	}
	for _, tt := range tc {
		cache := NewCache()
		t.Run(tt.Name, func(t *testing.T) {
			err := cache.Upsert(tt.Provider)

			if (err == nil) && tt.ErrorExpected {
				t.Fatalf("err = nil; want non-nil")
			}
			if (err != nil) && !tt.ErrorExpected {
				t.Fatalf("err = \"%s\"; want nil", err)
			}
		})
	}
}

func TestGet(t *testing.T) {
	tc := []cacheTestCase{
		{
			Name:          "valid https provider",
			Provider:      createProvider("test", "https://test", 1, validCABundle),
			ErrorExpected: false,
		},
		{
			Name:          "valid https provider with empty caBundle",
			Provider:      createProvider("test", "https://test", 1, ""),
			ErrorExpected: true,
		},
		{
			Name:          "valid https provider with bad caBundle",
			Provider:      createProvider("test", "https://test", 1, badCABundle),
			ErrorExpected: true,
		},
		{
			Name:          "invalid provider",
			Provider:      createProvider("", "http://test", 1, ""),
			ErrorExpected: true,
		},
	}
	for _, tt := range tc {
		cache := NewCache()
		t.Run(tt.Name, func(t *testing.T) {
			_ = cache.Upsert(tt.Provider)
			_, err := cache.Get(tt.Provider.Name)

			if (err == nil) && tt.ErrorExpected {
				t.Fatalf("err = nil; want non-nil")
			}
			if (err != nil) && !tt.ErrorExpected {
				t.Fatalf("err = \"%s\"; want nil", err)
			}
		})
	}
}

func TestRemove(t *testing.T) {
	tc := []cacheTestCase{
		{
			Name:          "valid provider",
			Provider:      createProvider("test", "https://test", 1, ""),
			ErrorExpected: false,
		},
	}
	for _, tt := range tc {
		cache := NewCache()
		t.Run(tt.Name, func(t *testing.T) {
			_ = cache.Upsert(tt.Provider)
			cache.Remove(tt.Provider.Name)

			if (cache != nil) && tt.ErrorExpected {
				t.Fatalf("cache = \"%v\"; want nil", cache)
			}
		})
	}
}

func TestProviderResponseCache(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	tests := []struct {
		name        string
		key         CacheKey
		value       CacheValue
		expected    *CacheValue
		expectedErr error
	}{
		{
			name:        "Upsert and Get",
			key:         CacheKey{ProviderName: "test", Key: "key1"},
			value:       CacheValue{Received: time.Now().Unix(), Value: "value1"},
			expected:    &CacheValue{Received: time.Now().Unix(), Value: "value1"},
			expectedErr: nil,
		},
		{
			name:        "Remove",
			key:         CacheKey{ProviderName: "test", Key: "key1"},
			value:       CacheValue{Received: time.Now().Unix(), Value: "value1"},
			expected:    nil,
			expectedErr: fmt.Errorf("key 'test:key1' is not found in provider response cache"),
		},
		{
			name:        "Invalidation",
			key:         CacheKey{ProviderName: "test", Key: "key2"},
			value:       CacheValue{Value: "value2"},
			expected:    nil,
			expectedErr: fmt.Errorf("key 'test:key2' is not found in provider response cache"),
		},
		{
			name:        "Error",
			key:         CacheKey{ProviderName: "test", Key: "key3"},
			value:       CacheValue{},
			expected:    nil,
			expectedErr: fmt.Errorf("key 'test:key3' is not found in provider response cache"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.name {
			case "Upsert and Get":
				cache := NewProviderResponseCache(ctx, 1*time.Minute)
				cache.Upsert(tt.key, tt.value)

				cachedValue, err := cache.Get(tt.key)
				if err != tt.expectedErr {
					t.Errorf("Expected error to be %v, but got %v", tt.expectedErr, err)
				}
				if cachedValue != nil && cachedValue.Value != tt.expected.Value {
					t.Errorf("Expected cached value to be %v, but got %v", tt.expected.Value, cachedValue.Value)
				}
			case "Remove":
				cache := NewProviderResponseCache(ctx, 1*time.Minute)
				cache.Remove(tt.key)

				_, err := cache.Get(tt.key)
				if err == nil {
					t.Errorf("Expected error, but got nil")
				}
				if err.Error() != tt.expectedErr.Error() {
					t.Errorf("Expected error message to be '%s', but got '%s'", tt.expectedErr.Error(), err.Error())
				}
			case "Invalidation":
				cache := NewProviderResponseCache(ctx, 5*time.Second)
				tt.value.Received = time.Now().Add(-10 * time.Second).Unix()
				cache.Upsert(tt.key, tt.value)

				time.Sleep(5 * time.Second)

				_, err := cache.Get(tt.key)
				if err == nil {
					t.Errorf("Expected error, but got nil")
				}
				if err.Error() != tt.expectedErr.Error() {
					t.Errorf("Expected error message to be '%s', but got '%s'", tt.expectedErr.Error(), err.Error())
				}
			case "Error":
				cache := NewProviderResponseCache(ctx, 1*time.Minute)
				_, err := cache.Get(tt.key)
				if err == nil {
					t.Errorf("Expected error, but got nil")
				}
				if err.Error() != tt.expectedErr.Error() {
					t.Errorf("Expected error message to be '%s', but got '%s'", tt.expectedErr.Error(), err.Error())
				}
			}
		})
	}
}
