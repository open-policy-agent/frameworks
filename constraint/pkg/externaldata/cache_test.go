package externaldata

import (
	"testing"

	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/externaldata/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type cacheTestCase struct {
	Name          string
	Provider      *v1alpha1.Provider
	ErrorExpected bool
}

func createProvider(name string, url string, timeout int, caBundle string, insecureTLSSkipVerify bool) *v1alpha1.Provider {
	return &v1alpha1.Provider{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v1alpha1.ProviderSpec{
			URL:                   url,
			Timeout:               timeout,
			CABundle:              caBundle,
			InsecureTLSSkipVerify: insecureTLSSkipVerify,
		},
	}
}

func TestUpsert(t *testing.T) {
	tc := []cacheTestCase{
		{
			Name:          "valid http provider",
			Provider:      createProvider("test", "http://test", 1, "", true),
			ErrorExpected: false,
		},
		{
			Name:          "http provider with caBundle and insecureTLSSkipVerify",
			Provider:      createProvider("test", "http://test", 1, "caBundle", true),
			ErrorExpected: true,
		},
		{
			Name:          "http provider with without insecure tls skip verify",
			Provider:      createProvider("test", "http://test", 1, "", false),
			ErrorExpected: true,
		},
		{
			Name:          "valid https provider",
			Provider:      createProvider("test", "https://test", 1, "caBundle", false),
			ErrorExpected: false,
		},
		{
			Name:          "https provider with no caBundle",
			Provider:      createProvider("test", "https://test", 1, "", false),
			ErrorExpected: true,
		},
		{
			Name:          "empty name",
			Provider:      createProvider("", "http://test", 1, "", true),
			ErrorExpected: true,
		},
		{
			Name:          "empty url",
			Provider:      createProvider("test", "", 1, "", true),
			ErrorExpected: true,
		},
		{
			Name:          "invalid url",
			Provider:      createProvider("test", "gopher://test", 1, "", true),
			ErrorExpected: true,
		},
		{
			Name:          "invalid timeout",
			Provider:      createProvider("test", "http://test", -1, "", true),
			ErrorExpected: true,
		},
		{
			Name:          "empty provider",
			Provider:      &v1alpha1.Provider{},
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
			Name:          "valid provider",
			Provider:      createProvider("test", "http://test", 1, "", true),
			ErrorExpected: false,
		},
		{
			Name:          "invalid provider",
			Provider:      createProvider("", "http://test", 1, "", true),
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
			Provider:      createProvider("test", "http://test", 1, "", true),
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
