package rego

import (
	"context"
	"crypto/tls"
	"net/http"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	oparego "github.com/open-policy-agent/opa/v1/rego"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/externaldata/unversioned"
	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
)

func TestExternalDataBuiltinCachesOnlyRequestedKeys(t *testing.T) {
	callCount := 0
	d := newExternalDataBuiltinTestDriver(t, func(_ context.Context, _ *unversioned.Provider, keys []string, _ *tls.Certificate) (*externaldata.ProviderResponse, int, error) {
		callCount++
		items := []externaldata.Item{{Key: keys[0], Value: "requested-value"}}
		if callCount == 1 {
			items = append(items, externaldata.Item{Key: "other-key", Value: "other-value"})
		}
		return providerResponse(items, ""), http.StatusOK, nil
	})

	callExternalDataBuiltin(t, d, "requested-key")
	callExternalDataBuiltin(t, d, "other-key")

	if callCount != 2 {
		t.Fatalf("provider called %d times, want 2", callCount)
	}
}

func TestExternalDataBuiltinDoesNotCacheSystemErrors(t *testing.T) {
	callCount := 0
	d := newExternalDataBuiltinTestDriver(t, func(_ context.Context, _ *unversioned.Provider, keys []string, _ *tls.Certificate) (*externaldata.ProviderResponse, int, error) {
		callCount++
		if callCount == 1 {
			return providerResponse([]externaldata.Item{{Key: keys[0], Value: "stale-value"}}, "provider unavailable"), http.StatusOK, nil
		}
		return providerResponse([]externaldata.Item{{Key: keys[0], Value: "current-value"}}, ""), http.StatusOK, nil
	})

	first := callExternalDataBuiltin(t, d, "key")
	if first.SystemError != "provider unavailable" {
		t.Fatalf("system error = %q, want %q", first.SystemError, "provider unavailable")
	}
	second := callExternalDataBuiltin(t, d, "key")
	if second.SystemError != "" {
		t.Fatalf("system error = %q, want empty", second.SystemError)
	}
	if callCount != 2 {
		t.Fatalf("provider called %d times, want 2", callCount)
	}
}

func newExternalDataBuiltinTestDriver(t *testing.T, send externaldata.SendRequestToProvider) *Driver {
	t.Helper()

	providerCache := externaldata.NewCache()
	err := providerCache.Upsert(&unversioned.Provider{
		ObjectMeta: metav1.ObjectMeta{Name: "dummy-provider"},
		Spec: unversioned.ProviderSpec{
			URL:      "https://example.com",
			Timeout:  1,
			CABundle: caBundle,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	return &Driver{
		providerCache:         providerCache,
		providerResponseCache: externaldata.NewProviderResponseCache(t.Context(), time.Minute),
		sendRequestToProvider: send,
	}
}

func callExternalDataBuiltin(t *testing.T, d *Driver, keys ...string) externaldata.RegoResponse {
	t.Helper()

	value, err := ast.InterfaceToValue(map[string]interface{}{
		"provider": "dummy-provider",
		"keys":     keys,
	})
	if err != nil {
		t.Fatal(err)
	}
	term, err := externalDataBuiltin(d)(oparego.BuiltinContext{Context: t.Context()}, ast.NewTerm(value))
	if err != nil {
		t.Fatal(err)
	}

	var response externaldata.RegoResponse
	if err := ast.As(term.Value, &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func providerResponse(items []externaldata.Item, systemError string) *externaldata.ProviderResponse {
	return &externaldata.ProviderResponse{
		Response: externaldata.Response{
			Idempotent:  true,
			Items:       items,
			SystemError: systemError,
		},
	}
}
