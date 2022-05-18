package externaldata

import (
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/externaldata/v1alpha1"
)

type ProviderCache struct {
	cache map[string]v1alpha1.Provider
	mux   sync.RWMutex
}

func NewCache() *ProviderCache {
	return &ProviderCache{
		cache: make(map[string]v1alpha1.Provider),
	}
}

func (c *ProviderCache) Get(key string) (v1alpha1.Provider, error) {
	c.mux.RLock()
	defer c.mux.RUnlock()

	if v, ok := c.cache[key]; ok {
		dc := *v.DeepCopy()
		return dc, nil
	}
	return v1alpha1.Provider{}, fmt.Errorf("key is not found in provider cache")
}

func (c *ProviderCache) Upsert(provider *v1alpha1.Provider) error {
	c.mux.Lock()
	defer c.mux.Unlock()

	if !isValidName(provider.Name) {
		return fmt.Errorf("provider name can not be empty. value %s", provider.Name)
	}
	if !isValidURL(provider.Spec.URL) {
		return fmt.Errorf("invalid provider url. value: %s", provider.Spec.URL)
	}
	if !isValidTimeout(provider.Spec.Timeout) {
		return fmt.Errorf("provider timeout should be a positive integer. value: %d", provider.Spec.Timeout)
	}
	if err := isValidCABundle(provider); err != nil {
		return err
	}

	c.cache[provider.GetName()] = *provider.DeepCopy()
	return nil
}

func (c *ProviderCache) Remove(name string) {
	c.mux.Lock()
	defer c.mux.Unlock()

	delete(c.cache, name)
}

func isValidName(name string) bool {
	return len(name) != 0
}

func isValidURL(url string) bool {
	if len(url) == 0 {
		return false
	}
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return false
	}
	return true
}

func isValidCABundle(provider *v1alpha1.Provider) error {
	if provider.Spec.InsecureTLSSkipVerify {
		if provider.Spec.CABundle != "" {
			return fmt.Errorf("insecureTLSSkipVerify is set to true but caBundle is not empty")
		}

		return nil
	}

	u, err := url.Parse(provider.Spec.URL)
	if err != nil {
		return err
	}

	switch u.Scheme {
	case "http":
		return fmt.Errorf("only HTTPS scheme is supported for Providers. To enable HTTP scheme, set insecureTLSSkipVerify to true")
	case "https":
		if provider.Spec.CABundle == "" {
			return fmt.Errorf("caBundle should be set for HTTPS scheme")
		}
	}

	return nil
}

func isValidTimeout(timeout int) bool {
	return timeout >= 0
}
