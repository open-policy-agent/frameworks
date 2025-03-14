package rego

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/externaldata/unversioned"
	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
)

const (
	providerResponseAPIVersion = "externaldata.gatekeeper.sh/v1beta1"
	providerResponseKind       = "ProviderResponse"
	HTTPSScheme                = "https"
	idleConnTimeout            = 90 * time.Second
	maxIdleConnsPerHost        = 100
)

func externalDataBuiltin(d *Driver) func(bctx rego.BuiltinContext, regorequest *ast.Term) (*ast.Term, error) {
	return func(bctx rego.BuiltinContext, regorequest *ast.Term) (*ast.Term, error) {
		var regoReq externaldata.RegoRequest
		if err := ast.As(regorequest.Value, &regoReq); err != nil {
			return nil, err
		}

		provider, err := d.providerCache.Get(regoReq.ProviderName)
		if err != nil {
			return externaldata.HandleError(http.StatusBadRequest, err)
		}

		clientCert, err := d.getTLSCertificate()
		if err != nil {
			return externaldata.HandleError(http.StatusBadRequest, err)
		}

		client, err := getClient(&provider, clientCert)
		if err != nil {
			return externaldata.HandleError(http.StatusInternalServerError,
				fmt.Errorf("failed to get HTTP client: %w", err))
		}

		// check provider response cache
		var providerRequestKeys []string
		var providerResponseStatusCode int
		var prepareResponse externaldata.Response

		prepareResponse.Idempotent = true
		for _, k := range regoReq.Keys {
			if d.providerResponseCache == nil {
				// external data response cache is not enabled, add key to call provider
				providerRequestKeys = append(providerRequestKeys, k)
				continue
			}

			cachedResponse, err := d.providerResponseCache.Get(
				externaldata.CacheKey{
					ProviderName: regoReq.ProviderName,
					Key:          k,
				},
			)
			if err != nil || time.Since(time.Unix(cachedResponse.Received, 0)) > d.providerResponseCache.TTL {
				// key is not found or cache entry is stale, add key to the provider request keys
				providerRequestKeys = append(providerRequestKeys, k)
			} else {
				prepareResponse.Items = append(
					prepareResponse.Items, externaldata.Item{
						Key:   k,
						Value: cachedResponse.Value,
						Error: cachedResponse.Error,
					},
				)

				// we are taking conservative approach here, if any of the cached response is not idempotent
				// we will mark the whole response as not idempotent
				if !cachedResponse.Idempotent {
					prepareResponse.Idempotent = false
				}
			}
		}

		if len(providerRequestKeys) > 0 {
			externaldataResponse, statusCode, err := d.sendRequestToProvider(bctx.Context, &provider, providerRequestKeys, client)
			if err != nil {
				return externaldata.HandleError(statusCode, err)
			}

			// update provider response cache if it is enabled
			if d.providerResponseCache != nil {
				for _, item := range externaldataResponse.Response.Items {
					d.providerResponseCache.Upsert(
						externaldata.CacheKey{
							ProviderName: regoReq.ProviderName,
							Key:          item.Key,
						},
						externaldata.CacheValue{
							Received:   time.Now().Unix(),
							Value:      item.Value,
							Error:      item.Error,
							Idempotent: externaldataResponse.Response.Idempotent,
						},
					)
				}
			}

			// we are taking conservative approach here, if any of the response is not idempotent
			// we will mark the whole response as not idempotent
			if !externaldataResponse.Response.Idempotent {
				prepareResponse.Idempotent = false
			}

			prepareResponse.Items = append(prepareResponse.Items, externaldataResponse.Response.Items...)
			prepareResponse.SystemError = externaldataResponse.Response.SystemError
			providerResponseStatusCode = statusCode
		}

		providerResponse := &externaldata.ProviderResponse{
			APIVersion: providerResponseAPIVersion,
			Kind:       providerResponseKind,
			Response:   prepareResponse,
		}

		regoResponse := externaldata.NewRegoResponse(providerResponseStatusCode, providerResponse)
		return externaldata.PrepareRegoResponse(regoResponse)
	}
}

// getClient returns a new HTTP client, and set up its TLS configuration.
func getClient(provider *unversioned.Provider, clientCert *tls.Certificate) (*http.Client, error) {
	u, err := url.Parse(provider.Spec.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse provider URL %s: %w", provider.Spec.URL, err)
	}

	if u.Scheme != HTTPSScheme {
		return nil, fmt.Errorf("only HTTPS scheme is supported")
	}

	client := &http.Client{
		Timeout: time.Duration(provider.Spec.Timeout) * time.Second,
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}

	// present our client cert to the server
	// in case provider wants to verify it
	if clientCert != nil {
		tlsConfig.Certificates = []tls.Certificate{*clientCert}
	}

	// if the provider presents its own CA bundle,
	// we will use it to verify the server's certificate
	caBundleData, err := base64.StdEncoding.DecodeString(provider.Spec.CABundle)
	if err != nil {
		return nil, fmt.Errorf("failed to decode CA bundle: %w", err)
	}

	providerCertPool := x509.NewCertPool()
	if ok := providerCertPool.AppendCertsFromPEM(caBundleData); !ok {
		return nil, fmt.Errorf("failed to append provider's CA bundle to certificate pool")
	}

	tlsConfig.RootCAs = providerCertPool

	client.Transport = &http.Transport{
		TLSClientConfig:     tlsConfig,
		IdleConnTimeout:     idleConnTimeout,
		MaxIdleConnsPerHost: maxIdleConnsPerHost,
	}

	return client, nil
}
