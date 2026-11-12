package rego

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	opatypes "github.com/open-policy-agent/opa/v1/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/certwatcher"

	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/externaldata/unversioned"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/clienttest/cts"
	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
)

const (
	isolationProviderName = "dummy-provider"

	// isolationPolicy reports which Provider answered each of two calls.
	isolationPolicy = `package foobar

violation[{"msg": msg}] {
  first := external_data({"provider": "dummy-provider", "keys": [input.review.key]})
  second := external_data({"provider": "dummy-provider", "keys": [concat("-", [input.review.key, "second"])]})
  msg := sprintf("%v/%v", [first.responses[0][1], second.responses[0][1]])
}
`

	// memoizedPolicy calls external_data twice with identical arguments.
	memoizedPolicy = `package foobar

violation[{"msg": msg}] {
  first := external_data({"provider": "dummy-provider", "keys": [input.review.key]})
  second := external_data({"provider": "dummy-provider", "keys": [input.review.key]})
  msg := sprintf("%v/%v", [first.responses[0][1], second.responses[0][1]])
}
`

	httpSendPolicy = `package foobar

violation[{"msg": "unexpected http.send"}] {
  http.send({"method": "get", "url": "https://example.com"})
}
`
)

type providerCall struct {
	key  string
	cert *tls.Certificate
}

// recordingSender answers every key with value and records each request.
type recordingSender struct {
	value string
	// beforeReply, if set, runs for each key before replying and may block.
	beforeReply func(ctx context.Context, key string) error

	mu    sync.Mutex
	calls []providerCall
}

func (s *recordingSender) send(ctx context.Context, _ *unversioned.Provider, keys []string, cert *tls.Certificate) (*externaldata.ProviderResponse, int, error) {
	items := make([]externaldata.Item, 0, len(keys))
	for _, key := range keys {
		s.mu.Lock()
		s.calls = append(s.calls, providerCall{key: key, cert: cert})
		s.mu.Unlock()

		if s.beforeReply != nil {
			if err := s.beforeReply(ctx, key); err != nil {
				return nil, http.StatusInternalServerError, err
			}
		}
		items = append(items, externaldata.Item{Key: key, Value: s.value})
	}

	return &externaldata.ProviderResponse{
		Response: externaldata.Response{Idempotent: true, Items: items},
	}, http.StatusOK, nil
}

func (s *recordingSender) recorded() []providerCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.calls)
}

func (s *recordingSender) keys() []string {
	var keys []string
	for _, call := range s.recorded() {
		keys = append(keys, call.key)
	}
	return keys
}

func newProviderCache(t testing.TB) *externaldata.ProviderCache {
	t.Helper()

	cache := externaldata.NewCache()
	err := cache.Upsert(&unversioned.Provider{
		ObjectMeta: metav1.ObjectMeta{Name: isolationProviderName},
		Spec: unversioned.ProviderSpec{
			URL:      "https://example.com",
			Timeout:  1,
			CABundle: caBundle,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	return cache
}

// newIsolationDriver creates a Driver with policy and a single Constraint.
func newIsolationDriver(t testing.TB, policy string, send externaldata.SendRequestToProvider, args ...Arg) *Driver {
	t.Helper()

	d, err := New(args...)
	if err != nil {
		t.Fatal(err)
	}
	if send != nil {
		d.sendRequestToProvider = send
	}

	ctx := context.Background()
	tmpl := cts.New(cts.OptTargets(cts.TargetWithVersion(cts.MockTargetHandler, policy, ast.RegoV0)))
	if err := d.AddTemplate(ctx, tmpl); err != nil {
		t.Fatal(err)
	}
	if err := d.AddConstraint(ctx, cts.MakeConstraint(t, "Fakes", "foo-1")); err != nil {
		t.Fatal(err)
	}

	return d
}

func newTestCertWatcher(t *testing.T) *certwatcher.CertWatcher {
	t.Helper()

	dir := t.TempDir()
	certFile := filepath.Join(dir, "tls.crt")
	keyFile := filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certFile, []byte(clientCert), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, []byte(clientKey), 0o600); err != nil {
		t.Fatal(err)
	}

	watcher, err := certwatcher.New(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}

	return watcher
}

// newClientCertWatcher returns a CertWatcher for a new self-signed cert.
func newClientCertWatcher(t *testing.T, commonName string) *certwatcher.CertWatcher {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	certFile := filepath.Join(dir, "tls.crt")
	keyFile := filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}

	watcher, err := certwatcher.New(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}

	return watcher
}

// queryMessages returns the sorted violation messages for key.
func queryMessages(ctx context.Context, d *Driver, constraint *unstructured.Unstructured, key string) ([]string, error) {
	response, err := d.Query(ctx, cts.MockTargetHandler,
		[]*unstructured.Unstructured{constraint},
		map[string]interface{}{"key": key})
	if err != nil {
		return nil, err
	}

	msgs := make([]string, 0, len(response.Results))
	for _, result := range response.Results {
		msgs = append(msgs, result.Msg)
	}
	slices.Sort(msgs)

	return msgs, nil
}

func TestDriver_ExternalDataBoundPerDriver(t *testing.T) {
	ctx := t.Context()
	constraint := cts.MakeConstraint(t, "Fakes", "foo-1")

	responsesA := externaldata.NewProviderResponseCache(ctx, time.Minute)
	responsesB := externaldata.NewProviderResponseCache(ctx, time.Minute)
	senderA := &recordingSender{value: "A"}
	senderB := &recordingSender{value: "B"}

	driverA := newIsolationDriver(t, isolationPolicy, senderA.send,
		AddExternalDataProviderCache(newProviderCache(t)),
		AddExternalDataProviderResponseCache(responsesA),
		EnableExternalDataClientAuth(),
		AddExternalDataClientCertWatcher(newTestCertWatcher(t)),
	)
	// A second driver with the same Provider name must not affect the first.
	driverB := newIsolationDriver(t, isolationPolicy, senderB.send,
		AddExternalDataProviderCache(newProviderCache(t)),
		AddExternalDataProviderResponseCache(responsesB),
	)

	for _, tc := range []struct {
		name   string
		driver *Driver
		key    string
		want   string
	}{
		{name: "first driver", driver: driverA, key: "a", want: "A/A"},
		{name: "second driver", driver: driverB, key: "b", want: "B/B"},
	} {
		got, err := queryMessages(ctx, tc.driver, constraint, tc.key)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if !slices.Equal(got, []string{tc.want}) {
			t.Errorf("%s: got violations %q, want [%q]", tc.name, got, tc.want)
		}
	}

	if got, want := senderA.keys(), []string{"a", "a-second"}; !slices.Equal(got, want) {
		t.Errorf("first driver's Provider received %q, want %q", got, want)
	}
	if got, want := senderB.keys(), []string{"b", "b-second"}; !slices.Equal(got, want) {
		t.Errorf("second driver's Provider received %q, want %q", got, want)
	}
	for _, call := range senderA.recorded() {
		if call.cert == nil {
			t.Errorf("first driver sent key %q without its client certificate", call.key)
		}
	}
	for _, call := range senderB.recorded() {
		if call.cert != nil {
			t.Errorf("second driver sent key %q with a client certificate it was not configured with", call.key)
		}
	}

	for _, tc := range []struct {
		key        string
		owner      *externaldata.ProviderResponseCache
		other      *externaldata.ProviderResponseCache
		ownerLabel string
	}{
		{key: "a", owner: responsesA, other: responsesB, ownerLabel: "first"},
		{key: "a-second", owner: responsesA, other: responsesB, ownerLabel: "first"},
		{key: "b", owner: responsesB, other: responsesA, ownerLabel: "second"},
		{key: "b-second", owner: responsesB, other: responsesA, ownerLabel: "second"},
	} {
		cacheKey := externaldata.CacheKey{ProviderName: isolationProviderName, Key: tc.key}
		if _, err := tc.owner.Get(cacheKey); err != nil {
			t.Errorf("%s driver's response cache is missing key %q: %v", tc.ownerLabel, tc.key, err)
		}
		if _, err := tc.other.Get(cacheKey); err == nil {
			t.Errorf("key %q from the %s driver leaked into another driver's response cache", tc.key, tc.ownerLabel)
		}
	}
}

func TestDriver_ExternalDataClientCertificatePerDriver(t *testing.T) {
	ctx := t.Context()
	constraint := cts.MakeConstraint(t, "Fakes", "foo-1")

	// The Provider replies with the client cert's common name.
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity := "none"
		if len(r.TLS.PeerCertificates) > 0 {
			identity = r.TLS.PeerCertificates[0].Subject.CommonName
		}

		var req externaldata.ProviderRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := externaldata.ProviderResponse{
			APIVersion: "externaldata.gatekeeper.sh/v1beta1",
			Kind:       externaldata.ProviderResponseKind,
		}
		for _, key := range req.Request.Keys {
			resp.Response.Items = append(resp.Response.Items, externaldata.Item{Key: key, Value: identity})
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	server.TLS = &tls.Config{ClientAuth: tls.RequestClientCert, MinVersion: tls.VersionTLS13}
	server.StartTLS()
	t.Cleanup(server.Close)

	serverCA := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	newServerProviderCache := func() *externaldata.ProviderCache {
		cache := externaldata.NewCache()
		err := cache.Upsert(&unversioned.Provider{
			ObjectMeta: metav1.ObjectMeta{Name: isolationProviderName},
			Spec:       unversioned.ProviderSpec{URL: server.URL, Timeout: 5, CABundle: serverCA},
		})
		if err != nil {
			t.Fatal(err)
		}
		return cache
	}

	// Same Provider for all drivers, default sender.
	driverA := newIsolationDriver(t, isolationPolicy, nil,
		AddExternalDataProviderCache(newServerProviderCache()),
		EnableExternalDataClientAuth(),
		AddExternalDataClientCertWatcher(newClientCertWatcher(t, "driver-a")),
	)
	driverWithoutAuth := newIsolationDriver(t, isolationPolicy, nil,
		AddExternalDataProviderCache(newServerProviderCache()),
	)
	driverB := newIsolationDriver(t, isolationPolicy, nil,
		AddExternalDataProviderCache(newServerProviderCache()),
		EnableExternalDataClientAuth(),
		AddExternalDataClientCertWatcher(newClientCertWatcher(t, "driver-b")),
	)

	// driverA runs first so its connection is idle and could be reused.
	for _, tc := range []struct {
		name   string
		driver *Driver
		want   string
	}{
		{name: "driver with certificate A", driver: driverA, want: "driver-a/driver-a"},
		{name: "driver without client auth", driver: driverWithoutAuth, want: "none/none"},
		{name: "driver with certificate B", driver: driverB, want: "driver-b/driver-b"},
		{name: "driver with certificate A again", driver: driverA, want: "driver-a/driver-a"},
	} {
		got, err := queryMessages(ctx, tc.driver, constraint, tc.name)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if !slices.Equal(got, []string{tc.want}) {
			t.Errorf("%s: Provider saw client certificates %q, want [%q]", tc.name, got, tc.want)
		}
	}
}

func TestDriver_ExternalDataIsolatedAcrossOverlappingQueries(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	constraint := cts.MakeConstraint(t, "Fakes", "foo-1")

	paused := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseFirst := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseFirst()

	senderA := &recordingSender{value: "A", beforeReply: func(ctx context.Context, key string) error {
		if key != "paused" {
			return nil
		}
		close(paused)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}}
	driverA := newIsolationDriver(t, isolationPolicy, senderA.send,
		AddExternalDataProviderCache(newProviderCache(t)))

	type queryResult struct {
		msgs []string
		err  error
	}
	resultA := make(chan queryResult, 1)
	go func() {
		msgs, err := queryMessages(ctx, driverA, constraint, "paused")
		resultA <- queryResult{msgs: msgs, err: err}
	}()

	select {
	case <-paused:
	case <-ctx.Done():
		t.Fatalf("first query did not reach its Provider: %v", ctx.Err())
	}

	// Create and use a second driver mid-way through the first query.
	senderB := &recordingSender{value: "B"}
	driverB := newIsolationDriver(t, isolationPolicy, senderB.send,
		AddExternalDataProviderCache(newProviderCache(t)))
	gotB, err := queryMessages(ctx, driverB, constraint, "b")
	if err != nil {
		t.Fatal(err)
	}

	releaseFirst()
	gotA := <-resultA
	if gotA.err != nil {
		t.Fatal(gotA.err)
	}

	if want := []string{"A/A"}; !slices.Equal(gotA.msgs, want) {
		t.Errorf("first driver: got violations %q, want %q", gotA.msgs, want)
	}
	if want := []string{"B/B"}; !slices.Equal(gotB, want) {
		t.Errorf("second driver: got violations %q, want %q", gotB, want)
	}
	if got, want := senderA.keys(), []string{"paused", "paused-second"}; !slices.Equal(got, want) {
		t.Errorf("first driver's Provider received %q, want %q", got, want)
	}
	if got, want := senderB.keys(), []string{"b", "b-second"}; !slices.Equal(got, want) {
		t.Errorf("second driver's Provider received %q, want %q", got, want)
	}
}

func TestDriver_ExternalDataIsolatedAcrossConcurrentQueries(t *testing.T) {
	const (
		workers    = 8
		iterations = 20
	)

	ctx := t.Context()
	constraint := cts.MakeConstraint(t, "Fakes", "foo-1")

	senderA := &recordingSender{value: "A"}
	senderB := &recordingSender{value: "B"}
	driverA := newIsolationDriver(t, isolationPolicy, senderA.send,
		AddExternalDataProviderCache(newProviderCache(t)))
	driverB := newIsolationDriver(t, isolationPolicy, senderB.send,
		AddExternalDataProviderCache(newProviderCache(t)))

	errs := make(chan error, workers*iterations)
	var wg sync.WaitGroup
	for worker := range workers {
		wg.Go(func() {
			for i := range iterations {
				driver, want := driverA, "A/A"
				if (worker+i)%2 == 1 {
					driver, want = driverB, "B/B"
				}

				msgs, err := queryMessages(ctx, driver, constraint, fmt.Sprintf("%d-%d", worker, i))
				if err != nil {
					errs <- err
					continue
				}
				if !slices.Equal(msgs, []string{want}) {
					errs <- fmt.Errorf("worker %d iteration %d: got violations %q, want [%q]", worker, i, msgs, want)
				}
			}
		})
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}

func TestDriver_ExternalDataNotRegisteredGlobally(t *testing.T) {
	newIsolationDriver(t, isolationPolicy, (&recordingSender{value: "A"}).send,
		AddExternalDataProviderCache(newProviderCache(t)))

	if _, found := ast.BuiltinMap["external_data"]; found {
		t.Error("creating a driver registered external_data in OPA's global builtins")
	}
	isExternalData := func(b *ast.Builtin) bool { return b.Name == "external_data" }
	if slices.ContainsFunc(ast.CapabilitiesForThisVersion().Builtins, isExternalData) {
		t.Error("creating a driver added external_data to OPA's default capabilities")
	}

	// A driver without a Provider cache must not use another driver's.
	withoutCache, err := New()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := cts.New(cts.OptTargets(cts.TargetWithVersion(cts.MockTargetHandler, isolationPolicy, ast.RegoV0)))
	err = withoutCache.AddTemplate(t.Context(), tmpl)
	if err == nil || !strings.Contains(err.Error(), "undefined function external_data") {
		t.Fatalf("got AddTemplate() error %v, want undefined function external_data", err)
	}
}

const globalExternalDataEnv = "FRAMEWORKS_TEST_GLOBAL_EXTERNAL_DATA"

// Runs in a subprocess because OPA cannot unregister a global built-in.
func TestDriver_ExternalDataRejectsGlobalRegistration(t *testing.T) {
	const name = "TestDriver_ExternalDataRejectsGlobalRegistration"
	if os.Getenv(globalExternalDataEnv) != "1" {
		//nolint:gosec // Re-runs this test binary.
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^"+name+"$", "-test.v")
		cmd.Env = append(os.Environ(), globalExternalDataEnv+"=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("subprocess failed: %v\n%s", err, out)
		}
		if !strings.Contains(string(out), "--- PASS: "+name) {
			t.Fatalf("subprocess did not run %s:\n%s", name, out)
		}
		return
	}

	rego.RegisterBuiltin1(
		&rego.Function{Name: "external_data", Decl: opatypes.NewFunction(opatypes.Args(opatypes.A), opatypes.A)},
		func(rego.BuiltinContext, *ast.Term) (*ast.Term, error) {
			return ast.MustParseTerm(`{"responses": [["key", "global"]]}`), nil
		},
	)

	_, err := New(AddExternalDataProviderCache(newProviderCache(t)))
	if !errors.Is(err, ErrExternalDataRegisteredGlobally) {
		t.Fatalf("got New() error %v, want %v", err, ErrExternalDataRegisteredGlobally)
	}

	// Without a Provider cache, a global external_data keeps working.
	d := newIsolationDriver(t, isolationPolicy, nil)
	msgs, err := queryMessages(t.Context(), d, cts.MakeConstraint(t, "Fakes", "foo-1"), "key")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"global/global"}; !slices.Equal(msgs, want) {
		t.Fatalf("got messages %v, want %v", msgs, want)
	}
}

// A Provider cache enables external_data even if DisableBuiltins lists it.
func TestDriver_ExternalDataAvailability(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		args                 func(*externaldata.ProviderCache) []Arg
		wantHTTPSendDisabled bool
	}{
		{
			name: "provider cache",
			args: func(cache *externaldata.ProviderCache) []Arg {
				return []Arg{AddExternalDataProviderCache(cache)}
			},
		},
		{
			name: "external_data disabled before provider cache",
			args: func(cache *externaldata.ProviderCache) []Arg {
				return []Arg{DisableBuiltins("external_data"), AddExternalDataProviderCache(cache)}
			},
		},
		{
			name: "external_data disabled after provider cache",
			args: func(cache *externaldata.ProviderCache) []Arg {
				return []Arg{AddExternalDataProviderCache(cache), DisableBuiltins("external_data")}
			},
		},
		{
			name: "other builtins stay disabled",
			args: func(cache *externaldata.ProviderCache) []Arg {
				return []Arg{DisableBuiltins("http.send"), AddExternalDataProviderCache(cache)}
			},
			wantHTTPSendDisabled: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sender := &recordingSender{value: "A"}
			driver := newIsolationDriver(t, isolationPolicy, sender.send, tc.args(newProviderCache(t))...)

			got, err := queryMessages(t.Context(), driver, cts.MakeConstraint(t, "Fakes", "foo-1"), "a")
			if err != nil {
				t.Fatal(err)
			}
			if want := []string{"A/A"}; !slices.Equal(got, want) {
				t.Errorf("got violations %q, want %q", got, want)
			}

			if !tc.wantHTTPSendDisabled {
				return
			}
			tmpl := cts.New(cts.OptTargets(cts.TargetWithVersion(cts.MockTargetHandler, httpSendPolicy, ast.RegoV0)))
			err = driver.AddTemplate(t.Context(), tmpl)
			if err == nil || !strings.Contains(err.Error(), "undefined function http.send") {
				t.Errorf("got AddTemplate() error %v, want undefined function http.send", err)
			}
		})
	}
}

func TestDriver_ExternalDataMemoized(t *testing.T) {
	ctx := t.Context()
	constraint := cts.MakeConstraint(t, "Fakes", "foo-1")
	sender := &recordingSender{value: "A"}
	driver := newIsolationDriver(t, memoizedPolicy, sender.send,
		AddExternalDataProviderCache(newProviderCache(t)))

	// Identical calls are memoized per query, not across queries.
	for query, wantCalls := range []int{1, 2} {
		got, err := queryMessages(ctx, driver, constraint, "key")
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{"A/A"}; !slices.Equal(got, want) {
			t.Errorf("query %d: got violations %q, want %q", query, got, want)
		}
		if got := len(sender.recorded()); got != wantCalls {
			t.Errorf("after query %d: Provider called %d times, want %d", query, got, wantCalls)
		}
	}
}

func BenchmarkDriver_QueryExternalData(b *testing.B) {
	sender := func(_ context.Context, _ *unversioned.Provider, keys []string, _ *tls.Certificate) (*externaldata.ProviderResponse, int, error) {
		items := make([]externaldata.Item, 0, len(keys))
		for _, key := range keys {
			items = append(items, externaldata.Item{Key: key, Value: "A"})
		}
		return &externaldata.ProviderResponse{Response: externaldata.Response{Items: items}}, http.StatusOK, nil
	}
	driver := newIsolationDriver(b, isolationPolicy, sender, AddExternalDataProviderCache(newProviderCache(b)))
	benchmarkQuery(b, driver)
}

func BenchmarkDriver_QueryWithoutExternalData(b *testing.B) {
	driver := newIsolationDriver(b, AlwaysViolate, nil)
	benchmarkQuery(b, driver)
}

func benchmarkQuery(b *testing.B, driver *Driver) {
	ctx := context.Background()
	constraints := []*unstructured.Unstructured{cts.MakeConstraint(b, "Fakes", "foo-1")}
	review := map[string]interface{}{"key": "a"}

	b.ReportAllocs()
	for b.Loop() {
		if _, err := driver.Query(ctx, cts.MockTargetHandler, constraints, review); err != nil {
			b.Fatal(err)
		}
	}
}
