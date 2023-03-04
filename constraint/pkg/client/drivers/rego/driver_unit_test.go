package rego

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/constraints"
	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/externaldata/unversioned"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/clienttest/cts"
	clienterrors "github.com/open-policy-agent/frameworks/constraint/pkg/client/errors"
	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler/handlertest"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/certwatcher"
)

const (
	Module string = `
package foobar

fooisbar[msg] {
  input.foo == "bar"
  msg := "input.foo is bar"
}
`

	AlwaysViolate string = `
  package foobar

  violation[{"msg": "always violate"}] {
	  true
  }
`

	ExternalData string = `
	package foobar

	violation[{"msg": msg}] {
	  response := external_data({"provider": "dummy-provider", "keys": ["key"]})
	  response_with_error(response)
	  msg := sprintf("invalid response: %v", [response])
	}
	response_with_error(response) {
	  count(response.errors) > 0
	  errs := response.errors[_]
	  contains(errs[1], "_invalid")
	}
	response_with_error(response) {
	  count(response.system_error) > 0
	}
`
)

const (
	caBundle = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUIwekNDQVgyZ0F3SUJBZ0lKQUkvTTdCWWp3Qit1TUEwR0NTcUdTSWIzRFFFQkJRVUFNRVV4Q3pBSkJnTlYKQkFZVEFrRlZNUk13RVFZRFZRUUlEQXBUYjIxbExWTjBZWFJsTVNFd0h3WURWUVFLREJoSmJuUmxjbTVsZENCWAphV1JuYVhSeklGQjBlU0JNZEdRd0hoY05NVEl3T1RFeU1qRTFNakF5V2hjTk1UVXdPVEV5TWpFMU1qQXlXakJGCk1Rc3dDUVlEVlFRR0V3SkJWVEVUTUJFR0ExVUVDQXdLVTI5dFpTMVRkR0YwWlRFaE1COEdBMVVFQ2d3WVNXNTAKWlhKdVpYUWdWMmxrWjJsMGN5QlFkSGtnVEhSa01Gd3dEUVlKS29aSWh2Y05BUUVCQlFBRFN3QXdTQUpCQU5MSgpoUEhoSVRxUWJQa2xHM2liQ1Z4d0dNUmZwL3Y0WHFoZmRRSGRjVmZIYXA2TlE1V29rLzR4SUErdWkzNS9NbU5hCnJ0TnVDK0JkWjF0TXVWQ1BGWmNDQXdFQUFhTlFNRTR3SFFZRFZSME9CQllFRkp2S3M4UmZKYVhUSDA4VytTR3YKelF5S24wSDhNQjhHQTFVZEl3UVlNQmFBRkp2S3M4UmZKYVhUSDA4VytTR3Z6UXlLbjBIOE1Bd0dBMVVkRXdRRgpNQU1CQWY4d0RRWUpLb1pJaHZjTkFRRUZCUUFEUVFCSmxmZkpIeWJqREd4Uk1xYVJtRGhYMCs2djAyVFVLWnNXCnI1UXVWYnBRaEg2dSswVWdjVzBqcDlRd3B4b1BUTFRXR1hFV0JCQnVyeEZ3aUNCaGtRK1YKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="

	clientCert = `
-----BEGIN CERTIFICATE-----
MIID0DCCArigAwIBAgIBATANBgkqhkiG9w0BAQUFADB/MQswCQYDVQQGEwJGUjET
MBEGA1UECAwKU29tZS1TdGF0ZTEOMAwGA1UEBwwFUGFyaXMxDTALBgNVBAoMBERp
bWkxDTALBgNVBAsMBE5TQlUxEDAOBgNVBAMMB0RpbWkgQ0ExGzAZBgkqhkiG9w0B
CQEWDGRpbWlAZGltaS5mcjAeFw0xNDAxMjgyMDM2NTVaFw0yNDAxMjYyMDM2NTVa
MFsxCzAJBgNVBAYTAkZSMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJ
bnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxFDASBgNVBAMMC3d3dy5kaW1pLmZyMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvpnaPKLIKdvx98KW68lz8pGa
RRcYersNGqPjpifMVjjE8LuCoXgPU0HePnNTUjpShBnynKCvrtWhN+haKbSp+QWX
SxiTrW99HBfAl1MDQyWcukoEb9Cw6INctVUN4iRvkn9T8E6q174RbcnwA/7yTc7p
1NCvw+6B/aAN9l1G2pQXgRdYC/+G6o1IZEHtWhqzE97nY5QKNuUVD0V09dc5CDYB
aKjqetwwv6DFk/GRdOSEd/6bW+20z0qSHpa3YNW6qSp+x5pyYmDrzRIR03os6Dau
ZkChSRyc/Whvurx6o85D6qpzywo8xwNaLZHxTQPgcIA5su9ZIytv9LH2E+lSwwID
AQABo3sweTAJBgNVHRMEAjAAMCwGCWCGSAGG+EIBDQQfFh1PcGVuU1NMIEdlbmVy
YXRlZCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQU+tugFtyN+cXe1wxUqeA7X+yS3bgw
HwYDVR0jBBgwFoAUhMwqkbBrGp87HxfvwgPnlGgVR64wDQYJKoZIhvcNAQEFBQAD
ggEBAIEEmqqhEzeXZ4CKhE5UM9vCKzkj5Iv9TFs/a9CcQuepzplt7YVmevBFNOc0
+1ZyR4tXgi4+5MHGzhYCIVvHo4hKqYm+J+o5mwQInf1qoAHuO7CLD3WNa1sKcVUV
vepIxc/1aHZrG+dPeEHt0MdFfOw13YdUc2FH6AqEdcEL4aV5PXq2eYR8hR4zKbc1
fBtuqUsvA8NWSIyzQ16fyGve+ANf6vXvUizyvwDrPRv/kfvLNa3ZPnLMMxU98Mvh
PXy3PkB8++6U4Y3vdk2Ni2WYYlIls8yqbM4327IKmkDc2TimS8u60CT47mKU7aDY
cbTV5RDkrlaYwm5yqlTIglvCv7o=
-----END CERTIFICATE-----
`

	clientKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAvpnaPKLIKdvx98KW68lz8pGaRRcYersNGqPjpifMVjjE8LuC
oXgPU0HePnNTUjpShBnynKCvrtWhN+haKbSp+QWXSxiTrW99HBfAl1MDQyWcukoE
b9Cw6INctVUN4iRvkn9T8E6q174RbcnwA/7yTc7p1NCvw+6B/aAN9l1G2pQXgRdY
C/+G6o1IZEHtWhqzE97nY5QKNuUVD0V09dc5CDYBaKjqetwwv6DFk/GRdOSEd/6b
W+20z0qSHpa3YNW6qSp+x5pyYmDrzRIR03os6DauZkChSRyc/Whvurx6o85D6qpz
ywo8xwNaLZHxTQPgcIA5su9ZIytv9LH2E+lSwwIDAQABAoIBAFml8cD9a5pMqlW3
f9btTQz1sRL4Fvp7CmHSXhvjsjeHwhHckEe0ObkWTRsgkTsm1XLu5W8IITnhn0+1
iNr+78eB+rRGngdAXh8diOdkEy+8/Cee8tFI3jyutKdRlxMbwiKsouVviumoq3fx
OGQYwQ0Z2l/PvCwy/Y82ffq3ysC5gAJsbBYsCrg14bQo44ulrELe4SDWs5HCjKYb
EI2b8cOMucqZSOtxg9niLN/je2bo/I2HGSawibgcOdBms8k6TvsSrZMr3kJ5O6J+
77LGwKH37brVgbVYvbq6nWPL0xLG7dUv+7LWEo5qQaPy6aXb/zbckqLqu6/EjOVe
ydG5JQECgYEA9kKfTZD/WEVAreA0dzfeJRu8vlnwoagL7cJaoDxqXos4mcr5mPDT
kbWgFkLFFH/AyUnPBlK6BcJp1XK67B13ETUa3i9Q5t1WuZEobiKKBLFm9DDQJt43
uKZWJxBKFGSvFrYPtGZst719mZVcPct2CzPjEgN3Hlpt6fyw3eOrnoECgYEAxiOu
jwXCOmuGaB7+OW2tR0PGEzbvVlEGdkAJ6TC/HoKM1A8r2u4hLTEJJCrLLTfw++4I
ddHE2dLeR4Q7O58SfLphwgPmLDezN7WRLGr7Vyfuv7VmaHjGuC3Gv9agnhWDlA2Q
gBG9/R9oVfL0Dc7CgJgLeUtItCYC31bGT3yhV0MCgYEA4k3DG4L+RN4PXDpHvK9I
pA1jXAJHEifeHnaW1d3vWkbSkvJmgVf+9U5VeV+OwRHN1qzPZV4suRI6M/8lK8rA
Gr4UnM4aqK4K/qkY4G05LKrik9Ev2CgqSLQDRA7CJQ+Jn3Nb50qg6hFnFPafN+J7
7juWln08wFYV4Atpdd+9XQECgYBxizkZFL+9IqkfOcONvWAzGo+Dq1N0L3J4iTIk
w56CKWXyj88d4qB4eUU3yJ4uB4S9miaW/eLEwKZIbWpUPFAn0db7i6h3ZmP5ZL8Q
qS3nQCb9DULmU2/tU641eRUKAmIoka1g9sndKAZuWo+o6fdkIb1RgObk9XNn8R4r
psv+aQKBgB+CIcExR30vycv5bnZN9EFlIXNKaeMJUrYCXcRQNvrnUIUBvAO8+jAe
CdLygS5RtgOLZib0IVErqWsP3EI1ACGuLts0vQ9GFLQGaN1SaMS40C9kvns1mlDu
LhIhYpJ8UsCVt5snWo2N+M+6ANh5tpWdQnEK6zILh4tRbuzaiHgb
-----END RSA PRIVATE KEY-----
`
)

func TestDriver_Query(t *testing.T) {
	d, err := New()
	if err != nil {
		t.Fatal(err)
	}

	tmpl := cts.New(cts.OptTargets(cts.Target(cts.MockTargetHandler, AlwaysViolate)))
	ctx := context.Background()

	if err := d.AddTemplate(ctx, tmpl); err != nil {
		t.Fatalf("got AddTemplate() error = %v, want %v", err, nil)
	}

	if err := d.AddConstraint(ctx, cts.MakeConstraint(t, "Fakes", "foo-1")); err != nil {
		t.Fatalf("got AddConstraint() error = %v, want %v", err, nil)
	}

	res, _, err := d.Query(
		ctx,
		cts.MockTargetHandler,
		[]*unstructured.Unstructured{cts.MakeConstraint(t, "Fakes", "foo-1")},
		map[string]interface{}{"hi": "there"},
	)
	if err != nil {
		t.Fatalf("got Query() error = %v, want %v", err, nil)
	}
	if len(res) == 0 {
		t.Fatalf("got 0 errors on normal query; want 1")
	}

	// Remove data to make sure our rego hook is well-behaved when
	// there is no external data root
	if err := d.RemoveData(ctx, cts.MockTargetHandler, nil); err != nil {
		t.Fatalf("got RemoveData() error = %v, want %v", err, nil)
	}

	res, _, err = d.Query(
		ctx,
		cts.MockTargetHandler,
		[]*unstructured.Unstructured{cts.MakeConstraint(t, "Fakes", "foo-1")},
		map[string]interface{}{"hi": "there"},
	)
	if err != nil {
		t.Fatalf("got Query() (#2) error = %v, want %v", err, nil)
	}
	if len(res) == 0 {
		t.Fatalf("got 0 errors on data-less query; want 1")
	}

	stats, ok := res[0].EvaluationMeta.(EvaluationMeta)
	if !ok {
		t.Fatalf("could not type convert to RegoEvaluationMeta")
	}

	if stats.TemplateRunTime == 0 {
		t.Fatalf("expected %v's value to be positive was zero", "TemplateRunTime")
	}

	if stats.ConstraintCount != uint(1) {
		t.Fatalf("expected %v constraint count, got %v", 1, "ConstraintCount")
	}
}

func TestDriver_ExternalData(t *testing.T) {
	for _, tt := range []struct {
		name                  string
		provider              *unversioned.Provider
		clientCertContent     string
		clientKeyContent      string
		sendRequestToProvider externaldata.SendRequestToProvider
		errorExpected         bool
	}{
		{
			name:              "provider not found",
			clientCertContent: clientCert,
			clientKeyContent:  clientKey,
			errorExpected:     true,
		},
		{
			name: "error from SendRequestToProvider",
			provider: &unversioned.Provider{
				ObjectMeta: metav1.ObjectMeta{
					Name: "dummy-provider",
				},
				Spec: unversioned.ProviderSpec{
					URL:      "https://example.com",
					Timeout:  1,
					CABundle: caBundle,
				},
			},
			clientCertContent: clientCert,
			clientKeyContent:  clientKey,
			sendRequestToProvider: func(ctx context.Context, provider *unversioned.Provider, keys []string, clientCert *tls.Certificate) (*externaldata.ProviderResponse, int, error) {
				return nil, http.StatusBadRequest, errors.New("error from SendRequestToProvider")
			},
			errorExpected: true,
		},
		{
			name: "valid response",
			provider: &unversioned.Provider{
				ObjectMeta: metav1.ObjectMeta{
					Name: "dummy-provider",
				},
				Spec: unversioned.ProviderSpec{
					URL:      "https://example.com",
					Timeout:  1,
					CABundle: caBundle,
				},
			},
			clientCertContent: clientCert,
			clientKeyContent:  clientKey,
			sendRequestToProvider: func(ctx context.Context, provider *unversioned.Provider, keys []string, clientCert *tls.Certificate) (*externaldata.ProviderResponse, int, error) {
				return &externaldata.ProviderResponse{
					APIVersion: "v1beta1",
					Kind:       "Provider",
					Response: externaldata.Response{
						Idempotent: true,
						Items: []externaldata.Item{
							{
								Key:   "key",
								Value: "key_valid",
							},
						},
					},
				}, http.StatusOK, nil
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			clientCertFile, err := os.CreateTemp("", "client-cert")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(clientCertFile.Name())

			_, _ = clientCertFile.WriteString(tt.clientCertContent)
			clientCertFile.Close()

			clientKeyFile, err := os.CreateTemp("", "client-key")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(clientKeyFile.Name())

			_, _ = clientKeyFile.WriteString(tt.clientKeyContent)
			clientKeyFile.Close()

			clientCertWatcher, err := certwatcher.New(clientCertFile.Name(), clientKeyFile.Name())
			if err != nil {
				t.Fatal(err)
			}

			go func() {
				_ = clientCertWatcher.Start(ctx)
			}()

			d, err := New(
				AddExternalDataProviderCache(externaldata.NewCache()),
				EnableExternalDataClientAuth(),
				AddExternalDataClientCertWatcher(clientCertWatcher),
			)
			if err != nil {
				t.Fatal(err)
			}

			if tt.provider != nil {
				if err := d.providerCache.Upsert(tt.provider); err != nil {
					t.Fatal(err)
				}
			}

			if tt.sendRequestToProvider != nil {
				d.sendRequestToProvider = tt.sendRequestToProvider
			}

			tmpl := cts.New(cts.OptTargets(cts.Target(cts.MockTargetHandler, ExternalData)))

			if err := d.AddTemplate(ctx, tmpl); err != nil {
				t.Fatalf("got AddTemplate() error = %v, want %v", err, nil)
			}

			if err := d.AddConstraint(ctx, cts.MakeConstraint(t, "Fakes", "foo-1")); err != nil {
				t.Fatalf("got AddConstraint() error = %v, want %v", err, nil)
			}

			res, _, err := d.Query(
				ctx,
				cts.MockTargetHandler,
				[]*unstructured.Unstructured{cts.MakeConstraint(t, "Fakes", "foo-1")},
				map[string]interface{}{"hi": "there"},
			)
			if err != nil {
				t.Fatalf("got Query() error = %v, want %v", err, nil)
			}
			if tt.errorExpected && len(res) == 0 {
				t.Fatalf("got 0 errors on normal query; want 1")
			}
			if !tt.errorExpected && len(res) > 0 {
				t.Fatalf("got %d errors on normal query; want 0", len(res))
			}
		})
	}
}

func TestDriver_AddTemplate(t *testing.T) {
	testCases := []struct {
		name          string
		rego          string
		targetHandler string
		externs       []string

		wantErr       error
		wantCompilers map[string][]string
	}{
		{
			name:          "no target",
			wantErr:       clienterrors.ErrInvalidConstraintTemplate,
			wantCompilers: map[string][]string{},
		},
		{
			name:          "rego missing violation",
			targetHandler: cts.MockTargetHandler,
			rego:          Module,
			wantErr:       clienterrors.ErrInvalidConstraintTemplate,
			wantCompilers: map[string][]string{},
		},
		{
			name:          "valid template",
			targetHandler: cts.MockTargetHandler,
			rego: `
package something

violation[{"msg": "msg"}] {
  msg := "always"
}
`,
			wantCompilers: map[string][]string{"foo": {"Fakes"}},
		},
		{
			name:          "inventory disallowed template",
			targetHandler: cts.MockTargetHandler,
			rego: `package something

violation[{"msg": "msg"}] {
	data.inventory = "something_else"
}`,
			wantErr: clienterrors.ErrInvalidConstraintTemplate,
		},
		{
			name:          "inventory allowed template",
			targetHandler: cts.MockTargetHandler,
			rego: `package something

violation[{"msg": "msg"}] {
	data.inventory = "something_else"
}`,
			externs:       []string{"inventory"},
			wantErr:       nil,
			wantCompilers: map[string][]string{"foo": {"Fakes"}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := New(Externs(tc.externs...))
			if err != nil {
				t.Fatal(err)
			}

			tmpl := cts.New(cts.OptTargets(cts.Target(tc.targetHandler, tc.rego)))
			ctx := context.Background()

			gotErr := d.AddTemplate(ctx, tmpl)
			if !errors.Is(gotErr, tc.wantErr) {
				t.Fatalf("got AddTemplate() error = %v, want %v", gotErr, tc.wantErr)
			}

			gotCompilers := listCompilers(d)

			if diff := cmp.Diff(tc.wantCompilers, gotCompilers, cmpopts.EquateEmpty()); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func listCompilers(d *Driver) map[string][]string {
	gotCompilers := make(map[string][]string)

	for target, targetCompilers := range d.compilers.list() {
		for kind := range targetCompilers {
			gotCompilers[target] = append(gotCompilers[target], kind)
		}
		sort.Strings(gotCompilers[target])
	}

	return gotCompilers
}

func TestDriver_RemoveTemplates(t *testing.T) {
	testCases := []struct {
		name          string
		rego          string
		targetHandler string
		externs       []string
		wantErr       error
	}{
		{
			name:          "valid template",
			targetHandler: cts.MockTargetHandler,
			rego: `
package something

violation[{"msg": msg}] {msg := "always"}`,
		},
		{
			name:          "inventory allowed template",
			targetHandler: cts.MockTargetHandler,
			rego: `package something

violation[{"msg": "msg"}] {
	data.inventory = "something_else"
}`,
			externs: []string{"inventory"},
			wantErr: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := New(Externs(tc.externs...))
			if err != nil {
				t.Fatal(err)
			}

			tmpl := cts.New(cts.OptTargets(cts.Target(tc.targetHandler, tc.rego)))
			ctx := context.Background()

			gotErr := d.AddTemplate(ctx, tmpl)
			if !errors.Is(gotErr, tc.wantErr) {
				t.Fatalf("got AddTemplate() error = %v, want %v", gotErr, tc.wantErr)
			}

			if len(d.compilers.list()) == 0 {
				t.Errorf("driver failed to add module")
			}

			gotErr = d.RemoveTemplate(ctx, tmpl)
			if gotErr != nil {
				t.Errorf("err = %v; want nil", gotErr)
			}

			gotCompilers := listCompilers(d)
			wantCompilers := map[string][]string{}

			if diff := cmp.Diff(wantCompilers, gotCompilers); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestDriver_AddData(t *testing.T) {
	testCases := []struct {
		name        string
		beforePath  []string
		beforeValue interface{}
		path        []string
		value       interface{}

		wantErr error
	}{
		{
			name:  "valid to overwrite root inventory",
			path:  []string{},
			value: map[string]interface{}{},

			wantErr: nil,
		},
		{
			name:  "valid write",
			path:  []string{"foo"},
			value: map[string]interface{}{"foo": "bar"},

			wantErr: nil,
		},
		{
			name:        "valid overwrite",
			beforePath:  []string{"foo"},
			beforeValue: map[string]interface{}{"foo": "bar"},
			path:        []string{"foo"},
			value:       map[string]interface{}{"foo": "qux"},

			wantErr: nil,
		},
		{
			name:        "write to subdirectory of existing data",
			beforePath:  []string{"foo"},
			beforeValue: map[string]interface{}{"foo": "bar"},
			path:        []string{"foo", "bar"},
			value:       map[string]interface{}{"foo": "qux"},

			wantErr: nil,
		},
		{
			name:        "write to subdirectory of non-object",
			beforePath:  []string{"foo"},
			beforeValue: "bar",
			path:        []string{"foo", "bar"},
			value:       map[string]interface{}{"foo": "qux"},

			wantErr: clienterrors.ErrWrite,
		},
		{
			name:        "write to parent directory of existing data",
			beforePath:  []string{"foo", "bar"},
			beforeValue: map[string]interface{}{"foo": "bar"},
			path:        []string{"foo"},
			value:       map[string]interface{}{"foo": "qux"},

			wantErr: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			s := inmem.New()
			d, err := New(Storage(map[string]storage.Store{handlertest.TargetName: s}))
			if err != nil {
				t.Fatal(err)
			}

			if tc.beforeValue != nil {
				err := d.AddData(ctx, handlertest.TargetName, tc.beforePath, tc.beforeValue)
				if err != nil {
					t.Fatalf("got setup AddData() error = %v, want %v", err, nil)
				}
			}

			err = d.AddData(ctx, handlertest.TargetName, tc.path, tc.value)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("got AddData() error = %v, want %v",
					err, tc.wantErr)
			}

			if errors.Is(tc.wantErr, clienterrors.ErrPathInvalid) {
				return
			}

			// Verify the state of data in storage.

			wantValue := tc.value
			wantPath := tc.path
			if tc.wantErr != nil {
				// We encountered an error writing data, so we expect the original data to be unchanged.
				wantPath = tc.beforePath
				wantValue = tc.beforeValue
			}

			txn, err := s.NewTransaction(ctx)
			if err != nil {
				t.Fatal(err)
			}

			gotValue, err := s.Read(ctx, txn, inventoryPath(wantPath))
			if err != nil {
				t.Fatalf("got fakeStorage.Read() error = %v, want %v", err, nil)
			}

			err = s.Commit(ctx, txn)
			if err != nil {
				t.Fatal(err)
			}

			if diff := cmp.Diff(wantValue, gotValue); diff != "" {
				t.Errorf("read data did not equal expected (-want, +got): %v", diff)
			}
		})
	}
}

func TestDriver_AddData_StorageErrors(t *testing.T) {
	testCases := []struct {
		name    string
		storage storage.Store

		wantErr error
	}{
		{
			name:    "success",
			storage: &fakeStorage{},
			wantErr: nil,
		},
		{
			name:    "transaction error",
			storage: &transactionErrorStorage{},
			wantErr: clienterrors.ErrTransaction,
		},
		{
			name:    "read error",
			storage: &readErrorStorage{},
			wantErr: clienterrors.ErrRead,
		},
		{
			name:    "write error",
			storage: &writeErrorStorage{},
			wantErr: clienterrors.ErrWrite,
		},
		{
			name:    "commit error",
			storage: &commitErrorStorage{},
			wantErr: clienterrors.ErrTransaction,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			d, err := New(Storage(map[string]storage.Store{handlertest.TargetName: tc.storage}))
			if err != nil {
				t.Fatal(err)
			}

			path := []string{"foo"}
			value := map[string]string{"bar": "qux"}
			err = d.AddData(ctx, handlertest.TargetName, path, value)

			if !errors.Is(err, tc.wantErr) {
				t.Errorf("got AddData() error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestDriver_RemoveData(t *testing.T) {
	testCases := []struct {
		name        string
		beforePath  []string
		beforeValue interface{}
		path        []string

		wantDeleted bool
		wantErr     error
	}{
		{
			name:        "can delete inventory root",
			beforePath:  []string{"foo"},
			beforeValue: "bar",
			path:        []string{},

			wantDeleted: true,
			wantErr:     nil,
		},
		{
			name:        "success",
			beforePath:  []string{"foo"},
			beforeValue: "bar",
			path:        []string{"foo"},

			wantDeleted: true,
			wantErr:     nil,
		},
		{
			name:        "non existent",
			beforePath:  []string{"foo"},
			beforeValue: "bar",
			path:        []string{"qux"},

			wantDeleted: false,
			wantErr:     nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			s := inmem.New()
			d, err := New(Storage(map[string]storage.Store{handlertest.TargetName: s}))
			if err != nil {
				t.Fatal(err)
			}

			err = d.AddData(ctx, handlertest.TargetName, tc.beforePath, tc.beforeValue)
			if err != nil {
				t.Fatalf("got setup AddData() error = %v, want %v", err, nil)
			}

			err = d.RemoveData(ctx, handlertest.TargetName, tc.path)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("got RemoveData() error = %v, want %v", err, tc.wantErr)
			}

			var wantValue interface{}
			if !tc.wantDeleted {
				wantValue = tc.beforeValue
			}

			txn, err := s.NewTransaction(ctx)
			if err != nil {
				t.Fatal(err)
			}

			gotValue, err := s.Read(ctx, txn, inventoryPath(tc.beforePath))
			if tc.wantDeleted {
				if !storage.IsNotFound(err) {
					t.Fatalf("got err %v, want not found", err)
				}
				return
			}

			if err != nil {
				t.Fatal(err)
			}

			err = s.Commit(ctx, txn)
			if err != nil {
				t.Fatal(err)
			}

			if diff := cmp.Diff(wantValue, gotValue); diff != "" {
				t.Errorf(diff)
			}
		})
	}
}

func TestDriver_RemoveData_StorageErrors(t *testing.T) {
	testCases := []struct {
		name    string
		storage storage.Store

		wantErr error
	}{
		{
			name:    "success",
			storage: &fakeStorage{},
			wantErr: nil,
		},
		{
			name:    "transaction error",
			storage: &transactionErrorStorage{},
			wantErr: clienterrors.ErrTransaction,
		},
		{
			name:    "write error",
			storage: &writeErrorStorage{},
			wantErr: clienterrors.ErrWrite,
		},
		{
			name: "commit error",
			storage: &commitErrorStorage{
				fakeStorage: fakeStorage{values: map[string]interface{}{
					"/inventory/foo": "bar",
				}},
			},
			wantErr: clienterrors.ErrTransaction,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			d, err := New(Storage(map[string]storage.Store{handlertest.TargetName: tc.storage}))
			if err != nil {
				t.Fatal(err)
			}

			path := []string{"foo"}
			err = d.RemoveData(ctx, handlertest.TargetName, path)

			if !errors.Is(err, tc.wantErr) {
				t.Errorf("got RemoveData() error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestDriver_Externs_Intersection(t *testing.T) {
	tcs := []struct {
		name      string
		allowed   []Arg
		want      []string
		wantError error
	}{
		{
			name: "No Externs specified",
			want: []string{"data.inventory"},
		},
		{
			name:    "Empty Externs Used",
			allowed: []Arg{Externs()},
			want:    []string{},
		},
		{
			name:    "Inventory Used",
			allowed: []Arg{Externs("inventory")},
			want:    []string{"data.inventory"},
		},
		{
			name:      "Invalid Data Field",
			allowed:   []Arg{Externs("no_overlap")},
			want:      []string{},
			wantError: clienterrors.ErrCreatingDriver,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			d, err := New(tc.allowed...)
			if !errors.Is(err, tc.wantError) {
				t.Fatalf("got NewClient() error = %v, want %v",
					err, tc.wantError)
			}

			if tc.wantError != nil {
				return
			}

			if diff := cmp.Diff(tc.want, d.compilers.externs); diff != "" {
				t.Error(diff)
			}
		})
	}
}

type fakeStorage struct {
	storage.Store

	policies map[string][]byte
	values   map[string]interface{}
}

var _ storage.Store = &fakeStorage{}

func (s *fakeStorage) UpsertPolicy(_ context.Context, _ storage.Transaction, name string, bytes []byte) error {
	if s.policies == nil {
		s.policies = make(map[string][]byte)
	}

	s.policies[name] = bytes

	return nil
}

func (s *fakeStorage) DeletePolicy(_ context.Context, _ storage.Transaction, name string) error {
	delete(s.policies, name)

	return nil
}

func (s *fakeStorage) NewTransaction(_ context.Context, _ ...storage.TransactionParams) (storage.Transaction, error) {
	return nil, nil
}

func (s *fakeStorage) Read(_ context.Context, _ storage.Transaction, path storage.Path) (interface{}, error) {
	value, found := s.values[path.String()]
	if !found {
		return nil, &storage.Error{Code: storage.NotFoundErr}
	}

	return value, nil
}

func (s *fakeStorage) Write(_ context.Context, _ storage.Transaction, _ storage.PatchOp, path storage.Path, value interface{}) error {
	if s.values == nil {
		s.values = make(map[string]interface{})
	}

	if value == nil && s.values[path.String()] == nil {
		return &storage.Error{Code: storage.NotFoundErr}
	}

	s.values[path.String()] = value

	return nil
}

func (s *fakeStorage) Commit(_ context.Context, _ storage.Transaction) error {
	return nil
}

func (s *fakeStorage) Abort(_ context.Context, _ storage.Transaction) {}

type transactionErrorStorage struct {
	fakeStorage
}

func (s *transactionErrorStorage) NewTransaction(_ context.Context, _ ...storage.TransactionParams) (storage.Transaction, error) {
	return nil, errors.New("error making new transaction")
}

type commitErrorStorage struct {
	fakeStorage
}

func (s *commitErrorStorage) Commit(_ context.Context, _ storage.Transaction) error {
	return errors.New("error committing changes")
}

type writeErrorStorage struct {
	fakeStorage
}

func (s *writeErrorStorage) Write(_ context.Context, _ storage.Transaction, _ storage.PatchOp, _ storage.Path, _ interface{}) error {
	return errors.New("error writing data")
}

type readErrorStorage struct {
	fakeStorage
}

func (s *readErrorStorage) Read(_ context.Context, _ storage.Transaction, _ storage.Path) (interface{}, error) {
	return nil, errors.New("error writing data")
}

func TestDriver_AddConstraint(t *testing.T) {
	tests := []struct {
		name             string
		beforeConstraint *unstructured.Unstructured
		constraint       *unstructured.Unstructured
		wantParameters   map[string]interface{}
		wantError        error
	}{
		{
			name: "add constraint",
			constraint: cts.MakeConstraint(t, "Foo", "foo-1",
				cts.WantData("bar")),
			wantParameters: map[string]interface{}{
				"wantData": "bar",
			},
		},
		{
			name: "nil parameters",
			constraint: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"kind": "Foo",
					"metadata": map[string]interface{}{
						"name": "foo-1",
					},
					"spec": map[string]interface{}{
						"parameters": nil,
					},
				},
			},
			wantParameters: map[string]interface{}{},
		},
		{
			name: "invalid parameters",
			constraint: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"kind": "Foo",
					"metadata": map[string]interface{}{
						"name": "foo-1",
					},
					"spec": "invalid",
				},
			},
			wantParameters: nil,
			wantError:      constraints.ErrInvalidConstraint,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := New()
			if err != nil {
				t.Fatal(err)
			}

			ctx := context.Background()
			beforeTemplate := cts.New(cts.OptName("foo"), cts.OptCRDNames("Foo"))
			err = d.AddTemplate(ctx, beforeTemplate)
			if err != nil {
				t.Fatal(err)
			}

			if tt.beforeConstraint != nil {
				err = d.AddConstraint(ctx, tt.beforeConstraint)
				if err != nil {
					t.Fatal(err)
				}
			}

			err = d.AddConstraint(ctx, tt.constraint)
			if !errors.Is(err, tt.wantError) {
				t.Fatalf("got AddConstraint error = %v, want %v",
					err, tt.wantError)
			}

			compiler := ast.NewCompiler()
			module, err := ast.ParseModule("", `package foo`)
			if err != nil {
				t.Fatal(err)
			}
			compiler.Compile(map[string]*ast.Module{
				"foo": module,
			})

			key := fmt.Sprintf("%s[%q]", tt.constraint.GetKind(), tt.constraint.GetName())

			result, _, err := d.eval(ctx, compiler, handlertest.TargetName, []string{"constraints", key}, nil)
			if err != nil {
				t.Fatal(err)
			}

			if tt.wantParameters == nil {
				if len(result) != 0 {
					t.Fatalf("want no parameters stored but got %+v", result)
				}
				return
			}

			gotParameters := result[0].Expressions[0].Value

			if diff := cmp.Diff(tt.wantParameters, gotParameters); diff != "" {
				t.Fatal(diff)
			}

			err = d.RemoveConstraint(ctx, tt.constraint)
			if err != nil {
				t.Fatal(err)
			}

			result2, _, err := d.eval(ctx, compiler, handlertest.TargetName, []string{"constraints", key}, nil)
			if err != nil {
				t.Fatal(err)
			}

			if len(result2) != 0 {
				t.Fatalf("want no parameters stored after deletion but got %+v", result)
			}
		})
	}
}
