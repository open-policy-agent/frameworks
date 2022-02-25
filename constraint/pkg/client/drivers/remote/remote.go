package remote

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	"github.com/open-policy-agent/opa/storage"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type Arg func(*inits)

type inits struct {
	url          string
	opaCAs       *x509.CertPool
	auth         string
	traceEnabled bool
}

func URL(url string) Arg {
	return func(i *inits) {
		i.url = url
	}
}

func OpaCA(ca *x509.CertPool) Arg {
	return func(i *inits) {
		i.opaCAs = ca
	}
}

func Auth(auth string) Arg {
	return func(i *inits) {
		i.auth = auth
	}
}

func Tracing(enabled bool) Arg {
	return func(i *inits) {
		i.traceEnabled = enabled
	}
}

func New(args ...Arg) (drivers.Driver, error) {
	i := &inits{}
	for _, arg := range args {
		arg(i)
	}
	if i.url == "" {
		return nil, errors.New("missing URL for OPA")
	}
	return &driver{opa: newHTTPClient(i.url, i.opaCAs, i.auth), traceEnabled: i.traceEnabled}, nil
}

var _ drivers.Driver = &driver{}

type driver struct {
	opa          client
	traceEnabled bool
}

func (d *driver) Init() error {
	return nil
}

// Re-add once there is an implementation for Query.
// func (d *driver) addTrace(path string) string {
//	return path + "?explain=full&pretty=true"
// }

func (d *driver) PutModule(name string, src string) error {
	return d.opa.InsertPolicy(name, []byte(src))
}

// DeleteModule deletes a rule from OPA and returns true if a rule was found and deleted, false
// if a rule was not found, and any errors.
func (d *driver) DeleteModule(name string) (bool, error) {
	err := d.opa.DeletePolicy(name)
	if err != nil {
		e := &Error{}
		if errors.As(err, &e) {
			if e.Status == 404 {
				return false, nil
			}
		}
	}
	return err == nil, err
}

// AddTemplate implements drivers.Driver.
func (d *driver) AddTemplate(ct *templates.ConstraintTemplate) error {
	panic("not implemented")
}

// RemoveTemplate implements driver.Driver.
func (d *driver) RemoveTemplate(ctx context.Context, ct *templates.ConstraintTemplate) error {
	panic("not implemented")
}

func (d *driver) AddConstraint(ctx context.Context, constraint *unstructured.Unstructured) error {
	panic("not implemented")
}

func (d *driver) RemoveConstraint(ctx context.Context, constraint *unstructured.Unstructured) error {
	panic("not implemented")
}

func (d *driver) AddData(_ context.Context, path storage.Path, data interface{}) error {
	return d.opa.PutData(path.String(), data)
}

// RemoveData deletes data from OPA and returns true if data was found and deleted, false
// if data was not found, and any errors.
func (d *driver) RemoveData(_ context.Context, path storage.Path) (bool, error) {
	err := d.opa.DeleteData(path.String())
	if err != nil {
		e := &Error{}
		if errors.As(err, &e) {
			if e.Status == 404 {
				return false, nil
			}
		}
	}
	return err == nil, err
}

// makeURLPath takes a path of the form data.foo["bar.baz"].yes and converts it to an URI path
// such as /data/foo/bar.baz/yes.
func makeURLPath(path string) (string, error) {
	var pieces []string
	quoted := false
	openBracket := false
	builder := &strings.Builder{}
	for _, chr := range path {
		ch := string(chr)
		if !quoted {
			if ch == "." {
				pieces = append(pieces, builder.String())
				builder.Reset()
				continue
			}
			if ch == "[" {
				if !openBracket {
					openBracket = true
					pieces = append(pieces, builder.String())
					builder.Reset()
					continue
				} else {
					return "", fmt.Errorf("mismatched bracketing: %q", path)
				}
			}
			if ch == "]" {
				if openBracket {
					openBracket = false
					continue
				} else {
					return "", fmt.Errorf("mismatched bracketing: %q", path)
				}
			}
		}
		if ch == `"` {
			quoted = !quoted
			continue
		}
		_, _ = fmt.Fprint(builder, ch)
	}
	pieces = append(pieces, builder.String())

	return strings.Join(pieces, "/"), nil
}

func (d *driver) Query(ctx context.Context, target string, constraints []*unstructured.Unstructured, review interface{}, opts ...drivers.QueryOpt) ([]*types.Result, *string, error) {
	return nil, nil, nil
}

func (d *driver) Dump(_ context.Context) (string, error) {
	response, err := d.opa.Query("", nil)
	if err != nil {
		return "", err
	}
	resp := make(map[string]interface{})
	resp["data"] = response.Result

	polResponse, err := d.opa.ListPolicies()
	if err != nil {
		return "", err
	}
	pols := make([]map[string]interface{}, 0)
	err = json.Unmarshal(polResponse.Result, &pols)
	if err != nil {
		return "", err
	}
	policies := make(map[string]string)
	for _, v := range pols {
		id, ok := v["id"]
		raw, ok2 := v["raw"]
		ids, ok3 := id.(string)
		raws, ok4 := raw.(string)
		if ok && ok2 && ok3 && ok4 {
			p, err := url.PathUnescape(ids)
			if err != nil {
				return "", err
			}
			policies[p] = raws
		}
	}
	resp["modules"] = policies
	b, err := json.MarshalIndent(resp, "", "   ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
