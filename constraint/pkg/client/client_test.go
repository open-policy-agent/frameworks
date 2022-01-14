package client_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"text/template"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/clienttest"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/clienttest/cts"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/crds"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/local"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/constraints"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/utils/pointer"
)

const badRego = `asd{`

var _ client.TargetHandler = &badHandler{}

type badHandler struct {
	Name        string
	Errors      bool
	HasLib      bool
	HandlesData bool
}

func (h *badHandler) ToMatcher(_ *unstructured.Unstructured) (constraints.Matcher, error) {
	return nil, errors.New("unimplemented")
}

func (h *badHandler) GetName() string {
	return h.Name
}

func (h *badHandler) Library() *template.Template {
	if !h.HasLib {
		return nil
	}
	return template.Must(template.New("foo").Parse(`
package foo
autoreject_review[r] {r = data.r}
matching_constraints[c] {c = data.c}
matching_reviews_and_constraints[[r,c]] {r = data.r; c = data.c}`))
}

func (h *badHandler) MatchSchema() apiextensions.JSONSchemaProps {
	return apiextensions.JSONSchemaProps{XPreserveUnknownFields: pointer.Bool(true)}
}

func (h *badHandler) ProcessData(_ interface{}) (bool, string, interface{}, error) {
	if h.Errors {
		return false, "", nil, errors.New("some error")
	}
	if !h.HandlesData {
		return false, "", nil, nil
	}
	return true, "projects/something", nil, nil
}

func (h *badHandler) HandleReview(_ interface{}) (bool, interface{}, error) {
	return false, "", nil
}

func (h *badHandler) HandleViolation(_ *types.Result) error {
	return nil
}

func (h *badHandler) ValidateConstraint(_ *unstructured.Unstructured) error {
	return nil
}

func TestBackend_NewClient_InvalidTargetName(t *testing.T) {
	tcs := []struct {
		name      string
		handler   client.TargetHandler
		wantError error
	}{
		{
			name:      "Acceptable name",
			handler:   &badHandler{Name: "Hello8", HasLib: true},
			wantError: nil,
		},
		{
			name:      "No name",
			handler:   &badHandler{Name: ""},
			wantError: client.ErrCreatingClient,
		},
		{
			name:      "Dots not allowed",
			handler:   &badHandler{Name: "asdf.asdf"},
			wantError: client.ErrCreatingClient,
		},
		{
			name:      "Spaces not allowed",
			handler:   &badHandler{Name: "asdf asdf"},
			wantError: client.ErrCreatingClient,
		},
		{
			name:      "Must start with a letter",
			handler:   &badHandler{Name: "8asdf"},
			wantError: client.ErrCreatingClient,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			d := local.New()

			b, err := client.NewBackend(client.Driver(d))
			if err != nil {
				t.Fatalf("Could not create backend: %s", err)
			}

			_, err = b.NewClient(client.Targets(tc.handler))
			if !errors.Is(err, tc.wantError) {
				t.Errorf("got NewClient() error = %v, want %v",
					err, tc.wantError)
			}
		})
	}
}

func TestClient_AddData(t *testing.T) {
	tcs := []struct {
		name        string
		handler1    client.TargetHandler
		handler2    client.TargetHandler
		wantHandled map[string]bool
		wantError   map[string]bool
	}{
		{
			name:        "Handled By Both",
			handler1:    &badHandler{Name: "h1", HasLib: true, HandlesData: true},
			handler2:    &badHandler{Name: "h2", HasLib: true, HandlesData: true},
			wantHandled: map[string]bool{"h1": true, "h2": true},
			wantError:   nil,
		},
		{
			name:        "Handled By One",
			handler1:    &badHandler{Name: "h1", HasLib: true, HandlesData: true},
			handler2:    &badHandler{Name: "h2", HasLib: true, HandlesData: false},
			wantHandled: map[string]bool{"h1": true},
			wantError:   nil,
		},
		{
			name:        "Errored By One",
			handler1:    &badHandler{Name: "h1", HasLib: true, HandlesData: true},
			handler2:    &badHandler{Name: "h2", HasLib: true, HandlesData: true, Errors: true},
			wantHandled: map[string]bool{"h1": true},
			wantError:   map[string]bool{"h2": true},
		},
		{
			name:      "Errored By Both",
			handler1:  &badHandler{Name: "h1", HasLib: true, HandlesData: true, Errors: true},
			handler2:  &badHandler{Name: "h2", HasLib: true, HandlesData: true, Errors: true},
			wantError: map[string]bool{"h1": true, "h2": true},
		},
		{
			name:        "Handled By None",
			handler1:    &badHandler{Name: "h1", HasLib: true, HandlesData: false},
			handler2:    &badHandler{Name: "h2", HasLib: true, HandlesData: false},
			wantHandled: nil,
			wantError:   nil,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			d := local.New()

			b, err := client.NewBackend(client.Driver(d))
			if err != nil {
				t.Fatalf("Could not create backend: %s", err)
			}

			c, err := b.NewClient(client.Targets(tc.handler1, tc.handler2))
			if err != nil {
				t.Fatal(err)
			}

			r, err := c.AddData(context.Background(), nil)
			if err != nil && len(tc.wantError) == 0 {
				t.Fatalf("err = %s; want nil", err)
			}

			gotErrs := make(map[string]bool)
			if e, ok := err.(*client.ErrorMap); ok {
				for k := range *e {
					gotErrs[k] = true
				}
			}

			if diff := cmp.Diff(tc.wantError, gotErrs, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf(diff)
			}

			if r == nil {
				t.Fatal("got AddTemplate() == nil, want non-nil")
			}

			if diff := cmp.Diff(tc.wantHandled, r.Handled, cmpopts.EquateEmpty()); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestClient_RemoveData(t *testing.T) {
	tcs := []struct {
		name        string
		handler1    client.TargetHandler
		handler2    client.TargetHandler
		wantHandled map[string]bool
		wantError   map[string]bool
	}{
		{
			name:        "Handled By Both",
			handler1:    &badHandler{Name: "h1", HasLib: true, HandlesData: true},
			handler2:    &badHandler{Name: "h2", HasLib: true, HandlesData: true},
			wantHandled: map[string]bool{"h1": true, "h2": true},
			wantError:   nil,
		},
		{
			name:        "Handled By One",
			handler1:    &badHandler{Name: "h1", HasLib: true, HandlesData: true},
			handler2:    &badHandler{Name: "h2", HasLib: true, HandlesData: false},
			wantHandled: map[string]bool{"h1": true},
			wantError:   nil,
		},
		{
			name:        "Errored By One",
			handler1:    &badHandler{Name: "h1", HasLib: true, HandlesData: true},
			handler2:    &badHandler{Name: "h2", HasLib: true, HandlesData: true, Errors: true},
			wantHandled: map[string]bool{"h1": true},
			wantError:   map[string]bool{"h2": true},
		},
		{
			name:        "Errored By Both",
			handler1:    &badHandler{Name: "h1", HasLib: true, HandlesData: true, Errors: true},
			handler2:    &badHandler{Name: "h2", HasLib: true, HandlesData: true, Errors: true},
			wantHandled: nil,
			wantError:   map[string]bool{"h1": true, "h2": true},
		},
		{
			name:        "Handled By None",
			handler1:    &badHandler{Name: "h1", HasLib: true, HandlesData: false},
			handler2:    &badHandler{Name: "h2", HasLib: true, HandlesData: false},
			wantHandled: nil,
			wantError:   nil,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			d := local.New()

			b, err := client.NewBackend(client.Driver(d))
			if err != nil {
				t.Fatalf("Could not create backend: %s", err)
			}

			c, err := b.NewClient(client.Targets(tc.handler1, tc.handler2))
			if err != nil {
				t.Fatal(err)
			}

			r, err := c.RemoveData(context.Background(), nil)
			if err != nil && len(tc.wantError) == 0 {
				t.Fatalf("err = %s; want nil", err)
			}

			gotErrs := make(map[string]bool)
			if e, ok := err.(*client.ErrorMap); ok {
				for k := range *e {
					gotErrs[k] = true
				}
			}

			if diff := cmp.Diff(tc.wantError, gotErrs, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf(diff)
			}

			if r == nil {
				t.Fatal("got RemoveData() == nil, want non-nil")
			}

			if diff := cmp.Diff(tc.wantHandled, r.Handled, cmpopts.EquateEmpty()); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestClient_AddTemplate(t *testing.T) {
	badRegoTempl := cts.New(cts.OptName("fake"), cts.OptCRDNames("Fake"), cts.OptTargets("h1"))
	badRegoTempl.Spec.Targets[0].Rego = badRego

	missingRuleTempl := cts.New(cts.OptName("fake"), cts.OptCRDNames("Fake"), cts.OptTargets("h1"))
	missingRuleTempl.Spec.Targets[0].Rego = `
package foo

some_rule[r] {
 r = 5
}
`
	emptyRegoTempl := cts.New(cts.OptName("fake"), cts.OptCRDNames("Fake"), cts.OptTargets("h1"))
	emptyRegoTempl.Spec.Targets[0].Rego = ""

	tcs := []struct {
		name        string
		handler     client.TargetHandler
		template    *templates.ConstraintTemplate
		wantHandled map[string]bool
		wantError   error
	}{
		{
			name:        "Good Template",
			handler:     &badHandler{Name: "h1", HasLib: true},
			template:    cts.New(cts.OptName("fakes"), cts.OptCRDNames("Fakes"), cts.OptTargets("h1")),
			wantHandled: map[string]bool{"h1": true},
			wantError:   nil,
		},
		{
			name:        "Unknown Target",
			handler:     &badHandler{Name: "h1", HasLib: true},
			template:    cts.New(cts.OptName("fake"), cts.OptCRDNames("Fake"), cts.OptTargets("h2")),
			wantHandled: nil,
			wantError:   local.ErrInvalidConstraintTemplate,
		},
		{
			name:        "Bad CRD",
			handler:     &badHandler{Name: "h1", HasLib: true},
			template:    cts.New(cts.OptName("fakes"), cts.OptTargets("h1")),
			wantHandled: nil,
			wantError:   local.ErrInvalidConstraintTemplate,
		},
		{
			name:        "No name",
			handler:     &badHandler{Name: "h1", HasLib: true},
			template:    cts.New(cts.OptCRDNames("Fake"), cts.OptTargets("h1")),
			wantHandled: nil,
			wantError:   local.ErrInvalidConstraintTemplate,
		},
		{
			name:        "Bad Rego",
			handler:     &badHandler{Name: "h1", HasLib: true},
			template:    badRegoTempl,
			wantHandled: nil,
			wantError:   local.ErrInvalidConstraintTemplate,
		},
		{
			name:        "No Rego",
			handler:     &badHandler{Name: "h1", HasLib: true},
			template:    emptyRegoTempl,
			wantHandled: nil,
			wantError:   local.ErrInvalidConstraintTemplate,
		},
		{
			name:        "Missing Rule",
			handler:     &badHandler{Name: "h1", HasLib: true},
			template:    missingRuleTempl,
			wantHandled: nil,
			wantError:   local.ErrInvalidConstraintTemplate,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			d := local.New()

			b, err := client.NewBackend(client.Driver(d))
			if err != nil {
				t.Fatalf("Could not create backend: %s", err)
			}

			c, err := b.NewClient(client.Targets(tc.handler))
			if err != nil {
				t.Fatal(err)
			}

			r, err := c.AddTemplate(tc.template)
			if !errors.Is(err, tc.wantError) {
				t.Fatalf("got AddTemplate() error = %v, want %v",
					err, tc.wantError)
			}

			if r == nil {
				t.Fatal("got AddTemplate() == nil, want non-nil")
			}

			if diff := cmp.Diff(r.Handled, tc.wantHandled, cmpopts.EquateEmpty()); diff != "" {
				t.Error(diff)
			}

			cached, err := c.GetTemplate(tc.template)
			if tc.wantError != nil {
				if err == nil {
					t.Fatalf("got GetTemplate() error = %v, want non-nil", err)
				}
				return
			}

			if err != nil {
				t.Fatalf("could not retrieve template when error was expected: %v", err)
			}

			if !cached.SemanticEqual(tc.template) {
				t.Error("cached template does not equal stored template")
			}

			r2, err := c.RemoveTemplate(context.Background(), tc.template)
			if err != nil {
				t.Fatal("could not remove template")
			}

			if r2.HandledCount() != 1 {
				t.Error("more targets handled than expected")
			}

			if _, err := c.GetTemplate(tc.template); err == nil {
				t.Error("template not cleared from cache")
			}
		})
	}
}

func TestClient_RemoveTemplate(t *testing.T) {
	badRegoTempl := cts.New(cts.OptName("fake"), cts.OptCRDNames("Fake"), cts.OptTargets("h1"))
	badRegoTempl.Spec.Targets[0].Rego = badRego
	tcs := []struct {
		name        string
		handler     client.TargetHandler
		template    *templates.ConstraintTemplate
		wantHandled map[string]bool
		wantError   error
	}{
		{
			name:        "Good Template",
			handler:     &badHandler{Name: "h1", HasLib: true},
			template:    cts.New(cts.OptName("fake"), cts.OptCRDNames("Fake"), cts.OptTargets("h1")),
			wantHandled: map[string]bool{"h1": true},
			wantError:   nil,
		},
		{
			name:        "Unknown Target",
			handler:     &badHandler{Name: "h1", HasLib: true},
			template:    cts.New(cts.OptName("fake"), cts.OptCRDNames("Fake"), cts.OptTargets("h2")),
			wantHandled: nil,
			wantError:   local.ErrInvalidConstraintTemplate,
		},
		{
			name:        "Bad CRD",
			handler:     &badHandler{Name: "h1", HasLib: true},
			template:    cts.New(cts.OptName("fake"), cts.OptTargets("h1")),
			wantHandled: nil,
			wantError:   local.ErrInvalidConstraintTemplate,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			d := local.New()

			b, err := client.NewBackend(client.Driver(d))
			if err != nil {
				t.Fatalf("Could not create backend: %s", err)
			}

			c, err := b.NewClient(client.Targets(tc.handler))
			if err != nil {
				t.Fatal(err)
			}

			_, err = c.AddTemplate(tc.template)
			if !errors.Is(err, tc.wantError) {
				t.Fatalf("got AddTemplate() error = %v, want %v",
					err, tc.wantError)
			}

			r, err := c.RemoveTemplate(context.Background(), tc.template)
			if err != nil {
				t.Errorf("err = %v; want nil", err)
			}

			if diff := cmp.Diff(tc.wantHandled, r.Handled, cmpopts.EquateEmpty()); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestClient_RemoveTemplate_ByNameOnly(t *testing.T) {
	badRegoTempl := cts.New(cts.OptName("fake"), cts.OptCRDNames("Fake"), cts.OptTargets("h1"))
	badRegoTempl.Spec.Targets[0].Rego = badRego
	tcs := []struct {
		name        string
		handler     client.TargetHandler
		template    *templates.ConstraintTemplate
		wantHandled map[string]bool
		wantError   error
	}{
		{
			name:        "Good Template",
			handler:     &badHandler{Name: "h1", HasLib: true},
			template:    cts.New(cts.OptName("fake"), cts.OptCRDNames("Fake"), cts.OptTargets("h1")),
			wantHandled: map[string]bool{"h1": true},
			wantError:   nil,
		},
		{
			name:        "Unknown Target",
			handler:     &badHandler{Name: "h1", HasLib: true},
			template:    cts.New(cts.OptName("fake"), cts.OptCRDNames("Fake"), cts.OptTargets("h2")),
			wantHandled: nil,
			wantError:   local.ErrInvalidConstraintTemplate,
		},
		{
			name:        "Bad CRD",
			handler:     &badHandler{Name: "h1", HasLib: true},
			template:    cts.New(cts.OptName("fake"), cts.OptTargets("h1")),
			wantHandled: nil,
			wantError:   local.ErrInvalidConstraintTemplate,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			d := local.New()

			b, err := client.NewBackend(client.Driver(d))
			if err != nil {
				t.Fatalf("Could not create backend: %s", err)
			}

			c, err := b.NewClient(client.Targets(tc.handler))
			if err != nil {
				t.Fatal(err)
			}

			_, err = c.AddTemplate(tc.template)
			if !errors.Is(err, tc.wantError) {
				t.Fatalf("got AddTemplate() error = %v, want %v",
					err, tc.wantError)
			}

			sparseTemplate := &templates.ConstraintTemplate{}
			sparseTemplate.Name = tc.template.Name

			r, err := c.RemoveTemplate(context.Background(), sparseTemplate)
			if err != nil {
				t.Errorf("err = %v; want nil", err)
			}

			if diff := cmp.Diff(tc.wantHandled, r.Handled, cmpopts.EquateEmpty()); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestClient_GetTemplate(t *testing.T) {
	badRegoTempl := cts.New(cts.OptName("fake"), cts.OptCRDNames("Fake"), cts.OptTargets("h1"))
	badRegoTempl.Spec.Targets[0].Rego = badRego

	tcs := []struct {
		name         string
		handler      client.TargetHandler
		wantTemplate *templates.ConstraintTemplate
		wantAddError error
		wantGetError error
	}{
		{
			name:         "Good Template",
			handler:      &badHandler{Name: "h1", HasLib: true},
			wantTemplate: cts.New(cts.OptName("fake"), cts.OptCRDNames("Fake"), cts.OptTargets("h1")),
			wantAddError: nil,
			wantGetError: nil,
		},
		{
			name:         "Unknown Target",
			handler:      &badHandler{Name: "h1", HasLib: true},
			wantTemplate: cts.New(cts.OptName("fake"), cts.OptCRDNames("Fake"), cts.OptTargets("h2")),
			wantAddError: local.ErrInvalidConstraintTemplate,
			wantGetError: client.ErrMissingConstraintTemplate,
		},
		{
			name:         "Bad CRD",
			handler:      &badHandler{Name: "h1", HasLib: true},
			wantTemplate: cts.New(cts.OptName("fake"), cts.OptTargets("h1")),
			wantAddError: local.ErrInvalidConstraintTemplate,
			wantGetError: client.ErrMissingConstraintTemplate,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			d := local.New()

			b, err := client.NewBackend(client.Driver(d))
			if err != nil {
				t.Fatalf("Could not create backend: %s", err)
			}

			c, err := b.NewClient(client.Targets(tc.handler))
			if err != nil {
				t.Fatal(err)
			}

			_, err = c.AddTemplate(tc.wantTemplate)
			if !errors.Is(err, tc.wantAddError) {
				t.Fatalf("got AddTemplate() error = %v, want %v",
					err, tc.wantAddError)
			}

			gotTemplate, err := c.GetTemplate(tc.wantTemplate)
			if !errors.Is(err, tc.wantGetError) {
				t.Fatalf("got GetTemplate() error = %v, want %v",
					err, tc.wantGetError)
			}

			if tc.wantAddError != nil {
				return
			}

			if diff := cmp.Diff(tc.wantTemplate, gotTemplate); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestClient_GetTemplate_ByNameOnly(t *testing.T) {
	badRegoTempl := cts.New(cts.OptName("fake"), cts.OptCRDNames("Fake"), cts.OptTargets("h1"))
	badRegoTempl.Spec.Targets[0].Rego = badRego

	tcs := []struct {
		name         string
		handler      client.TargetHandler
		wantTemplate *templates.ConstraintTemplate
		wantAddError error
		wantGetError error
	}{
		{
			name:         "Good Template",
			handler:      &badHandler{Name: "h1", HasLib: true},
			wantTemplate: cts.New(cts.OptName("fake"), cts.OptCRDNames("Fake"), cts.OptTargets("h1")),
			wantAddError: nil,
			wantGetError: nil,
		},
		{
			name:         "Unknown Target",
			handler:      &badHandler{Name: "h1", HasLib: true},
			wantTemplate: cts.New(cts.OptName("fake"), cts.OptCRDNames("Fake"), cts.OptTargets("h2")),
			wantAddError: local.ErrInvalidConstraintTemplate,
			wantGetError: client.ErrMissingConstraintTemplate,
		},
		{
			name:         "Bad CRD",
			handler:      &badHandler{Name: "h1", HasLib: true},
			wantTemplate: cts.New(cts.OptName("fake"), cts.OptTargets("h1")),
			wantAddError: local.ErrInvalidConstraintTemplate,
			wantGetError: client.ErrMissingConstraintTemplate,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			d := local.New()

			b, err := client.NewBackend(client.Driver(d))
			if err != nil {
				t.Fatalf("Could not create backend: %s", err)
			}

			c, err := b.NewClient(client.Targets(tc.handler))
			if err != nil {
				t.Fatal(err)
			}

			_, err = c.AddTemplate(tc.wantTemplate)
			if !errors.Is(err, tc.wantAddError) {
				t.Fatalf("got AddTemplate() error = %v, want %v",
					err, tc.wantAddError)
			}

			sparseTemplate := &templates.ConstraintTemplate{}
			sparseTemplate.Name = tc.wantTemplate.Name

			gotTemplate, err := c.GetTemplate(sparseTemplate)
			if !errors.Is(err, tc.wantGetError) {
				t.Fatalf("Got GetTemplate() error = %v, want %v",
					err, tc.wantGetError)
			}

			if tc.wantGetError != nil {
				return
			}

			if diff := cmp.Diff(tc.wantTemplate, gotTemplate); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestClient_RemoveTemplate_CascadingDelete(t *testing.T) {
	handler := &badHandler{Name: "h1", HasLib: true}

	d := local.New()
	b, err := client.NewBackend(client.Driver(d))
	if err != nil {
		t.Fatalf("Could not create backend: %s", err)
	}

	c, err := b.NewClient(client.Targets(handler))
	if err != nil {
		t.Fatal(err)
	}

	templ := cts.New(cts.OptName("cascadingdelete"), cts.OptCRDNames("CascadingDelete"), cts.OptTargets("h1"))
	if _, err = c.AddTemplate(templ); err != nil {
		t.Errorf("err = %v; want nil", err)
	}

	cst1 := clienttest.MakeConstraint(t, "CascadingDelete", "cascadingdelete")
	if _, err = c.AddConstraint(context.Background(), cst1); err != nil {
		t.Fatalf("could not add first constraint: %v", err)
	}

	cst2 := clienttest.MakeConstraint(t, "CascadingDelete", "cascadingdelete2")
	if _, err = c.AddConstraint(context.Background(), cst2); err != nil {
		t.Fatalf("could not add second constraint: %v", err)
	}

	template2 := cts.New(cts.OptName("stillpersists"), cts.OptCRDNames("StillPersists"), cts.OptTargets("h1"))
	if _, err = c.AddTemplate(template2); err != nil {
		t.Errorf("err = %v; want nil", err)
	}

	cst3 := clienttest.MakeConstraint(t, "StillPersists", "stillpersists")
	if _, err = c.AddConstraint(context.Background(), cst3); err != nil {
		t.Fatalf("could not add third constraint: %v", err)
	}

	cst4 := clienttest.MakeConstraint(t, "StillPersists", "stillpersists2")
	if _, err = c.AddConstraint(context.Background(), cst4); err != nil {
		t.Fatalf("could not add fourth constraint: %v", err)
	}

	orig, err := c.Dump(context.Background())
	if err != nil {
		t.Errorf("could not dump original state: %s", err)
	}

	origLower := strings.ToLower(orig)
	origToDelete := strings.Count(origLower, "cascadingdelete")
	if origToDelete == 0 {
		t.Errorf("delete candidate not cached: %s", orig)
	}

	origPreserved := strings.Count(origLower, "stillpersists")
	if origPreserved == 0 {
		t.Errorf("preservation candidate not cached: %s", orig)
	}

	if _, err = c.RemoveTemplate(context.Background(), templ); err != nil {
		t.Error("could not remove template")
	}

	_, err = c.GetConstraint(cst1)
	if !errors.Is(err, client.ErrMissingConstraint) {
		t.Errorf("found constraint %v %v", cst1.GroupVersionKind(), cst1.GetName())
	}

	_, err = c.GetConstraint(cst2)
	if !errors.Is(err, client.ErrMissingConstraint) {
		t.Errorf("found constraint %v %v", cst2.GroupVersionKind(), cst2.GetName())
	}

	_, err = c.GetConstraint(cst3)
	if err != nil {
		t.Errorf("did not find constraint %v %v: %v", cst3.GroupVersionKind(), cst3.GetName(), err)
	}

	_, err = c.GetConstraint(cst4)
	if err != nil {
		t.Errorf("did not find constraint %v %v: %v", cst4.GroupVersionKind(), cst4.GetName(), err)
	}

	s, err := c.Dump(context.Background())
	if err != nil {
		t.Errorf("could not dump OPA cache")
	}

	sLower := strings.ToLower(s)
	if strings.Contains(sLower, "cascadingdelete") {
		t.Errorf("Template not removed from cache: %s", s)
	}

	finalPreserved := strings.Count(sLower, "stillpersists")
	if finalPreserved != origPreserved {
		t.Errorf("finalPreserved = %d, expected %d :: %s", finalPreserved, origPreserved, s)
	}
}

func TestClient_AddConstraint(t *testing.T) {
	handler := &badHandler{Name: "h1", HasLib: true}

	tcs := []struct {
		name                   string
		template               *templates.ConstraintTemplate
		constraint             *unstructured.Unstructured
		wantHandled            map[string]bool
		wantAddConstraintError error
		wantGetConstraintError error
	}{
		{
			name:                   "Good Constraint",
			template:               cts.New(cts.OptName("foos"), cts.OptCRDNames("Foos"), cts.OptTargets("h1")),
			constraint:             clienttest.MakeConstraint(t, "Foos", "foo"),
			wantHandled:            map[string]bool{"h1": true},
			wantAddConstraintError: nil,
			wantGetConstraintError: nil,
		},
		{
			name:                   "No Name",
			template:               cts.New(cts.OptName("foos"), cts.OptCRDNames("Foos"), cts.OptTargets("h1")),
			constraint:             clienttest.MakeConstraint(t, "Foos", ""),
			wantHandled:            nil,
			wantAddConstraintError: crds.ErrInvalidConstraint,
			wantGetConstraintError: crds.ErrInvalidConstraint,
		},
		{
			name:                   "No Kind",
			template:               cts.New(cts.OptName("foos"), cts.OptCRDNames("Foos"), cts.OptTargets("h1")),
			constraint:             clienttest.MakeConstraint(t, "", "foo"),
			wantHandled:            nil,
			wantAddConstraintError: crds.ErrInvalidConstraint,
			wantGetConstraintError: crds.ErrInvalidConstraint,
		},
		{
			name:                   "No Template",
			template:               nil,
			constraint:             clienttest.MakeConstraint(t, "Foo", "foo"),
			wantHandled:            nil,
			wantAddConstraintError: client.ErrMissingConstraintTemplate,
			wantGetConstraintError: client.ErrMissingConstraint,
		},
		{
			name:     "No Group",
			template: cts.New(cts.OptName("foos"), cts.OptCRDNames("Foos"), cts.OptTargets("h1")),
			constraint: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"kind": "Foos",
				},
			},
			wantHandled:            nil,
			wantAddConstraintError: crds.ErrInvalidConstraint,
			wantGetConstraintError: crds.ErrInvalidConstraint,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			d := local.New()

			b, err := client.NewBackend(client.Driver(d))
			if err != nil {
				t.Fatal(err)
			}

			c, err := b.NewClient(client.Targets(handler))
			if err != nil {
				t.Fatal(err)
			}

			if tc.template != nil {
				_, err = c.AddTemplate(tc.template)
				if err != nil {
					t.Fatal(err)
				}
			}

			r, err := c.AddConstraint(context.Background(), tc.constraint)
			if !errors.Is(err, tc.wantAddConstraintError) {
				t.Fatalf("got AddConstraint() error = %v, want %v",
					err, tc.wantAddConstraintError)
			}

			if r == nil {
				t.Fatal("got AddConstraint() == nil, want non-nil")
			}

			if diff := cmp.Diff(tc.wantHandled, r.Handled, cmpopts.EquateEmpty()); diff != "" {
				t.Error(diff)
			}

			cached, err := c.GetConstraint(tc.constraint)
			if !errors.Is(err, tc.wantGetConstraintError) {
				t.Fatalf("got GetConstraint() error = %v, want %v",
					err, tc.wantGetConstraintError)
			}

			if tc.wantGetConstraintError != nil {
				return
			}

			if diff := cmp.Diff(tc.constraint.Object["spec"], cached.Object["spec"]); diff != "" {
				t.Error("cached constraint does not equal stored constraint")
			}

			r2, err := c.RemoveConstraint(context.Background(), tc.constraint)
			if err != nil {
				t.Error("could not remove constraint")
			}

			if r2 == nil {
				t.Fatal("got RemoveConstraint() == nil, want non-nil")
			}

			if r2.HandledCount() != 1 {
				t.Error("more targets handled than expected")
			}

			if _, err := c.GetConstraint(tc.constraint); err == nil {
				t.Error("constraint not cleared from cache")
			}
		})
	}
}

func TestClient_RemoveConstraint(t *testing.T) {
	tcs := []struct {
		name        string
		template    *templates.ConstraintTemplate
		constraint  *unstructured.Unstructured
		toRemove    *unstructured.Unstructured
		wantHandled map[string]bool
		wantError   error
	}{
		{
			name:        "Good Constraint",
			template:    cts.New(cts.OptName("foos"), cts.OptCRDNames("Foos"), cts.OptTargets("h1")),
			constraint:  clienttest.MakeConstraint(t, "Foos", "foo"),
			toRemove:    clienttest.MakeConstraint(t, "Foos", "foo"),
			wantHandled: map[string]bool{"h1": true},
			wantError:   nil,
		},
		{
			name:        "No name",
			template:    cts.New(cts.OptName("foos"), cts.OptCRDNames("Foos"), cts.OptTargets("h1")),
			constraint:  clienttest.MakeConstraint(t, "Foos", "foo"),
			toRemove:    clienttest.MakeConstraint(t, "Foos", ""),
			wantHandled: nil,
			wantError:   crds.ErrInvalidConstraint,
		},
		{
			name:        "No Kind",
			template:    cts.New(cts.OptName("foos"), cts.OptCRDNames("Foos"), cts.OptTargets("h1")),
			constraint:  clienttest.MakeConstraint(t, "Foos", "foo"),
			toRemove:    clienttest.MakeConstraint(t, "", "foo"),
			wantHandled: nil,
			wantError:   crds.ErrInvalidConstraint,
		},
		{
			name:        "No Template",
			toRemove:    clienttest.MakeConstraint(t, "Foos", "foo"),
			wantHandled: nil,
			wantError:   client.ErrMissingConstraintTemplate,
		},
		{
			name:        "No Constraint",
			template:    cts.New(cts.OptName("foos"), cts.OptCRDNames("Foos"), cts.OptTargets("h1")),
			toRemove:    clienttest.MakeConstraint(t, "Foos", "bar"),
			wantHandled: map[string]bool{"h1": true},
			wantError:   nil,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			d := local.New()
			b, err := client.NewBackend(client.Driver(d))
			if err != nil {
				t.Fatalf("Could not create backend: %s", err)
			}

			handler := &badHandler{Name: "h1", HasLib: true}
			c, err := b.NewClient(client.Targets(handler))
			if err != nil {
				t.Fatal(err)
			}

			if tc.template != nil {
				_, err = c.AddTemplate(tc.template)
				if err != nil {
					t.Fatal(err)
				}
			}

			if tc.constraint != nil {
				_, err = c.AddConstraint(ctx, tc.constraint)
				if err != nil {
					t.Fatal(err)
				}
			}

			r, err := c.RemoveConstraint(context.Background(), tc.toRemove)

			if !errors.Is(err, tc.wantError) {
				t.Errorf("got RemoveConstraint error = %v, want %v",
					err, tc.wantError)
			}

			if r == nil {
				t.Fatal("got RemoveConstraint() == nil, want non-nil")
			}

			if diff := cmp.Diff(tc.wantHandled, r.Handled, cmpopts.EquateEmpty()); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestClient_AllowedDataFields(t *testing.T) {
	inventoryTempl := cts.New(cts.OptName("fake"), cts.OptCRDNames("Fake"), cts.OptTargets("h1"))
	inventoryTempl.Spec.Targets[0].Rego = `
package something

violation[{"msg": "msg"}] {
	data.inventory = "something_else"
}
`

	tcs := []struct {
		name          string
		allowedFields []string
		handler       client.TargetHandler
		template      *templates.ConstraintTemplate
		wantHandled   map[string]bool
		wantError     error
	}{
		{
			name:          "Inventory Not Used",
			allowedFields: []string{},
			handler:       &badHandler{Name: "h1", HasLib: true},
			template:      cts.New(cts.OptName("fakes"), cts.OptCRDNames("Fakes"), cts.OptTargets("h1")),
			wantHandled:   map[string]bool{"h1": true},
			wantError:     nil,
		},
		{
			name:          "Inventory used but not allowed",
			allowedFields: []string{},
			handler:       &badHandler{Name: "h1", HasLib: true},
			template:      inventoryTempl,
			wantHandled:   nil,
			wantError:     local.ErrInvalidConstraintTemplate,
		},
		{
			name:          "Inventory used and allowed",
			allowedFields: []string{"inventory"},
			handler:       &badHandler{Name: "h1", HasLib: true},
			template:      inventoryTempl,
			wantHandled:   map[string]bool{"h1": true},
			wantError:     nil,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			d := local.New()

			b, err := client.NewBackend(client.Driver(d))
			if err != nil {
				t.Fatal(err)
			}

			c, err := b.NewClient(client.Targets(tc.handler), client.AllowedDataFields(tc.allowedFields...))
			if err != nil {
				t.Fatal(err)
			}

			r, err := c.AddTemplate(tc.template)
			if !errors.Is(err, tc.wantError) {
				t.Fatalf("got AddTemplate() error = %v, want %v",
					err, tc.wantError)
			}

			if r == nil {
				t.Fatal("got AddTemplate() == nil, want non-nil")
			}

			if diff := cmp.Diff(tc.wantHandled, r.Handled, cmpopts.EquateEmpty()); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestClient_AllowedDataFields_Intersection(t *testing.T) {
	tcs := []struct {
		name      string
		allowed   client.Opt
		want      []string
		wantError error
	}{
		{
			name: "No AllowedDataFields specified",
			want: []string{"inventory"},
		},
		{
			name:    "Empty AllowedDataFields Used",
			allowed: client.AllowedDataFields(),
			want:    nil,
		},
		{
			name:    "Inventory Used",
			allowed: client.AllowedDataFields("inventory"),
			want:    []string{"inventory"},
		},
		{
			name:      "Invalid Data Field",
			allowed:   client.AllowedDataFields("no_overlap"),
			want:      []string{},
			wantError: client.ErrCreatingClient,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			d := local.New()

			b, err := client.NewBackend(client.Driver(d))
			if err != nil {
				t.Fatalf("Could not create backend: %s", err)
			}

			opts := []client.Opt{client.Targets(&badHandler{Name: "h1", HasLib: true})}
			if tc.allowed != nil {
				opts = append(opts, tc.allowed)
			}

			c, err := b.NewClient(opts...)
			if !errors.Is(err, tc.wantError) {
				t.Fatalf("got NewClient() error = %v, want %v",
					err, tc.wantError)
			}

			if tc.wantError != nil {
				return
			}

			if diff := cmp.Diff(tc.want, c.AllowedDataFields); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestClient_CreateCRD(t *testing.T) {
	testCases := []struct {
		name     string
		targets  []client.TargetHandler
		template *templates.ConstraintTemplate
		want     *apiextensions.CustomResourceDefinition
		wantErr  error
	}{
		{
			name:     "nil",
			targets:  []client.TargetHandler{&badHandler{Name: "handler", HasLib: true}},
			template: nil,
			want:     nil,
			wantErr:  local.ErrInvalidConstraintTemplate,
		},
		{
			name:     "empty",
			targets:  []client.TargetHandler{&badHandler{Name: "handler", HasLib: true}},
			template: &templates.ConstraintTemplate{},
			want:     nil,
			wantErr:  local.ErrInvalidConstraintTemplate,
		},
		{
			name:    "no CRD kind",
			targets: []client.TargetHandler{&clienttest.Handler{}},
			template: &templates.ConstraintTemplate{
				ObjectMeta: v1.ObjectMeta{Name: "foo"},
			},
			want:    nil,
			wantErr: local.ErrInvalidConstraintTemplate,
		},
		{
			name:    "name-kind mismatch",
			targets: []client.TargetHandler{&badHandler{Name: "handler", HasLib: true}},
			template: &templates.ConstraintTemplate{
				ObjectMeta: v1.ObjectMeta{Name: "foo"},
				Spec: templates.ConstraintTemplateSpec{
					CRD: templates.CRD{
						Spec: templates.CRDSpec{
							Names: templates.Names{
								Kind: "Bar",
							},
						},
					},
					Targets: []templates.Target{{
						Target: "handler",
						Rego: `package foo

violation[msg] {msg := "always"}`,
					}},
				},
			},
			want:    nil,
			wantErr: local.ErrInvalidConstraintTemplate,
		},
		{
			name:    "no targets",
			targets: []client.TargetHandler{&badHandler{Name: "handler", HasLib: true}},
			template: &templates.ConstraintTemplate{
				ObjectMeta: v1.ObjectMeta{Name: "foo"},
				Spec: templates.ConstraintTemplateSpec{
					CRD: templates.CRD{
						Spec: templates.CRDSpec{
							Names: templates.Names{
								Kind: "Foo",
							},
						},
					},
				},
			},
			want:    nil,
			wantErr: local.ErrInvalidConstraintTemplate,
		},
		{
			name:    "wrong target",
			targets: []client.TargetHandler{&badHandler{Name: "handler.1", HasLib: true}},
			template: &templates.ConstraintTemplate{
				ObjectMeta: v1.ObjectMeta{Name: "foo"},
				Spec: templates.ConstraintTemplateSpec{
					CRD: templates.CRD{
						Spec: templates.CRDSpec{
							Names: templates.Names{
								Kind: "Foo",
							},
						},
					},
					Targets: []templates.Target{{
						Target: "handler.2",
					}},
				},
			},
			want:    nil,
			wantErr: local.ErrInvalidConstraintTemplate,
		},
		{
			name: "multiple targets",
			targets: []client.TargetHandler{
				&badHandler{Name: "handler", HasLib: true},
				&badHandler{Name: "handler.2", HasLib: true},
			},
			template: &templates.ConstraintTemplate{
				ObjectMeta: v1.ObjectMeta{Name: "foo"},
				Spec: templates.ConstraintTemplateSpec{
					CRD: templates.CRD{
						Spec: templates.CRDSpec{
							Names: templates.Names{
								Kind: "Foo",
							},
						},
					},
					Targets: []templates.Target{{
						Target: "handler",
						Rego: `package foo

violation[msg] {msg := "always"}`,
					}, {
						Target: "handler.2",
						Rego: `package foo

violation[msg] {msg := "always"}`,
					}},
				},
			},
			want:    nil,
			wantErr: local.ErrInvalidConstraintTemplate,
		},
		{
			name:    "minimal working",
			targets: []client.TargetHandler{&badHandler{Name: "handler", HasLib: true}},
			template: &templates.ConstraintTemplate{
				ObjectMeta: v1.ObjectMeta{Name: "foo"},
				Spec: templates.ConstraintTemplateSpec{
					CRD: templates.CRD{
						Spec: templates.CRDSpec{
							Names: templates.Names{
								Kind: "Foo",
							},
						},
					},
					Targets: []templates.Target{{
						Target: "handler",
						Rego: `package foo

violation[msg] {msg := "always"}`,
					}},
				},
			},
			want: &apiextensions.CustomResourceDefinition{
				ObjectMeta: v1.ObjectMeta{
					Name:   "foo.constraints.gatekeeper.sh",
					Labels: map[string]string{"gatekeeper.sh/constraint": "yes"},
				},
				Spec: apiextensions.CustomResourceDefinitionSpec{
					Group:   "constraints.gatekeeper.sh",
					Version: "v1beta1",
					Names: apiextensions.CustomResourceDefinitionNames{
						Plural:     "foo",
						Singular:   "foo",
						Kind:       "Foo",
						ListKind:   "FooList",
						Categories: []string{"constraint", "constraints"},
					},
					Scope: apiextensions.ClusterScoped,
					Subresources: &apiextensions.CustomResourceSubresources{
						Status: &apiextensions.CustomResourceSubresourceStatus{},
					},
					Versions: []apiextensions.CustomResourceDefinitionVersion{{
						Name: "v1beta1", Served: true, Storage: true,
					}, {
						Name: "v1alpha1", Served: true,
					}},
					AdditionalPrinterColumns: []apiextensions.CustomResourceColumnDefinition{{
						Name:     "enforcement-action",
						Type:     "string",
						JSONPath: ".spec.enforcementAction",
					}, {
						Name:     "total-violations",
						Type:     "integer",
						JSONPath: ".status.totalViolations",
					}},
					Conversion: &apiextensions.CustomResourceConversion{
						Strategy: apiextensions.NoneConverter,
					},
					PreserveUnknownFields: pointer.BoolPtr(false),
				},
				Status: apiextensions.CustomResourceDefinitionStatus{
					StoredVersions: []string{"v1beta1"},
				},
			},
			wantErr: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			d := local.New()

			b, err := client.NewBackend(client.Driver(d))
			if err != nil {
				t.Fatal(err)
			}

			c, err := b.NewClient(client.Targets(tc.targets...))
			if err != nil {
				t.Fatal(err)
			}

			got, err := c.CreateCRD(tc.template)

			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("got CreateTemplate() error = %v, want %v",
					err, tc.wantErr)
			}

			if diff := cmp.Diff(tc.want, got,
				cmpopts.IgnoreFields(apiextensions.CustomResourceDefinitionSpec{}, "Validation"),
				cmpopts.IgnoreFields(apiextensions.CustomResourceColumnDefinition{}, "Description")); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestClient_ValidateConstraintTemplate(t *testing.T) {
	testCases := []struct {
		name     string
		targets  []client.TargetHandler
		template *templates.ConstraintTemplate
		want     *apiextensions.CustomResourceDefinition
		wantErr  error
	}{
		{
			name:     "nil",
			template: nil,
			want:     nil,
			wantErr:  local.ErrInvalidConstraintTemplate,
		},
		{
			name:     "empty",
			template: &templates.ConstraintTemplate{},
			want:     nil,
			wantErr:  local.ErrInvalidConstraintTemplate,
		},
		{
			name: "no CRD kind",
			template: &templates.ConstraintTemplate{
				ObjectMeta: v1.ObjectMeta{Name: "foo"},
			},
			want:    nil,
			wantErr: local.ErrInvalidConstraintTemplate,
		},
		{
			name: "name-kind mismatch",
			template: &templates.ConstraintTemplate{
				ObjectMeta: v1.ObjectMeta{Name: "foo"},
				Spec: templates.ConstraintTemplateSpec{
					CRD: templates.CRD{
						Spec: templates.CRDSpec{
							Names: templates.Names{
								Kind: "Bar",
							},
						},
					},
					Targets: []templates.Target{{
						Target: "handler",
						Rego: `package foo

violation[msg] {msg := "always"}`,
					}},
				},
			},
			want:    nil,
			wantErr: local.ErrInvalidConstraintTemplate,
		},
		{
			name: "no targets",
			template: &templates.ConstraintTemplate{
				ObjectMeta: v1.ObjectMeta{Name: "foo"},
				Spec: templates.ConstraintTemplateSpec{
					CRD: templates.CRD{
						Spec: templates.CRDSpec{
							Names: templates.Names{
								Kind: "Foo",
							},
						},
					},
				},
			},
			want:    nil,
			wantErr: local.ErrInvalidConstraintTemplate,
		},
		{
			name: "wrong target",
			template: &templates.ConstraintTemplate{
				ObjectMeta: v1.ObjectMeta{Name: "foo"},
				Spec: templates.ConstraintTemplateSpec{
					CRD: templates.CRD{
						Spec: templates.CRDSpec{
							Names: templates.Names{
								Kind: "Foo",
							},
						},
					},
					Targets: []templates.Target{{
						Target: "handler.2",
					}},
				},
			},
			want:    nil,
			wantErr: local.ErrInvalidConstraintTemplate,
		},
		{
			name: "multiple targets",
			template: &templates.ConstraintTemplate{
				ObjectMeta: v1.ObjectMeta{Name: "foo"},
				Spec: templates.ConstraintTemplateSpec{
					CRD: templates.CRD{
						Spec: templates.CRDSpec{
							Names: templates.Names{
								Kind: "Foo",
							},
						},
					},
					Targets: []templates.Target{{
						Target: "handler",
						Rego: `package foo

violation[msg] {msg := "always"}`,
					}, {
						Target: "handler.2",
						Rego: `package foo

violation[msg] {msg := "always"}`,
					}},
				},
			},
			want:    nil,
			wantErr: local.ErrInvalidConstraintTemplate,
		},
		{
			name:    "no rego",
			targets: []client.TargetHandler{&badHandler{Name: "handler", HasLib: true}},
			template: &templates.ConstraintTemplate{
				ObjectMeta: v1.ObjectMeta{Name: "foo"},
				Spec: templates.ConstraintTemplateSpec{
					CRD: templates.CRD{
						Spec: templates.CRDSpec{
							Names: templates.Names{
								Kind: "Foo",
							},
						},
					},
					Targets: []templates.Target{{
						Target: "handler",
					}},
				},
			},
			want:    nil,
			wantErr: local.ErrInvalidConstraintTemplate,
		},
		{
			name:    "empty rego package",
			targets: []client.TargetHandler{&badHandler{Name: "handler", HasLib: true}},
			template: &templates.ConstraintTemplate{
				ObjectMeta: v1.ObjectMeta{Name: "foo"},
				Spec: templates.ConstraintTemplateSpec{
					CRD: templates.CRD{
						Spec: templates.CRDSpec{
							Names: templates.Names{
								Kind: "Foo",
							},
						},
					},
					Targets: []templates.Target{{
						Target: "handler",
						Rego:   `package foo`,
					}},
				},
			},
			want:    nil,
			wantErr: local.ErrInvalidConstraintTemplate,
		},
		{
			name:    "minimal working",
			targets: []client.TargetHandler{&badHandler{Name: "handler", HasLib: true}},
			template: &templates.ConstraintTemplate{
				ObjectMeta: v1.ObjectMeta{Name: "foo"},
				Spec: templates.ConstraintTemplateSpec{
					CRD: templates.CRD{
						Spec: templates.CRDSpec{
							Names: templates.Names{
								Kind: "Foo",
							},
						},
					},
					Targets: []templates.Target{{
						Target: "handler",
						Rego: `package foo

violation[msg] {msg := "always"}`,
					}},
				},
			},
			want: &apiextensions.CustomResourceDefinition{
				ObjectMeta: v1.ObjectMeta{
					Name:   "foo.constraints.gatekeeper.sh",
					Labels: map[string]string{"gatekeeper.sh/constraint": "yes"},
				},
				Spec: apiextensions.CustomResourceDefinitionSpec{
					Group:   "constraints.gatekeeper.sh",
					Version: "v1beta1",
					Names: apiextensions.CustomResourceDefinitionNames{
						Plural:     "foo",
						Singular:   "foo",
						Kind:       "Foo",
						ListKind:   "FooList",
						Categories: []string{"constraint", "constraints"},
					},
					Scope: apiextensions.ClusterScoped,
					Subresources: &apiextensions.CustomResourceSubresources{
						Status: &apiextensions.CustomResourceSubresourceStatus{},
					},
					Versions: []apiextensions.CustomResourceDefinitionVersion{{
						Name: "v1beta1", Served: true, Storage: true,
					}, {
						Name: "v1alpha1", Served: true,
					}},
					Conversion: &apiextensions.CustomResourceConversion{
						Strategy: apiextensions.NoneConverter,
					},
					PreserveUnknownFields: pointer.BoolPtr(false),
				},
				Status: apiextensions.CustomResourceDefinitionStatus{
					StoredVersions: []string{"v1beta1"},
				},
			},
			wantErr: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			d := local.New()

			b, err := client.NewBackend(client.Driver(d))
			if err != nil {
				t.Fatal(err)
			}
			targets := client.Targets(&clienttest.Handler{})
			if tc.targets != nil {
				targets = client.Targets(tc.targets...)
			}
			c, err := b.NewClient(targets)

			err = c.ValidateConstraintTemplate(tc.template)

			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("got CreateTemplate() error = %v, want %v",
					err, tc.wantErr)
			}
		})
	}
}

func TestClient_AddTemplate_Duplicate(t *testing.T) {
	d := local.New()

	b, err := client.NewBackend(client.Driver(d))
	if err != nil {
		t.Fatal(err)
	}

	c, err := b.NewClient(client.Targets(&clienttest.Handler{}))
	if err != nil {
		t.Fatal(err)
	}

	t1 := clienttest.TemplateCheckData()
	t2 := clienttest.TemplateCheckData()

	_, err = c.AddTemplate(t1)
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.AddTemplate(t2)
	if err != nil {
		t.Fatal(err)
	}

	t3, err := c.GetTemplate(cts.New(cts.OptName(t1.Name)))
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(t1, t3); diff != "" {
		t.Fatal(diff)
	}
}
