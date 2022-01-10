package client

import (
	"context"
	"errors"
	"strings"
	"testing"
	"text/template"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
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

var _ TargetHandler = &badHandler{}

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

func TestInvalidTargetName(t *testing.T) {
	tcs := []struct {
		name      string
		handler   TargetHandler
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
			wantError: ErrCreatingClient,
		},
		{
			name:      "Dots not allowed",
			handler:   &badHandler{Name: "asdf.asdf"},
			wantError: ErrCreatingClient,
		},
		{
			name:      "Spaces not allowed",
			handler:   &badHandler{Name: "asdf asdf"},
			wantError: ErrCreatingClient,
		},
		{
			name:      "Must start with a letter",
			handler:   &badHandler{Name: "8asdf"},
			wantError: ErrCreatingClient,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			d := local.New()

			b, err := NewBackend(Driver(d))
			if err != nil {
				t.Fatalf("Could not create backend: %s", err)
			}

			_, err = b.NewClient(Targets(tc.handler))
			if !errors.Is(err, tc.wantError) {
				t.Errorf("got NewClient() error = %v, want %v",
					err, tc.wantError)
			}
		})
	}
}

func TestAddData(t *testing.T) {
	tcs := []struct {
		name        string
		handler1    TargetHandler
		handler2    TargetHandler
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

			b, err := NewBackend(Driver(d))
			if err != nil {
				t.Fatalf("Could not create backend: %s", err)
			}

			c, err := b.NewClient(Targets(tc.handler1, tc.handler2))
			if err != nil {
				t.Fatal(err)
			}

			r, err := c.AddData(context.Background(), nil)
			if err != nil && len(tc.wantError) == 0 {
				t.Fatalf("err = %s; want nil", err)
			}

			gotErrs := make(map[string]bool)
			if e, ok := err.(*ErrorMap); ok {
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

func TestRemoveData(t *testing.T) {
	tcs := []struct {
		name        string
		handler1    TargetHandler
		handler2    TargetHandler
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

			b, err := NewBackend(Driver(d))
			if err != nil {
				t.Fatalf("Could not create backend: %s", err)
			}

			c, err := b.NewClient(Targets(tc.handler1, tc.handler2))
			if err != nil {
				t.Fatal(err)
			}

			r, err := c.RemoveData(context.Background(), nil)
			if err != nil && len(tc.wantError) == 0 {
				t.Fatalf("err = %s; want nil", err)
			}

			gotErrs := make(map[string]bool)
			if e, ok := err.(*ErrorMap); ok {
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
	badRegoTempl := createTemplate(name("fake"), crdNames("Fake"), targets("h1"))
	badRegoTempl.Spec.Targets[0].Rego = badRego

	missingRuleTempl := createTemplate(name("fake"), crdNames("Fake"), targets("h1"))
	missingRuleTempl.Spec.Targets[0].Rego = `
package foo

some_rule[r] {
 r = 5
}
`
	emptyRegoTempl := createTemplate(name("fake"), crdNames("Fake"), targets("h1"))
	emptyRegoTempl.Spec.Targets[0].Rego = ""

	tcs := []struct {
		name        string
		handler     TargetHandler
		template    *templates.ConstraintTemplate
		wantHandled map[string]bool
		wantError   error
	}{
		{
			name:        "Good Template",
			handler:     &badHandler{Name: "h1", HasLib: true},
			template:    createTemplate(name("fakes"), crdNames("Fakes"), targets("h1")),
			wantHandled: map[string]bool{"h1": true},
			wantError:   nil,
		},
		{
			name:        "Unknown Target",
			handler:     &badHandler{Name: "h1", HasLib: true},
			template:    createTemplate(name("fake"), crdNames("Fake"), targets("h2")),
			wantHandled: nil,
			wantError:   ErrInvalidConstraintTemplate,
		},
		{
			name:        "Bad CRD",
			handler:     &badHandler{Name: "h1", HasLib: true},
			template:    createTemplate(name("fakes"), targets("h1")),
			wantHandled: nil,
			wantError:   ErrInvalidConstraintTemplate,
		},
		{
			name:        "No name",
			handler:     &badHandler{Name: "h1", HasLib: true},
			template:    createTemplate(crdNames("Fake"), targets("h1")),
			wantHandled: nil,
			wantError:   ErrInvalidConstraintTemplate,
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

			b, err := NewBackend(Driver(d))
			if err != nil {
				t.Fatalf("Could not create backend: %s", err)
			}

			c, err := b.NewClient(Targets(tc.handler))
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

func TestRemoveTemplate(t *testing.T) {
	badRegoTempl := createTemplate(name("fake"), crdNames("Fake"), targets("h1"))
	badRegoTempl.Spec.Targets[0].Rego = badRego
	tcs := []struct {
		name        string
		handler     TargetHandler
		template    *templates.ConstraintTemplate
		wantHandled map[string]bool
		wantError   error
	}{
		{
			name:        "Good Template",
			handler:     &badHandler{Name: "h1", HasLib: true},
			template:    createTemplate(name("fake"), crdNames("Fake"), targets("h1")),
			wantHandled: map[string]bool{"h1": true},
			wantError:   nil,
		},
		{
			name:        "Unknown Target",
			handler:     &badHandler{Name: "h1", HasLib: true},
			template:    createTemplate(name("fake"), crdNames("Fake"), targets("h2")),
			wantHandled: nil,
			wantError:   ErrInvalidConstraintTemplate,
		},
		{
			name:        "Bad CRD",
			handler:     &badHandler{Name: "h1", HasLib: true},
			template:    createTemplate(name("fake"), targets("h1")),
			wantHandled: nil,
			wantError:   ErrInvalidConstraintTemplate,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			d := local.New()

			b, err := NewBackend(Driver(d))
			if err != nil {
				t.Fatalf("Could not create backend: %s", err)
			}

			c, err := b.NewClient(Targets(tc.handler))
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

func TestRemoveTemplateByNameOnly(t *testing.T) {
	badRegoTempl := createTemplate(name("fake"), crdNames("Fake"), targets("h1"))
	badRegoTempl.Spec.Targets[0].Rego = badRego
	tcs := []struct {
		name        string
		handler     TargetHandler
		template    *templates.ConstraintTemplate
		wantHandled map[string]bool
		wantError   error
	}{
		{
			name:        "Good Template",
			handler:     &badHandler{Name: "h1", HasLib: true},
			template:    createTemplate(name("fake"), crdNames("Fake"), targets("h1")),
			wantHandled: map[string]bool{"h1": true},
			wantError:   nil,
		},
		{
			name:        "Unknown Target",
			handler:     &badHandler{Name: "h1", HasLib: true},
			template:    createTemplate(name("fake"), crdNames("Fake"), targets("h2")),
			wantHandled: nil,
			wantError:   ErrInvalidConstraintTemplate,
		},
		{
			name:        "Bad CRD",
			handler:     &badHandler{Name: "h1", HasLib: true},
			template:    createTemplate(name("fake"), targets("h1")),
			wantHandled: nil,
			wantError:   ErrInvalidConstraintTemplate,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			d := local.New()

			b, err := NewBackend(Driver(d))
			if err != nil {
				t.Fatalf("Could not create backend: %s", err)
			}

			c, err := b.NewClient(Targets(tc.handler))
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

func TestGetTemplate(t *testing.T) {
	badRegoTempl := createTemplate(name("fake"), crdNames("Fake"), targets("h1"))
	badRegoTempl.Spec.Targets[0].Rego = badRego

	tcs := []struct {
		name         string
		handler      TargetHandler
		wantTemplate *templates.ConstraintTemplate
		wantAddError error
		wantGetError error
	}{
		{
			name:         "Good Template",
			handler:      &badHandler{Name: "h1", HasLib: true},
			wantTemplate: createTemplate(name("fake"), crdNames("Fake"), targets("h1")),
			wantAddError: nil,
			wantGetError: nil,
		},
		{
			name:         "Unknown Target",
			handler:      &badHandler{Name: "h1", HasLib: true},
			wantTemplate: createTemplate(name("fake"), crdNames("Fake"), targets("h2")),
			wantAddError: ErrInvalidConstraintTemplate,
			wantGetError: ErrMissingConstraintTemplate,
		},
		{
			name:         "Bad CRD",
			handler:      &badHandler{Name: "h1", HasLib: true},
			wantTemplate: createTemplate(name("fake"), targets("h1")),
			wantAddError: ErrInvalidConstraintTemplate,
			wantGetError: ErrMissingConstraintTemplate,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			d := local.New()

			b, err := NewBackend(Driver(d))
			if err != nil {
				t.Fatalf("Could not create backend: %s", err)
			}

			c, err := b.NewClient(Targets(tc.handler))
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

func TestGetTemplateByNameOnly(t *testing.T) {
	badRegoTempl := createTemplate(name("fake"), crdNames("Fake"), targets("h1"))
	badRegoTempl.Spec.Targets[0].Rego = badRego

	tcs := []struct {
		name         string
		handler      TargetHandler
		wantTemplate *templates.ConstraintTemplate
		wantAddError error
		wantGetError error
	}{
		{
			name:         "Good Template",
			handler:      &badHandler{Name: "h1", HasLib: true},
			wantTemplate: createTemplate(name("fake"), crdNames("Fake"), targets("h1")),
			wantAddError: nil,
			wantGetError: nil,
		},
		{
			name:         "Unknown Target",
			handler:      &badHandler{Name: "h1", HasLib: true},
			wantTemplate: createTemplate(name("fake"), crdNames("Fake"), targets("h2")),
			wantAddError: ErrInvalidConstraintTemplate,
			wantGetError: ErrMissingConstraintTemplate,
		},
		{
			name:         "Bad CRD",
			handler:      &badHandler{Name: "h1", HasLib: true},
			wantTemplate: createTemplate(name("fake"), targets("h1")),
			wantAddError: ErrInvalidConstraintTemplate,
			wantGetError: ErrMissingConstraintTemplate,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			d := local.New()

			b, err := NewBackend(Driver(d))
			if err != nil {
				t.Fatalf("Could not create backend: %s", err)
			}

			c, err := b.NewClient(Targets(tc.handler))
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

func TestTemplateCascadingDelete(t *testing.T) {
	handler := &badHandler{Name: "h1", HasLib: true}

	d := local.New()
	b, err := NewBackend(Driver(d))
	if err != nil {
		t.Fatalf("Could not create backend: %s", err)
	}

	c, err := b.NewClient(Targets(handler))
	if err != nil {
		t.Fatal(err)
	}

	templ := createTemplate(name("cascadingdelete"), crdNames("CascadingDelete"), targets("h1"))
	if _, err = c.AddTemplate(templ); err != nil {
		t.Errorf("err = %v; want nil", err)
	}

	cst1 := newConstraint("CascadingDelete", "cascadingdelete", nil, nil)
	if _, err = c.AddConstraint(context.Background(), cst1); err != nil {
		t.Error("could not add first constraint")
	}

	cst2 := newConstraint("CascadingDelete", "cascadingdelete2", nil, nil)
	if _, err = c.AddConstraint(context.Background(), cst2); err != nil {
		t.Error("could not add second constraint")
	}

	template2 := createTemplate(name("stillpersists"), crdNames("StillPersists"), targets("h1"))
	if _, err = c.AddTemplate(template2); err != nil {
		t.Errorf("err = %v; want nil", err)
	}

	cst3 := newConstraint("StillPersists", "stillpersists", nil, nil)
	if _, err = c.AddConstraint(context.Background(), cst3); err != nil {
		t.Error("could not add third constraint")
	}

	cst4 := newConstraint("StillPersists", "stillpersists2", nil, nil)
	if _, err = c.AddConstraint(context.Background(), cst4); err != nil {
		t.Error("could not add fourth constraint")
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

	if len(c.constraints) != 1 {
		t.Errorf("constraint cache expected to have only 1 entry: %+v", c.constraints)
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

func TestAddConstraint(t *testing.T) {
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
			template:               createTemplate(name("foos"), crdNames("Foos"), targets("h1")),
			constraint:             newConstraint("Foos", "foo", nil, nil),
			wantHandled:            map[string]bool{"h1": true},
			wantAddConstraintError: nil,
			wantGetConstraintError: nil,
		},
		{
			name:                   "No Name",
			template:               createTemplate(name("foos"), crdNames("Foos"), targets("h1")),
			constraint:             newConstraint("Foos", "", nil, nil),
			wantHandled:            nil,
			wantAddConstraintError: ErrInvalidConstraint,
			wantGetConstraintError: ErrInvalidConstraint,
		},
		{
			name:                   "No Kind",
			template:               createTemplate(name("foos"), crdNames("Foos"), targets("h1")),
			constraint:             newConstraint("", "foo", nil, nil),
			wantHandled:            nil,
			wantAddConstraintError: ErrInvalidConstraint,
			wantGetConstraintError: ErrInvalidConstraint,
		},
		{
			name:                   "No Template",
			template:               nil,
			constraint:             newConstraint("Foo", "foo", nil, nil),
			wantHandled:            nil,
			wantAddConstraintError: ErrMissingConstraintTemplate,
			wantGetConstraintError: ErrMissingConstraint,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			d := local.New()

			b, err := NewBackend(Driver(d))
			if err != nil {
				t.Fatal(err)
			}

			c, err := b.NewClient(Targets(handler))
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

func TestRemoveConstraint(t *testing.T) {
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
			template:    createTemplate(name("foos"), crdNames("Foos"), targets("h1")),
			constraint:  newConstraint("Foos", "foo", nil, nil),
			toRemove:    newConstraint("Foos", "foo", nil, nil),
			wantHandled: map[string]bool{"h1": true},
			wantError:   nil,
		},
		{
			name:        "No name",
			template:    createTemplate(name("foos"), crdNames("Foos"), targets("h1")),
			constraint:  newConstraint("Foos", "foo", nil, nil),
			toRemove:    newConstraint("Foos", "", nil, nil),
			wantHandled: nil,
			wantError:   ErrInvalidConstraint,
		},
		{
			name:        "No Kind",
			template:    createTemplate(name("foos"), crdNames("Foos"), targets("h1")),
			constraint:  newConstraint("Foos", "foo", nil, nil),
			toRemove:    newConstraint("", "foo", nil, nil),
			wantHandled: nil,
			wantError:   ErrInvalidConstraint,
		},
		{
			name:        "No Template",
			toRemove:    newConstraint("Foos", "foo", nil, nil),
			wantHandled: nil,
			wantError:   ErrMissingConstraintTemplate,
		},
		{
			name:        "No Constraint",
			template:    createTemplate(name("foos"), crdNames("Foos"), targets("h1")),
			toRemove:    newConstraint("Foos", "bar", nil, nil),
			wantHandled: map[string]bool{"h1": true},
			wantError:   nil,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			d := local.New()
			b, err := NewBackend(Driver(d))
			if err != nil {
				t.Fatalf("Could not create backend: %s", err)
			}

			handler := &badHandler{Name: "h1", HasLib: true}
			c, err := b.NewClient(Targets(handler))
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

func TestAllowedDataFields(t *testing.T) {
	inventoryTempl := createTemplate(name("fake"), crdNames("Fake"), targets("h1"))
	inventoryTempl.Spec.Targets[0].Rego = `
package something

violation[{"msg": "msg"}] {
	data.inventory = "something_else"
}
`

	tcs := []struct {
		name          string
		allowedFields []string
		handler       TargetHandler
		template      *templates.ConstraintTemplate
		wantHandled   map[string]bool
		wantError     error
	}{
		{
			name:          "Inventory Not Used",
			allowedFields: []string{},
			handler:       &badHandler{Name: "h1", HasLib: true},
			template:      createTemplate(name("fakes"), crdNames("Fakes"), targets("h1")),
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

			b, err := NewBackend(Driver(d))
			if err != nil {
				t.Fatal(err)
			}

			c, err := b.NewClient(Targets(tc.handler), AllowedDataFields(tc.allowedFields...))
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

func TestAllowedDataFieldsIntersection(t *testing.T) {
	tcs := []struct {
		name      string
		allowed   Opt
		want      []string
		wantError error
	}{
		{
			name: "No AllowedDataFields specified",
			want: []string{"inventory"},
		},
		{
			name:    "Empty AllowedDataFields Used",
			allowed: AllowedDataFields(),
			want:    nil,
		},
		{
			name:    "Inventory Used",
			allowed: AllowedDataFields("inventory"),
			want:    []string{"inventory"},
		},
		{
			name:      "Invalid Data Field",
			allowed:   AllowedDataFields("no_overlap"),
			want:      []string{},
			wantError: ErrCreatingClient,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			d := local.New()

			b, err := NewBackend(Driver(d))
			if err != nil {
				t.Fatalf("Could not create backend: %s", err)
			}

			opts := []Opt{Targets(&badHandler{Name: "h1", HasLib: true})}
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

			if diff := cmp.Diff(tc.want, c.allowedDataFields); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestClient_CreateCRD(t *testing.T) {
	testCases := []struct {
		name     string
		targets  []TargetHandler
		template *templates.ConstraintTemplate
		want     *apiextensions.CustomResourceDefinition
		wantErr  error
	}{
		{
			name:     "nil",
			targets:  []TargetHandler{&badHandler{Name: "handler", HasLib: true}},
			template: nil,
			want:     nil,
			wantErr:  ErrInvalidConstraintTemplate,
		},
		{
			name:     "empty",
			targets:  []TargetHandler{&badHandler{Name: "handler", HasLib: true}},
			template: &templates.ConstraintTemplate{},
			want:     nil,
			wantErr:  ErrInvalidConstraintTemplate,
		},
		{
			name:    "no CRD kind",
			targets: []TargetHandler{&handler{}},
			template: &templates.ConstraintTemplate{
				ObjectMeta: v1.ObjectMeta{Name: "foo"},
			},
			want:    nil,
			wantErr: ErrInvalidConstraintTemplate,
		},
		{
			name:    "name-kind mismatch",
			targets: []TargetHandler{&badHandler{Name: "handler", HasLib: true}},
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
			wantErr: ErrInvalidConstraintTemplate,
		},
		{
			name:    "no targets",
			targets: []TargetHandler{&badHandler{Name: "handler", HasLib: true}},
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
			wantErr: ErrInvalidConstraintTemplate,
		},
		{
			name:    "wrong target",
			targets: []TargetHandler{&badHandler{Name: "handler.1", HasLib: true}},
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
			wantErr: ErrInvalidConstraintTemplate,
		},
		{
			name: "multiple targets",
			targets: []TargetHandler{
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
			wantErr: ErrInvalidConstraintTemplate,
		},
		{
			name:    "minimal working",
			targets: []TargetHandler{&badHandler{Name: "handler", HasLib: true}},
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

			b, err := NewBackend(Driver(d))
			if err != nil {
				t.Fatal(err)
			}

			c, err := b.NewClient(Targets(tc.targets...))
			if err != nil {
				t.Fatal(err)
			}

			t.Log(c.targets)

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
