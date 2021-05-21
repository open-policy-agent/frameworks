package client

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"text/template"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/local"
	constraintlib "github.com/open-policy-agent/frameworks/constraint/pkg/core/constraints"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const badRego = `asd{`

func TestClientE2E(t *testing.T) {
	d := local.New()
	p, err := NewProbe(d)
	if err != nil {
		t.Fatal(err)
	}
	for name, f := range p.TestFuncs() {
		t.Run(name, func(t *testing.T) {
			if err := f(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

var _ TargetHandler = &badHandler{}

type badHandler struct {
	Name        string
	Errors      bool
	HasLib      bool
	HandlesData bool
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
	trueBool := true
	return apiextensions.JSONSchemaProps{XPreserveUnknownFields: &trueBool}
}

func (h *badHandler) ProcessData(obj interface{}) (bool, string, interface{}, error) {
	if h.Errors {
		return false, "", nil, errors.New("TEST ERROR")
	}
	if !h.HandlesData {
		return false, "", nil, nil
	}
	return true, "projects/something", nil, nil
}

func (h *badHandler) HandleReview(obj interface{}) (bool, interface{}, error) {
	return false, "", nil
}

func (h *badHandler) HandleViolation(result *types.Result) error {
	return nil
}

func (h *badHandler) ValidateConstraint(u *unstructured.Unstructured) error {
	return nil
}

func TestInvalidTargetName(t *testing.T) {
	tc := []struct {
		Name          string
		Handler       TargetHandler
		ErrorExpected bool
	}{
		{
			Name:          "Acceptable Name",
			Handler:       &badHandler{Name: "Hello8", HasLib: true},
			ErrorExpected: false,
		},
		{
			Name:          "No Name",
			Handler:       &badHandler{Name: ""},
			ErrorExpected: true,
		},
		{
			Name:          "No Dots",
			Handler:       &badHandler{Name: "asdf.asdf"},
			ErrorExpected: true,
		},
		{
			Name:          "No Spaces",
			Handler:       &badHandler{Name: "asdf asdf"},
			ErrorExpected: true,
		},
		{
			Name:          "Must start with a letter",
			Handler:       &badHandler{Name: "8asdf"},
			ErrorExpected: true,
		},
	}
	for _, tt := range tc {
		t.Run(tt.Name, func(t *testing.T) {
			d := local.New()
			b, err := NewBackend(Driver(d))
			if err != nil {
				t.Fatalf("Could not create backend: %s", err)
			}
			_, err = b.NewClient(Targets(tt.Handler))
			if (err == nil) && tt.ErrorExpected {
				t.Fatalf("err = nil; want non-nil")
			}
			if (err != nil) && !tt.ErrorExpected {
				t.Fatalf("err = \"%s\"; want nil", err)
			}
		})
	}
}

func TestAddData(t *testing.T) {
	tc := []struct {
		Name      string
		Handler1  TargetHandler
		Handler2  TargetHandler
		ErroredBy []string
		HandledBy []string
	}{
		{
			Name:      "Handled By Both",
			Handler1:  &badHandler{Name: "h1", HasLib: true, HandlesData: true},
			Handler2:  &badHandler{Name: "h2", HasLib: true, HandlesData: true},
			HandledBy: []string{"h1", "h2"},
		},
		{
			Name:      "Handled By One",
			Handler1:  &badHandler{Name: "h1", HasLib: true, HandlesData: true},
			Handler2:  &badHandler{Name: "h2", HasLib: true, HandlesData: false},
			HandledBy: []string{"h1"},
		},
		{
			Name:      "Errored By One",
			Handler1:  &badHandler{Name: "h1", HasLib: true, HandlesData: true},
			Handler2:  &badHandler{Name: "h2", HasLib: true, HandlesData: true, Errors: true},
			HandledBy: []string{"h1"},
			ErroredBy: []string{"h2"},
		},
		{
			Name:      "Errored By Both",
			Handler1:  &badHandler{Name: "h1", HasLib: true, HandlesData: true, Errors: true},
			Handler2:  &badHandler{Name: "h2", HasLib: true, HandlesData: true, Errors: true},
			ErroredBy: []string{"h1", "h2"},
		},
		{
			Name:     "Handled By None",
			Handler1: &badHandler{Name: "h1", HasLib: true, HandlesData: false},
			Handler2: &badHandler{Name: "h2", HasLib: true, HandlesData: false},
		},
	}
	for _, tt := range tc {
		t.Run(tt.Name, func(t *testing.T) {
			d := local.New()
			b, err := NewBackend(Driver(d))
			if err != nil {
				t.Fatalf("Could not create backend: %s", err)
			}
			c, err := b.NewClient(Targets(tt.Handler1, tt.Handler2))
			if err != nil {
				t.Fatal(err)
			}
			r, err := c.AddData(context.Background(), nil)
			if err != nil && len(tt.ErroredBy) == 0 {
				t.Errorf("err = %s; want nil", err)
			}
			expectedErr := make(map[string]bool)
			actualErr := make(map[string]bool)
			for _, v := range tt.ErroredBy {
				expectedErr[v] = true
			}
			if e, ok := err.(ErrorMap); ok {
				for k := range e {
					actualErr[k] = true
				}
			}
			if !reflect.DeepEqual(actualErr, expectedErr) {
				t.Errorf("errSet = %v; wanted %v", actualErr, expectedErr)
			}
			expectedHandled := make(map[string]bool)
			for _, v := range tt.HandledBy {
				expectedHandled[v] = true
			}
			if !reflect.DeepEqual(r.Handled, expectedHandled) {
				t.Errorf("handledSet = %v; wanted %v", r.Handled, expectedHandled)
			}
			if r.HandledCount() != len(expectedHandled) {
				t.Errorf("HandledCount() = %v; want %v", r.HandledCount(), len(expectedHandled))
			}
		})
	}
}

func TestRemoveData(t *testing.T) {
	tc := []struct {
		Name      string
		Handler1  TargetHandler
		Handler2  TargetHandler
		ErroredBy []string
		HandledBy []string
	}{
		{
			Name:      "Handled By Both",
			Handler1:  &badHandler{Name: "h1", HasLib: true, HandlesData: true},
			Handler2:  &badHandler{Name: "h2", HasLib: true, HandlesData: true},
			HandledBy: []string{"h1", "h2"},
		},
		{
			Name:      "Handled By One",
			Handler1:  &badHandler{Name: "h1", HasLib: true, HandlesData: true},
			Handler2:  &badHandler{Name: "h2", HasLib: true, HandlesData: false},
			HandledBy: []string{"h1"},
		},
		{
			Name:      "Errored By One",
			Handler1:  &badHandler{Name: "h1", HasLib: true, HandlesData: true},
			Handler2:  &badHandler{Name: "h2", HasLib: true, HandlesData: true, Errors: true},
			HandledBy: []string{"h1"},
			ErroredBy: []string{"h2"},
		},
		{
			Name:      "Errored By Both",
			Handler1:  &badHandler{Name: "h1", HasLib: true, HandlesData: true, Errors: true},
			Handler2:  &badHandler{Name: "h2", HasLib: true, HandlesData: true, Errors: true},
			ErroredBy: []string{"h1", "h2"},
		},
		{
			Name:     "Handled By None",
			Handler1: &badHandler{Name: "h1", HasLib: true, HandlesData: false},
			Handler2: &badHandler{Name: "h2", HasLib: true, HandlesData: false},
		},
	}
	for _, tt := range tc {
		t.Run(tt.Name, func(t *testing.T) {
			d := local.New()
			b, err := NewBackend(Driver(d))
			if err != nil {
				t.Fatalf("Could not create backend: %s", err)
			}
			c, err := b.NewClient(Targets(tt.Handler1, tt.Handler2))
			if err != nil {
				t.Fatal(err)
			}
			r, err := c.RemoveData(context.Background(), nil)
			if err != nil && len(tt.ErroredBy) == 0 {
				t.Errorf("err = %s; want nil", err)
			}
			expectedErr := make(map[string]bool)
			actualErr := make(map[string]bool)
			for _, v := range tt.ErroredBy {
				expectedErr[v] = true
			}
			if e, ok := err.(ErrorMap); ok {
				for k := range e {
					actualErr[k] = true
				}
			}
			if !reflect.DeepEqual(actualErr, expectedErr) {
				t.Errorf("errSet = %v; wanted %v", actualErr, expectedErr)
			}
			expectedHandled := make(map[string]bool)
			for _, v := range tt.HandledBy {
				expectedHandled[v] = true
			}
			if !reflect.DeepEqual(r.Handled, expectedHandled) {
				t.Errorf("handledSet = %v; wanted %v", r.Handled, expectedHandled)
			}
			if r.HandledCount() != len(expectedHandled) {
				t.Errorf("HandledCount() = %v; want %v", r.HandledCount(), len(expectedHandled))
			}
		})
	}
}

func TestAddTemplate(t *testing.T) {
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

	tc := []struct {
		Name          string
		Handler       TargetHandler
		Template      *templates.ConstraintTemplate
		ErrorExpected bool
	}{
		{
			Name:          "Good Template",
			Handler:       &badHandler{Name: "h1", HasLib: true},
			Template:      createTemplate(name("fakes"), crdNames("Fakes"), targets("h1")),
			ErrorExpected: false,
		},
		{
			Name:          "Unknown Target",
			Handler:       &badHandler{Name: "h1", HasLib: true},
			Template:      createTemplate(name("fake"), crdNames("Fake"), targets("h2")),
			ErrorExpected: true,
		},
		{
			Name:          "Bad CRD",
			Handler:       &badHandler{Name: "h1", HasLib: true},
			Template:      createTemplate(name("fakes"), targets("h1")),
			ErrorExpected: true,
		},
		{
			Name:          "No Name",
			Handler:       &badHandler{Name: "h1", HasLib: true},
			Template:      createTemplate(crdNames("Fake"), targets("h1")),
			ErrorExpected: true,
		},
		{
			Name:          "Bad Rego",
			Handler:       &badHandler{Name: "h1", HasLib: true},
			Template:      badRegoTempl,
			ErrorExpected: true,
		},
		{
			Name:          "No Rego",
			Handler:       &badHandler{Name: "h1", HasLib: true},
			Template:      emptyRegoTempl,
			ErrorExpected: true,
		},
		{
			Name:          "Missing Rule",
			Handler:       &badHandler{Name: "h1", HasLib: true},
			Template:      missingRuleTempl,
			ErrorExpected: true,
		},
	}
	for _, tt := range tc {
		t.Run(tt.Name, func(t *testing.T) {
			d := local.New()
			b, err := NewBackend(Driver(d))
			if err != nil {
				t.Fatalf("Could not create backend: %s", err)
			}
			c, err := b.NewClient(Targets(tt.Handler))
			if err != nil {
				t.Fatal(err)
			}

			r, err := c.AddTemplate(context.Background(), tt.Template)
			if err != nil && !tt.ErrorExpected {
				t.Errorf("err = %v; want nil", err)
			}
			if err == nil && tt.ErrorExpected {
				t.Error("err = nil; want non-nil")
			}

			expectedCount := 0
			expectedHandled := make(map[string]bool)
			if !tt.ErrorExpected {
				expectedCount = 1
				expectedHandled = map[string]bool{"h1": true}
			}
			if r.HandledCount() != expectedCount {
				t.Errorf("HandledCount() = %v; want %v", r.HandledCount(), expectedCount)
			}
			if !reflect.DeepEqual(r.Handled, expectedHandled) {
				t.Errorf("r.Handled = %v; want %v", r.Handled, expectedHandled)
			}

			cached, err := c.GetTemplate(context.Background(), tt.Template)
			if err == nil && tt.ErrorExpected {
				t.Error("retrieved template when error was expected")
			}
			if err != nil && !tt.ErrorExpected {
				t.Error("could not retrieve template when error was expected")
			}
			if !tt.ErrorExpected {
				if !cached.SemanticEqual(tt.Template) {
					t.Error("cached template does not equal stored template")
				}
				r2, err := c.RemoveTemplate(context.Background(), tt.Template)
				if err != nil {
					t.Error("could not remove template")
				}
				if r2.HandledCount() != 1 {
					t.Error("more targets handled than expected")
				}
				if _, err := c.GetTemplate(context.Background(), tt.Template); err == nil {
					t.Error("template not cleared from cache")
				}
			}
		})
	}
}

func TestRemoveTemplate(t *testing.T) {
	badRegoTempl := createTemplate(name("fake"), crdNames("Fake"), targets("h1"))
	badRegoTempl.Spec.Targets[0].Rego = badRego
	tc := []struct {
		Name          string
		Handler       TargetHandler
		Template      *templates.ConstraintTemplate
		ErrorExpected bool
	}{
		{
			Name:          "Good Template",
			Handler:       &badHandler{Name: "h1", HasLib: true},
			Template:      createTemplate(name("fake"), crdNames("Fake"), targets("h1")),
			ErrorExpected: false,
		},
		{
			Name:          "Unknown Target",
			Handler:       &badHandler{Name: "h1", HasLib: true},
			Template:      createTemplate(name("fake"), crdNames("Fake"), targets("h2")),
			ErrorExpected: true,
		},
		{
			Name:          "Bad CRD",
			Handler:       &badHandler{Name: "h1", HasLib: true},
			Template:      createTemplate(name("fake"), targets("h1")),
			ErrorExpected: true,
		},
	}
	for _, tt := range tc {
		t.Run(tt.Name, func(t *testing.T) {
			d := local.New()
			b, err := NewBackend(Driver(d))
			if err != nil {
				t.Fatalf("Could not create backend: %s", err)
			}
			c, err := b.NewClient(Targets(tt.Handler))
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.AddTemplate(context.Background(), tt.Template)
			if err != nil && !tt.ErrorExpected {
				t.Errorf("err = %v; want nil", err)
			}
			if err == nil && tt.ErrorExpected {
				t.Error("err = nil; want non-nil")
			}
			r, err := c.RemoveTemplate(context.Background(), tt.Template)
			if err != nil {
				t.Errorf("err = %v; want nil", err)
			}
			expectedCount := 0
			expectedHandled := make(map[string]bool)
			if !tt.ErrorExpected {
				expectedCount = 1
				expectedHandled = map[string]bool{"h1": true}
			}
			if r.HandledCount() != expectedCount {
				t.Errorf("HandledCount() = %v; want %v", r.HandledCount(), expectedCount)
			}
			if !reflect.DeepEqual(r.Handled, expectedHandled) {
				t.Errorf("r.Handled = %v; want %v", r.Handled, expectedHandled)
			}
		})
	}
}

func TestRemoveTemplateByNameOnly(t *testing.T) {
	badRegoTempl := createTemplate(name("fake"), crdNames("Fake"), targets("h1"))
	badRegoTempl.Spec.Targets[0].Rego = badRego
	tc := []struct {
		Name          string
		Handler       TargetHandler
		Template      *templates.ConstraintTemplate
		ErrorExpected bool
	}{
		{
			Name:          "Good Template",
			Handler:       &badHandler{Name: "h1", HasLib: true},
			Template:      createTemplate(name("fake"), crdNames("Fake"), targets("h1")),
			ErrorExpected: false,
		},
		{
			Name:          "Unknown Target",
			Handler:       &badHandler{Name: "h1", HasLib: true},
			Template:      createTemplate(name("fake"), crdNames("Fake"), targets("h2")),
			ErrorExpected: true,
		},
		{
			Name:          "Bad CRD",
			Handler:       &badHandler{Name: "h1", HasLib: true},
			Template:      createTemplate(name("fake"), targets("h1")),
			ErrorExpected: true,
		},
	}
	for _, tt := range tc {
		t.Run(tt.Name, func(t *testing.T) {
			d := local.New()
			b, err := NewBackend(Driver(d))
			if err != nil {
				t.Fatalf("Could not create backend: %s", err)
			}
			c, err := b.NewClient(Targets(tt.Handler))
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.AddTemplate(context.Background(), tt.Template)
			if err != nil && !tt.ErrorExpected {
				t.Errorf("err = %v; want nil", err)
			}
			if err == nil && tt.ErrorExpected {
				t.Error("err = nil; want non-nil")
			}
			sparseTemplate := &templates.ConstraintTemplate{}
			sparseTemplate.Name = tt.Template.Name
			r, err := c.RemoveTemplate(context.Background(), sparseTemplate)
			if err != nil {
				t.Errorf("err = %v; want nil", err)
			}
			expectedCount := 0
			expectedHandled := make(map[string]bool)
			if !tt.ErrorExpected {
				expectedCount = 1
				expectedHandled = map[string]bool{"h1": true}
			}
			if r.HandledCount() != expectedCount {
				t.Errorf("HandledCount() = %v; want %v", r.HandledCount(), expectedCount)
			}
			if !reflect.DeepEqual(r.Handled, expectedHandled) {
				t.Errorf("r.Handled = %v; want %v", r.Handled, expectedHandled)
			}
		})
	}
}

func TestGetTemplate(t *testing.T) {
	badRegoTempl := createTemplate(name("fake"), crdNames("Fake"), targets("h1"))
	badRegoTempl.Spec.Targets[0].Rego = badRego
	tc := []struct {
		Name          string
		Handler       TargetHandler
		Template      *templates.ConstraintTemplate
		ErrorExpected bool
	}{
		{
			Name:          "Good Template",
			Handler:       &badHandler{Name: "h1", HasLib: true},
			Template:      createTemplate(name("fake"), crdNames("Fake"), targets("h1")),
			ErrorExpected: false,
		},
		{
			Name:          "Unknown Target",
			Handler:       &badHandler{Name: "h1", HasLib: true},
			Template:      createTemplate(name("fake"), crdNames("Fake"), targets("h2")),
			ErrorExpected: true,
		},
		{
			Name:          "Bad CRD",
			Handler:       &badHandler{Name: "h1", HasLib: true},
			Template:      createTemplate(name("fake"), targets("h1")),
			ErrorExpected: true,
		},
	}
	for _, tt := range tc {
		t.Run(tt.Name, func(t *testing.T) {
			d := local.New()
			b, err := NewBackend(Driver(d))
			if err != nil {
				t.Fatalf("Could not create backend: %s", err)
			}
			c, err := b.NewClient(Targets(tt.Handler))
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.AddTemplate(context.Background(), tt.Template)
			if err != nil && !tt.ErrorExpected {
				t.Errorf("err = %v; want nil", err)
			}
			if err == nil && tt.ErrorExpected {
				t.Error("err = nil; want non-nil")
			}
			tmpl, err := c.GetTemplate(context.Background(), tt.Template)
			if err != nil && !tt.ErrorExpected {
				t.Errorf("err = %v; want nil", err)
			}
			if err == nil && tt.ErrorExpected {
				t.Error("err = nil; want non-nil")
			}
			if !tt.ErrorExpected {
				if !reflect.DeepEqual(tmpl, tt.Template) {
					t.Error("Stored and retrieved template differ")
				}
			}
		})
	}
}

func TestGetTemplateByNameOnly(t *testing.T) {
	badRegoTempl := createTemplate(name("fake"), crdNames("Fake"), targets("h1"))
	badRegoTempl.Spec.Targets[0].Rego = badRego
	tc := []struct {
		Name          string
		Handler       TargetHandler
		Template      *templates.ConstraintTemplate
		ErrorExpected bool
	}{
		{
			Name:          "Good Template",
			Handler:       &badHandler{Name: "h1", HasLib: true},
			Template:      createTemplate(name("fake"), crdNames("Fake"), targets("h1")),
			ErrorExpected: false,
		},
		{
			Name:          "Unknown Target",
			Handler:       &badHandler{Name: "h1", HasLib: true},
			Template:      createTemplate(name("fake"), crdNames("Fake"), targets("h2")),
			ErrorExpected: true,
		},
		{
			Name:          "Bad CRD",
			Handler:       &badHandler{Name: "h1", HasLib: true},
			Template:      createTemplate(name("fake"), targets("h1")),
			ErrorExpected: true,
		},
	}
	for _, tt := range tc {
		t.Run(tt.Name, func(t *testing.T) {
			d := local.New()
			b, err := NewBackend(Driver(d))
			if err != nil {
				t.Fatalf("Could not create backend: %s", err)
			}
			c, err := b.NewClient(Targets(tt.Handler))
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.AddTemplate(context.Background(), tt.Template)
			if err != nil && !tt.ErrorExpected {
				t.Errorf("err = %v; want nil", err)
			}
			if err == nil && tt.ErrorExpected {
				t.Error("err = nil; want non-nil")
			}
			sparseTemplate := &templates.ConstraintTemplate{}
			sparseTemplate.Name = tt.Template.Name
			tmpl, err := c.GetTemplate(context.Background(), sparseTemplate)
			if err != nil && !tt.ErrorExpected {
				t.Errorf("err = %v; want nil", err)
			}
			if err == nil && tt.ErrorExpected {
				t.Error("err = nil; want non-nil")
			}
			if !tt.ErrorExpected {
				if !reflect.DeepEqual(tmpl, tt.Template) {
					t.Error("Stored and retrieved template differ")
				}
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
	template := createTemplate(name("cascadingdelete"), crdNames("CascadingDelete"), targets("h1"))
	if _, err = c.AddTemplate(context.Background(), template); err != nil {
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
	if _, err = c.AddTemplate(context.Background(), template2); err != nil {
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

	if _, err = c.RemoveTemplate(context.Background(), template); err != nil {
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
	tc := []struct {
		Name          string
		Constraint    *unstructured.Unstructured
		OmitTemplate  bool
		ErrorExpected bool
	}{
		{
			Name:       "Good Constraint",
			Constraint: newConstraint("Foos", "foo", nil, nil),
		},
		{
			Name:          "No Name",
			Constraint:    newConstraint("Foos", "", nil, nil),
			ErrorExpected: true,
		},
		{
			Name:          "No Kind",
			Constraint:    newConstraint("", "foo", nil, nil),
			ErrorExpected: true,
		},
		{
			Name:          "No Template",
			Constraint:    newConstraint("Foo", "foo", nil, nil),
			OmitTemplate:  true,
			ErrorExpected: true,
		},
	}
	for _, tt := range tc {
		t.Run(tt.Name, func(t *testing.T) {
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
			if !tt.OmitTemplate {
				tmpl := createTemplate(name("foos"), crdNames("Foos"), targets("h1"))
				_, err := c.AddTemplate(context.Background(), tmpl)
				if err != nil {
					t.Fatal(err)
				}
			}
			r, err := c.AddConstraint(context.Background(), tt.Constraint)
			if err != nil && !tt.ErrorExpected {
				t.Errorf("err = %v; want nil", err)
			}
			if err == nil && tt.ErrorExpected {
				t.Error("err = nil; want non-nil")
			}
			expectedCount := 0
			expectedHandled := make(map[string]bool)
			if !tt.ErrorExpected {
				expectedCount = 1
				expectedHandled = map[string]bool{"h1": true}
			}
			if r.HandledCount() != expectedCount {
				t.Errorf("HandledCount() = %v; want %v", r.HandledCount(), expectedCount)
			}
			if !reflect.DeepEqual(r.Handled, expectedHandled) {
				t.Errorf("r.Handled = %v; want %v", r.Handled, expectedHandled)
			}
			cached, err := c.GetConstraint(context.Background(), tt.Constraint)
			if err == nil && tt.ErrorExpected {
				t.Error("retrieved constraint when error was expected")
			}
			if err != nil && !tt.ErrorExpected {
				t.Error("could not retrieve constraint when error was expected")
			}
			if !tt.ErrorExpected {
				if !constraintlib.SemanticEqual(cached, tt.Constraint) {
					t.Error("cached constraint does not equal stored constraint")
				}
				r2, err := c.RemoveConstraint(context.Background(), tt.Constraint)
				if err != nil {
					t.Error("could not remove constraint")
				}
				if r2.HandledCount() != 1 {
					t.Error("more targets handled than expected")
				}
				if _, err := c.GetConstraint(context.Background(), tt.Constraint); err == nil {
					t.Error("constraint not cleared from cache")
				}
			}
		})
	}
}

func TestRemoveConstraint(t *testing.T) {
	tc := []struct {
		Name              string
		Constraint        *unstructured.Unstructured
		OmitTemplate      bool
		ErrorExpected     bool
		ExpectedErrorType string
	}{
		{
			Name:       "Good Constraint",
			Constraint: newConstraint("Foos", "foo", nil, nil),
		},
		{
			Name:          "No Name",
			Constraint:    newConstraint("Foos", "", nil, nil),
			ErrorExpected: true,
		},
		{
			Name:          "No Kind",
			Constraint:    newConstraint("", "foo", nil, nil),
			ErrorExpected: true,
		},
		{
			Name:          "No Template",
			Constraint:    newConstraint("Foo", "foo", nil, nil),
			OmitTemplate:  true,
			ErrorExpected: true,
		},
		{
			Name:              "Unrecognized Constraint",
			Constraint:        newConstraint("Bar", "bar", nil, nil),
			OmitTemplate:      true,
			ErrorExpected:     true,
			ExpectedErrorType: "*client.UnrecognizedConstraintError",
		},
	}
	for _, tt := range tc {
		t.Run(tt.Name, func(t *testing.T) {
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
			if !tt.OmitTemplate {
				tmpl := createTemplate(name("foos"), crdNames("Foos"), targets("h1"))
				_, err := c.AddTemplate(context.Background(), tmpl)
				if err != nil {
					t.Fatal(err)
				}
			}
			r, err := c.RemoveConstraint(context.Background(), tt.Constraint)
			if err != nil && !tt.ErrorExpected {
				t.Errorf("err = %v; want nil", err)
			}
			if err == nil && tt.ErrorExpected {
				t.Error("err = nil; want non-nil")
			}
			if tt.ErrorExpected && tt.ExpectedErrorType != "" && reflect.TypeOf(err).String() != tt.ExpectedErrorType {
				t.Errorf("err type = %s; want %s", reflect.TypeOf(err).String(), tt.ExpectedErrorType)
			}
			expectedCount := 0
			expectedHandled := make(map[string]bool)
			if !tt.ErrorExpected {
				expectedCount = 1
				expectedHandled = map[string]bool{"h1": true}
			}
			if r.HandledCount() != expectedCount {
				t.Errorf("HandledCount() = %v; want %v", r.HandledCount(), expectedCount)
			}
			if !reflect.DeepEqual(r.Handled, expectedHandled) {
				t.Errorf("r.Handled = %v; want %v", r.Handled, expectedHandled)
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

	tc := []struct {
		Name          string
		Handler       TargetHandler
		Template      *templates.ConstraintTemplate
		ErrorExpected bool
		InvAllowed    bool
	}{
		{
			Name:          "Inventory Not Used",
			Handler:       &badHandler{Name: "h1", HasLib: true},
			Template:      createTemplate(name("fakes"), crdNames("Fakes"), targets("h1")),
			ErrorExpected: false,
		},
		{
			Name:          "Inventory Used",
			Handler:       &badHandler{Name: "h1", HasLib: true},
			Template:      inventoryTempl,
			ErrorExpected: true,
		},
		{
			Name:          "Inventory Used But Allowed",
			Handler:       &badHandler{Name: "h1", HasLib: true},
			Template:      inventoryTempl,
			ErrorExpected: false,
			InvAllowed:    true,
		},
	}
	for _, tt := range tc {
		t.Run(tt.Name, func(t *testing.T) {
			d := local.New()
			b, err := NewBackend(Driver(d))
			if err != nil {
				t.Fatalf("Could not create backend: %s", err)
			}
			f := AllowedDataFields()
			if tt.InvAllowed {
				f = AllowedDataFields("inventory")
			}
			c, err := b.NewClient(Targets(tt.Handler), f)
			if err != nil {
				t.Fatal(err)
			}
			r, err := c.AddTemplate(context.Background(), tt.Template)
			if err != nil && !tt.ErrorExpected {
				t.Errorf("err = %v; want nil", err)
			}
			if err == nil && tt.ErrorExpected {
				t.Error("err = nil; want non-nil")
			}
			expectedCount := 0
			expectedHandled := make(map[string]bool)
			if !tt.ErrorExpected {
				expectedCount = 1
				expectedHandled = map[string]bool{"h1": true}
			}
			if r.HandledCount() != expectedCount {
				t.Errorf("HandledCount() = %v; want %v", r.HandledCount(), expectedCount)
			}
			if !reflect.DeepEqual(r.Handled, expectedHandled) {
				t.Errorf("r.Handled = %v; want %v", r.Handled, expectedHandled)
			}
		})
	}
}

func TestAllowedDataFieldsIntersection(t *testing.T) {
	tc := []struct {
		Name      string
		Allowed   Opt
		Expected  []string
		wantError bool
	}{
		{
			Name:     "No AllowedDataFields specified",
			Expected: []string{"inventory"},
		},
		{
			Name:     "Empty AllowedDataFields Used",
			Allowed:  AllowedDataFields(),
			Expected: nil,
		},
		{
			Name:     "Inventory Used",
			Allowed:  AllowedDataFields("inventory"),
			Expected: []string{"inventory"},
		},
		{
			Name:      "Invalid Data Field",
			Allowed:   AllowedDataFields("no_overlap"),
			Expected:  []string{},
			wantError: true,
		},
	}
	for _, tt := range tc {
		t.Run(tt.Name, func(t *testing.T) {
			d := local.New()
			b, err := NewBackend(Driver(d))
			if err != nil {
				t.Fatalf("Could not create backend: %s", err)
			}
			opts := []Opt{Targets(&badHandler{Name: "h1", HasLib: true})}
			if tt.Allowed != nil {
				opts = append(opts, tt.Allowed)
			}
			c, err := b.NewClient(opts...)
			if tt.wantError {
				if err == nil {
					t.Fatalf("Expectd error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(c.allowedDataFields, tt.Expected) {
				t.Errorf("c.allowedDataFields = %v; want %v", c.allowedDataFields, tt.Expected)
			}
		})
	}
}
