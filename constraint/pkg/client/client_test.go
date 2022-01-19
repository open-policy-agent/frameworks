package client_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/clienttest"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/clienttest/cts"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/crds"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/local"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler/handlertest"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/utils/pointer"
)

func TestBackend_NewClient_InvalidTargetName(t *testing.T) {
	tcs := []struct {
		name      string
		handler   handler.TargetHandler
		wantError error
	}{
		{
			name:      "Acceptable name",
			handler:   &handlertest.Handler{Name: pointer.String("test")},
			wantError: nil,
		},
		{
			name:      "No name",
			handler:   &handlertest.Handler{Name: pointer.String("")},
			wantError: client.ErrCreatingClient,
		},
		{
			name:      "Spaces not allowed",
			handler:   &handlertest.Handler{Name: pointer.String("asdf asdf")},
			wantError: client.ErrCreatingClient,
		},
		{
			name:      "Must start with a letter",
			handler:   &handlertest.Handler{Name: pointer.String("8asdf")},
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
		handler1    handler.TargetHandler
		handler2    handler.TargetHandler
		wantHandled map[string]bool
		wantError   map[string]bool
	}{
		{
			name:        "Handled By Both",
			handler1:    &handlertest.Handler{Name: pointer.String("h1")},
			handler2:    &handlertest.Handler{Name: pointer.String("h2")},
			wantHandled: map[string]bool{"h1": true, "h2": true},
			wantError:   nil,
		},
		{
			name: "Handled By One",
			handler1: &handlertest.Handler{
				Name: pointer.String("h1"),
			},
			handler2: &handlertest.Handler{
				Name:         pointer.String("h2"),
				ShouldHandle: func(*handlertest.Object) bool { return false },
			},
			wantHandled: map[string]bool{"h1": true},
			wantError:   nil,
		},
		{
			name: "Errored By One",
			handler1: &handlertest.Handler{
				Name: pointer.String("h1"),
			},
			handler2: &handlertest.Handler{
				Name:             pointer.String("h2"),
				ProcessDataError: errors.New("some error"),
			},
			wantHandled: map[string]bool{"h1": true},
			wantError:   map[string]bool{"h2": true},
		},
		{
			name: "Errored By Both",
			handler1: &handlertest.Handler{
				Name:             pointer.String("h1"),
				ProcessDataError: errors.New("some error"),
			},
			handler2: &handlertest.Handler{
				Name:             pointer.String("h2"),
				ProcessDataError: errors.New("some other error"),
			},
			wantError: map[string]bool{"h1": true, "h2": true},
		},
		{
			name: "Handled By None",
			handler1: &handlertest.Handler{
				Name:         pointer.String("h1"),
				ShouldHandle: func(*handlertest.Object) bool { return false },
			},
			handler2: &handlertest.Handler{
				Name:         pointer.String("h2"),
				ShouldHandle: func(*handlertest.Object) bool { return false },
			},
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

			r, err := c.AddData(context.Background(), &handlertest.Object{})
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
		handler1    handler.TargetHandler
		handler2    handler.TargetHandler
		wantHandled map[string]bool
		wantError   map[string]bool
	}{
		{
			name:        "Handled By Both",
			handler1:    &handlertest.Handler{Name: pointer.String("h1")},
			handler2:    &handlertest.Handler{Name: pointer.String("h2")},
			wantHandled: map[string]bool{"h1": true, "h2": true},
			wantError:   nil,
		},
		{
			name: "Handled By One",
			handler1: &handlertest.Handler{
				Name: pointer.String("h1"),
			},
			handler2: &handlertest.Handler{
				Name:         pointer.String("h2"),
				ShouldHandle: func(*handlertest.Object) bool { return false },
			},
			wantHandled: map[string]bool{"h1": true},
			wantError:   nil,
		},
		{
			name: "Errored By One",
			handler1: &handlertest.Handler{
				Name: pointer.String("h1"),
			},
			handler2: &handlertest.Handler{
				Name:             pointer.String("h2"),
				ProcessDataError: errors.New("some error"),
			},
			wantHandled: map[string]bool{"h1": true},
			wantError:   map[string]bool{"h2": true},
		},
		{
			name: "Errored By Both",
			handler1: &handlertest.Handler{
				Name:             pointer.String("h1"),
				ProcessDataError: errors.New("some error"),
			},
			handler2: &handlertest.Handler{
				Name:             pointer.String("h2"),
				ProcessDataError: errors.New("some other error"),
			},
			wantError: map[string]bool{"h1": true, "h2": true},
		},
		{
			name: "Handled By None",
			handler1: &handlertest.Handler{
				Name:         pointer.String("h1"),
				ShouldHandle: func(*handlertest.Object) bool { return false },
			},
			handler2: &handlertest.Handler{
				Name:         pointer.String("h2"),
				ShouldHandle: func(*handlertest.Object) bool { return false },
			},
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

			r, err := c.RemoveData(context.Background(), &handlertest.Object{})
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
	tcs := []struct {
		name     string
		handler  handler.TargetHandler
		template *templates.ConstraintTemplate
		wantHandled map[string]bool
		wantError   error
	}{
		{
			name:        "Good Template",
			handler:     &handlertest.Handler{},
			template:    cts.New(),
			wantHandled: map[string]bool{handlertest.HandlerName: true},
			wantError:   nil,
		},
		{
			name:        "Unknown Target",
			handler:     &handlertest.Handler{},
			template:    cts.New(cts.OptTargets(cts.Target("h2", cts.ModuleDeny))),
			wantHandled: nil,
			wantError:   local.ErrInvalidConstraintTemplate,
		},
		{
			name:        "Bad CRD",
			handler:     &handlertest.Handler{},
			template:    cts.New(cts.OptCRDNames(""), cts.OptTargets(cts.Target(handlertest.HandlerName, cts.ModuleDeny))),
			wantHandled: nil,
			wantError:   local.ErrInvalidConstraintTemplate,
		},
		{
			name:        "No metadata name",
			handler:     &handlertest.Handler{},
			template:    cts.New(cts.OptName(""), cts.OptTargets(cts.Target(handlertest.HandlerName, cts.ModuleDeny))),
			wantHandled: nil,
			wantError:   local.ErrInvalidConstraintTemplate,
		},
		{
			name:        "Bad Rego",
			handler:     &handlertest.Handler{},
			template:    cts.New(cts.OptTargets(cts.Target(handlertest.HandlerName, `asd{`))),
			wantHandled: nil,
			wantError:   local.ErrInvalidConstraintTemplate,
		},
		{
			name:        "No Rego",
			handler:     &handlertest.Handler{},
			template:    cts.New(cts.OptTargets(cts.Target(handlertest.HandlerName, ""))),
			wantHandled: nil,
			wantError:   local.ErrInvalidConstraintTemplate,
		},
		{
			name:    "Missing Rule",
			handler: &handlertest.Handler{},
			template: cts.New(cts.OptTargets(cts.Target(handlertest.HandlerName, `
package foo

some_rule[r] {
r = 5
}
`))),
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
	tcs := []struct {
		name     string
		handler  handler.TargetHandler
		template *templates.ConstraintTemplate
		wantHandled map[string]bool
		wantError   error
	}{
		{
			name:        "Good Template",
			handler:     &handlertest.Handler{},
			template:    cts.New(),
			wantHandled: map[string]bool{handlertest.HandlerName: true},
			wantError:   nil,
		},
		{
			name:        "Unknown Target",
			handler:     &handlertest.Handler{},
			template:    cts.New(cts.OptTargets(cts.Target("other.target", cts.ModuleDeny))),
			wantHandled: nil,
			wantError:   local.ErrInvalidConstraintTemplate,
		},
		{
			name:        "Bad CRD",
			handler:     &handlertest.Handler{},
			template:    cts.New(cts.OptName("fake")),
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
	tcs := []struct {
		name     string
		handler  handler.TargetHandler
		template *templates.ConstraintTemplate
		wantHandled map[string]bool
		wantError   error
	}{
		{
			name:        "Good Template",
			handler:     &handlertest.Handler{},
			template:    cts.New(),
			wantHandled: map[string]bool{handlertest.HandlerName: true},
			wantError:   nil,
		},
		{
			name:        "Unknown Target",
			handler:     &handlertest.Handler{},
			template:    cts.New(cts.OptTargets(cts.Target("h2", cts.ModuleDeny))),
			wantHandled: nil,
			wantError:   local.ErrInvalidConstraintTemplate,
		},
		{
			name:        "Bad CRD",
			handler:     &handlertest.Handler{},
			template:    cts.New(cts.OptName("fake")),
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
	tcs := []struct {
		name         string
		handler      handler.TargetHandler
		wantTemplate *templates.ConstraintTemplate
		wantAddError error
		wantGetError error
	}{
		{
			name:         "Good Template",
			handler:      &handlertest.Handler{},
			wantTemplate: cts.New(),
			wantAddError: nil,
			wantGetError: nil,
		},
		{
			name:         "Unknown Target",
			handler:      &handlertest.Handler{},
			wantTemplate: cts.New(cts.OptTargets(cts.Target("h2", cts.ModuleDeny))),
			wantAddError: local.ErrInvalidConstraintTemplate,
			wantGetError: client.ErrMissingConstraintTemplate,
		},
		{
			name:         "Bad CRD",
			handler:      &handlertest.Handler{},
			wantTemplate: cts.New(cts.OptName("fake")),
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
	tcs := []struct {
		name         string
		handler      handler.TargetHandler
		wantTemplate *templates.ConstraintTemplate
		wantAddError error
		wantGetError error
	}{
		{
			name:         "Good Template",
			handler:      &handlertest.Handler{},
			wantTemplate: cts.New(),
			wantAddError: nil,
			wantGetError: nil,
		},
		{
			name:         "Unknown Target",
			handler:      &handlertest.Handler{},
			wantTemplate: cts.New(cts.OptTargets(cts.Target("h2", cts.ModuleDeny))),
			wantAddError: local.ErrInvalidConstraintTemplate,
			wantGetError: client.ErrMissingConstraintTemplate,
		},
		{
			name:         "Bad CRD",
			handler:      &handlertest.Handler{},
			wantTemplate: cts.New(cts.OptName("fake")),
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
	handler := &handlertest.Handler{}

	d := local.New()
	b, err := client.NewBackend(client.Driver(d))
	if err != nil {
		t.Fatalf("Could not create backend: %s", err)
	}

	c, err := b.NewClient(client.Targets(handler))
	if err != nil {
		t.Fatal(err)
	}

	templ := cts.New(cts.OptName("cascadingdelete"), cts.OptCRDNames("CascadingDelete"))
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

	template2 := cts.New(cts.OptName("stillpersists"), cts.OptCRDNames("StillPersists"))
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
		if err != nil {
			t.Errorf("found constraint %v %v", cst1.GroupVersionKind(), cst1.GetName())
		} else {
			t.Error(err)
		}
	}

	_, err = c.GetConstraint(cst2)
	if !errors.Is(err, client.ErrMissingConstraint) {
		if err != nil {
			t.Errorf("found constraint %v %v", cst2.GroupVersionKind(), cst2.GetName())
		} else {
			t.Error(err)
		}
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
			template:               cts.New(cts.OptName("foos"), cts.OptCRDNames("Foos")),
			constraint:             clienttest.MakeConstraint(t, "Foos", "foo"),
			wantHandled:            map[string]bool{handlertest.HandlerName: true},
			wantAddConstraintError: nil,
			wantGetConstraintError: nil,
		},
		{
			name:                   "No Name",
			template:               cts.New(cts.OptName("foos"), cts.OptCRDNames("Foos")),
			constraint:             clienttest.MakeConstraint(t, "Foos", ""),
			wantHandled:            nil,
			wantAddConstraintError: crds.ErrInvalidConstraint,
			wantGetConstraintError: crds.ErrInvalidConstraint,
		},
		{
			name:                   "No Kind",
			template:               cts.New(cts.OptName("foos"), cts.OptCRDNames("Foos")),
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
			template: cts.New(cts.OptName("foos"), cts.OptCRDNames("Foos")),
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

			c, err := b.NewClient(client.Targets(&handlertest.Handler{}))
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
			template:    cts.New(cts.OptName("foos"), cts.OptCRDNames("Foos")),
			constraint:  clienttest.MakeConstraint(t, "Foos", "foo"),
			toRemove:    clienttest.MakeConstraint(t, "Foos", "foo"),
			wantHandled: map[string]bool{handlertest.HandlerName: true},
			wantError:   nil,
		},
		{
			name:        "No name",
			template:    cts.New(cts.OptName("foos"), cts.OptCRDNames("Foos")),
			constraint:  clienttest.MakeConstraint(t, "Foos", "foo"),
			toRemove:    clienttest.MakeConstraint(t, "Foos", ""),
			wantHandled: nil,
			wantError:   crds.ErrInvalidConstraint,
		},
		{
			name:        "No Kind",
			template:    cts.New(cts.OptName("foos"), cts.OptCRDNames("Foos")),
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
			template:    cts.New(cts.OptName("foos"), cts.OptCRDNames("Foos")),
			toRemove:    clienttest.MakeConstraint(t, "Foos", "bar"),
			wantHandled: map[string]bool{handlertest.HandlerName: true},
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

			handler := &handlertest.Handler{}
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
	tcs := []struct {
		name          string
		allowedFields []string
		handler       handler.TargetHandler
		template      *templates.ConstraintTemplate
		wantHandled   map[string]bool
		wantError     error
	}{
		{
			name:          "Inventory Not Used",
			allowedFields: []string{},
			handler:       &handlertest.Handler{},
			template:      cts.New(),
			wantHandled:   map[string]bool{handlertest.HandlerName: true},
			wantError:     nil,
		},
		{
			name:          "Inventory used but not allowed",
			allowedFields: []string{},
			handler:       &handlertest.Handler{},
			template: cts.New(cts.OptTargets(cts.Target(handlertest.HandlerName, `
package something

violation[{"msg": "msg"}] {
	data.inventory = "something_else"
}
`))),
			wantHandled: nil,
			wantError:   local.ErrInvalidConstraintTemplate,
		},
		{
			name:          "Inventory used and allowed",
			allowedFields: []string{"inventory"},
			handler:       &handlertest.Handler{},
			template: cts.New(cts.OptTargets(cts.Target(handlertest.HandlerName, `
package something

violation[{"msg": "msg"}] {
	data.inventory = "something_else"
}
`))),
			wantHandled: map[string]bool{handlertest.HandlerName: true},
			wantError:   nil,
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

			opts := []client.Opt{client.Targets(&handlertest.Handler{})}
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
		targets  []handler.TargetHandler
		template *templates.ConstraintTemplate
		want     *apiextensions.CustomResourceDefinition
		wantErr  error
	}{
		{
			name:     "nil",
			targets:  []handler.TargetHandler{&handlertest.Handler{}},
			template: nil,
			want:     nil,
			wantErr:  local.ErrInvalidConstraintTemplate,
		},
		{
			name:     "empty",
			targets:  []handler.TargetHandler{&handlertest.Handler{}},
			template: &templates.ConstraintTemplate{},
			want:     nil,
			wantErr:  local.ErrInvalidConstraintTemplate,
		},
		{
			name:    "no CRD kind",
			targets: []handler.TargetHandler{&handlertest.Handler{}},
			template: &templates.ConstraintTemplate{
				ObjectMeta: v1.ObjectMeta{Name: "foo"},
			},
			want:    nil,
			wantErr: local.ErrInvalidConstraintTemplate,
		},
		{
			name:    "name-kind mismatch",
			targets: []handler.TargetHandler{&handlertest.Handler{}},
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
						Target: handlertest.HandlerName,
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
			targets: []handler.TargetHandler{&handlertest.Handler{}},
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
			targets: []handler.TargetHandler{&handlertest.Handler{}},
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
			targets: []handler.TargetHandler{
				&handlertest.Handler{},
				&handlertest.Handler{Name: pointer.String("handler2")},
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
						Target: handlertest.HandlerName,
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
			targets: []handler.TargetHandler{&handlertest.Handler{}},
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
						Target: handlertest.HandlerName,
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
		targets  []handler.TargetHandler
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
						Target: handlertest.HandlerName,
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
						Target: handlertest.HandlerName,
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
			targets: []handler.TargetHandler{&handlertest.Handler{}},
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
						Target: handlertest.HandlerName,
					}},
				},
			},
			want:    nil,
			wantErr: local.ErrInvalidConstraintTemplate,
		},
		{
			name:    "empty rego package",
			targets: []handler.TargetHandler{&handlertest.Handler{}},
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
						Target: handlertest.HandlerName,
						Rego:   `package foo`,
					}},
				},
			},
			want:    nil,
			wantErr: local.ErrInvalidConstraintTemplate,
		},
		{
			name:    "minimal working",
			targets: []handler.TargetHandler{&handlertest.Handler{}},
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
						Target: handlertest.HandlerName,
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
			c := clienttest.New(t)

			err := c.ValidateConstraintTemplate(tc.template)

			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("got CreateTemplate() error = %v, want %v",
					err, tc.wantErr)
			}
		})
	}
}

func TestClient_AddTemplate_Duplicate(t *testing.T) {
	c := clienttest.New(t)

	t1 := clienttest.TemplateCheckData()
	t2 := clienttest.TemplateCheckData()

	_, err := c.AddTemplate(t1)
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
