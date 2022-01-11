package client_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/clienttest"
	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
)

func TestE2E_RemoveConstraint(t *testing.T) {
	ctx := context.Background()
	c := clienttest.New(t)

	_, err := c.AddTemplate(clienttest.TemplateDeny())
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.AddConstraint(ctx, clienttest.MakeConstraint(t, clienttest.KindDeny, "foo"))
	if err != nil {
		t.Fatal(err)
	}

	responses, err := c.Review(ctx, clienttest.Review{Object: clienttest.Object{Name: "bar"}})
	if err != nil {
		t.Fatal(err)
	}

	got := responses.Results()
	want := []*types.Result{{
		Msg:               "denied",
		Constraint:        clienttest.MakeConstraint(t, clienttest.KindDeny, "foo"),
		EnforcementAction: "deny",
	}}

	if diff := cmp.Diff(want, got, cmpopts.IgnoreFields(types.Result{}, "Review", "Metadata", "Resource")); diff != "" {
		t.Fatal(diff)
	}

	_, err = c.RemoveConstraint(ctx, clienttest.MakeConstraint(t, clienttest.KindDeny, "foo"))
	if err != nil {
		t.Fatal(err)
	}

	responses2, err := c.Review(ctx, clienttest.Review{Object: clienttest.Object{Name: "bar"}})
	if err != nil {
		t.Fatal(err)
	}

	got2 := responses2.Results()
	var want2 []*types.Result

	if diff := cmp.Diff(want2, got2, cmpopts.IgnoreFields(types.Result{}, "Review", "Metadata", "Resource")); diff != "" {
		t.Fatal(diff)
	}
}

func TestE2E_RemoveTemplate(t *testing.T) {
	ctx := context.Background()
	c := clienttest.New(t)

	_, err := c.AddTemplate(clienttest.TemplateDeny())
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.AddConstraint(ctx, clienttest.MakeConstraint(t, clienttest.KindDeny, "foo"))
	if err != nil {
		t.Fatal(err)
	}

	responses, err := c.Review(ctx, clienttest.Review{Object: clienttest.Object{Name: "bar"}})
	if err != nil {
		t.Fatal(err)
	}

	got := responses.Results()
	want := []*types.Result{{
		Msg:               "denied",
		Constraint:        clienttest.MakeConstraint(t, clienttest.KindDeny, "foo"),
		EnforcementAction: "deny",
	}}

	if diff := cmp.Diff(want, got, cmpopts.IgnoreFields(types.Result{}, "Review", "Metadata", "Resource")); diff != "" {
		t.Fatal(diff)
	}

	_, err = c.RemoveTemplate(ctx, clienttest.TemplateDeny())
	if err != nil {
		t.Fatal(err)
	}

	responses2, err := c.Review(ctx, clienttest.Review{Object: clienttest.Object{Name: "bar"}})
	if err != nil {
		t.Fatal(err)
	}

	got2 := responses2.Results()
	var want2 []*types.Result

	if diff := cmp.Diff(want2, got2, cmpopts.IgnoreFields(types.Result{}, "Review", "Metadata", "Resource")); diff != "" {
		t.Fatal(diff)
	}
}

func TestE2E_Review_Tracing(t *testing.T) {
	tests := []struct {
		name           string
		tracingEnabled bool
	}{
		{
			name:           "disabled",
			tracingEnabled: false,
		},
		{
			name:           "enabled",
			tracingEnabled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			c := clienttest.New(t)

			_, err := c.AddTemplate(clienttest.TemplateDeny())
			if err != nil {
				t.Fatal(err)
			}

			_, err = c.AddConstraint(ctx, clienttest.MakeConstraint(t, clienttest.KindDeny, "foo"))
			if err != nil {
				t.Fatal(err)
			}

			obj := clienttest.Review{Object: clienttest.Object{Name: "bar"}}

			rsps, err := c.Review(ctx, obj, client.Tracing(tt.tracingEnabled))
			if err != nil {
				t.Fatal(err)
			}

			trace := rsps.ByTarget[clienttest.HandlerName].Trace
			if trace == nil && tt.tracingEnabled {
				t.Fatal("got nil trace but tracing enabled")
			} else if trace != nil && !tt.tracingEnabled {
				t.Fatalf("got trace but tracing disabled: %v", *trace)
			}

			_, err = c.AddData(ctx, &obj.Object)
			if err != nil {
				t.Fatal(err)
			}

			rsps2, err := c.Audit(ctx, client.Tracing(tt.tracingEnabled))
			if err != nil {
				t.Fatal(err)
			}

			trace2 := rsps2.ByTarget[clienttest.HandlerName].Trace
			if trace2 == nil && tt.tracingEnabled {
				t.Fatal("got nil trace but tracing enabled")
			} else if trace2 != nil && !tt.tracingEnabled {
				t.Fatalf("got trace but tracing disabled: %v", *trace)
			}
		})
	}
}
