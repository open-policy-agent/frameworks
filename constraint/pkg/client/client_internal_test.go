package client

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/clienttest/cts"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/fake"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/fake/schema"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler/handlertest"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/utils/pointer"
)

func TestMultiDriverAddTemplate(t *testing.T) {
	templateA := cts.New(cts.OptTargets(
		cts.TargetCustomEngines(
			"h1",
			cts.Code("driverA", (&schema.Source{RejectWith: "MUCH REJECTING"}).ToUnstructured()),
		),
	))
	templateB := cts.New(cts.OptTargets(
		cts.TargetCustomEngines(
			"h1",
			cts.Code("driverB", (&schema.Source{RejectWith: "MUCH REJECTING"}).ToUnstructured()),
		),
	))
	templateC := cts.New(cts.OptTargets(
		cts.TargetCustomEngines(
			"h1",
			cts.Code("driverC", (&schema.Source{RejectWith: "MUCH REJECTING"}).ToUnstructured()),
		),
	))
	// sometimes we don't care which template we use
	anyTemplate := templateA.DeepCopy()

	constraint1 := cts.MakeConstraint(t, "Fakes", "constraint1")
	constraint2 := cts.MakeConstraint(t, "Fakes", "constraint2")
	constraint3 := cts.MakeConstraint(t, "Fakes", "constraint3")
	constraints := map[string]*unstructured.Unstructured{
		"constraint1": constraint1.DeepCopy(),
		"constraint2": constraint2.DeepCopy(),
	}
	constraintsPlus := map[string]*unstructured.Unstructured{
		"constraint1": constraint1.DeepCopy(),
		"constraint2": constraint2.DeepCopy(),
		"constraint3": constraint3.DeepCopy(),
	}

	cleanSlate := func() (*fake.Driver, *fake.Driver, *fake.Driver, *Client) {
		driverA := fake.New("driverA")
		driverB := fake.New("driverB")
		driverC := fake.New("driverC")

		client, err := NewClient(
			Targets(&handlertest.Handler{Name: pointer.String("h1")}),
			Driver(driverA),
			Driver(driverB),
			Driver(driverC),
		)
		if err != nil {
			t.Fatal(err)
		}

		return driverA, driverB, driverC, client
	}

	bootstrapTwoConstraints := func(t *testing.T, client *Client) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		if _, err := client.AddTemplate(ctx, templateA.DeepCopy()); err != nil {
			t.Fatal(err)
		}
		if _, err := client.AddConstraint(ctx, constraint1.DeepCopy()); err != nil {
			t.Fatal(err)
		}
		if _, err := client.AddConstraint(ctx, constraint2.DeepCopy()); err != nil {
			t.Fatal(err)
		}
	}

	driverA, driverB, driverC, client := cleanSlate()
	t.Run("Bootstrap State Correct", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		bootstrapTwoConstraints(t, client)

		// test desired state.
		if !reflect.DeepEqual(driverA.GetConstraintsForTemplate(anyTemplate), constraints) {
			t.Errorf("Missing constraints: %v", cmp.Diff(driverA.GetConstraintsForTemplate(anyTemplate), constraints))
		}
		if len(driverB.GetConstraintsForTemplate(anyTemplate)) != 0 {
			t.Errorf("Driver B has unexpected state: %v", driverB.GetConstraintsForTemplate(anyTemplate))
		}
		if len(driverC.GetConstraintsForTemplate(anyTemplate)) != 0 {
			t.Errorf("Driver C has unexpected state: %v", driverC.GetConstraintsForTemplate(anyTemplate))
		}

		resp, err := client.Review(ctx, handlertest.NewReview("", "foo", "bar"))
		if err != nil {
			t.Fatal(err)
		}
		if len(resp.Results()) != len(constraints) {
			t.Errorf("Unexpected results: %v; wanted %d results", resp.Results(), len(constraints))
		}
		for _, result := range resp.Results() {
			if !strings.HasPrefix(result.Msg, fmt.Sprintf("rejected by driver %s:", driverA.Name())) {
				t.Errorf("Unexpected rejection message: %v", result.Msg)
			}
		}
	})

	t.Run("Successful Switch", func(t *testing.T) {
		driverA, driverB, driverC, client = cleanSlate()
		bootstrapTwoConstraints(t, client)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		if _, err := client.AddTemplate(ctx, templateB.DeepCopy()); err != nil {
			t.Fatal(err)
		}

		// test desired state.
		if !reflect.DeepEqual(driverB.GetConstraintsForTemplate(anyTemplate), constraints) {
			t.Errorf("Missing constraints: %v", cmp.Diff(driverB.GetConstraintsForTemplate(anyTemplate), constraints))
		}
		if len(driverA.GetConstraintsForTemplate(anyTemplate)) != 0 {
			t.Errorf("Driver A has unexpected state: %v", driverA.GetConstraintsForTemplate(anyTemplate))
		}
		if len(driverC.GetConstraintsForTemplate(anyTemplate)) != 0 {
			t.Errorf("Driver C has unexpected state: %v", driverC.GetConstraintsForTemplate(anyTemplate))
		}

		resp, err := client.Review(ctx, handlertest.NewReview("", "foo", "bar"))
		if err != nil {
			t.Fatal(err)
		}
		if len(resp.Results()) != len(constraints) {
			t.Errorf("Unexpected results: %v; wanted %d results", resp.Results(), len(constraints))
		}
		for _, result := range resp.Results() {
			if !strings.HasPrefix(result.Msg, fmt.Sprintf("rejected by driver %s:", driverB.Name())) {
				t.Errorf("Unexpected rejection message: %v", result.Msg)
			}
		}
	})

	t.Run("Error On Destination AddTemplate", func(t *testing.T) {
		driverA, driverB, driverC, client = cleanSlate()
		bootstrapTwoConstraints(t, client)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		driverB.SetErrOnAddTemplate(true)

		if _, err := client.AddTemplate(ctx, templateB.DeepCopy()); err == nil {
			t.Fatal("expected error, got nothing")
		}

		// test desired state.
		if !reflect.DeepEqual(driverA.GetConstraintsForTemplate(anyTemplate), constraints) {
			t.Errorf("Missing constraints: %v", cmp.Diff(driverA.GetConstraintsForTemplate(anyTemplate), constraints))
		}
		if len(driverB.GetConstraintsForTemplate(anyTemplate)) != 0 {
			t.Errorf("Driver B has unexpected state: %v", driverB.GetConstraintsForTemplate(anyTemplate))
		}
		if len(driverC.GetConstraintsForTemplate(anyTemplate)) != 0 {
			t.Errorf("Driver C has unexpected state: %v", driverC.GetConstraintsForTemplate(anyTemplate))
		}

		resp, err := client.Review(ctx, handlertest.NewReview("", "foo", "bar"))
		if err != nil {
			t.Fatal(err)
		}
		if len(resp.Results()) != len(constraints) {
			t.Errorf("Unexpected results: %v; wanted %d results", resp.Results(), len(constraints))
		}
		for _, result := range resp.Results() {
			if !strings.HasPrefix(result.Msg, fmt.Sprintf("rejected by driver %s:", driverA.Name())) {
				t.Errorf("Unexpected rejection message: %v", result.Msg)
			}
		}
	})

	t.Run("Recover From Error On Destination AddTemplate", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		driverB.SetErrOnAddTemplate(false)

		if _, err := client.AddTemplate(ctx, templateB.DeepCopy()); err != nil {
			t.Fatal(err)
		}

		// test desired state.
		if !reflect.DeepEqual(driverB.GetConstraintsForTemplate(anyTemplate), constraints) {
			t.Errorf("Missing constraints: %v", cmp.Diff(driverB.GetConstraintsForTemplate(anyTemplate), constraints))
		}
		if len(driverA.GetConstraintsForTemplate(anyTemplate)) != 0 {
			t.Errorf("Driver A has unexpected state: %v", driverA.GetConstraintsForTemplate(anyTemplate))
		}
		if len(driverC.GetConstraintsForTemplate(anyTemplate)) != 0 {
			t.Errorf("Driver C has unexpected state: %v", driverC.GetConstraintsForTemplate(anyTemplate))
		}

		resp, err := client.Review(ctx, handlertest.NewReview("", "foo", "bar"))
		if err != nil {
			t.Fatal(err)
		}
		if len(resp.Results()) != len(constraints) {
			t.Errorf("Unexpected results: %v; wanted %d results", resp.Results(), len(constraints))
		}
		for _, result := range resp.Results() {
			if !strings.HasPrefix(result.Msg, fmt.Sprintf("rejected by driver %s:", driverB.Name())) {
				t.Errorf("Unexpected rejection message: %v", result.Msg)
			}
		}
	})

	t.Run("Error On Destination AddConstraint", func(t *testing.T) {
		driverA, driverB, driverC, client = cleanSlate()
		bootstrapTwoConstraints(t, client)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		driverB.SetErrOnAddConstraint(true)

		if _, err := client.AddTemplate(ctx, templateB.DeepCopy()); err == nil {
			t.Fatal("expected err; got nil")
		}

		// test desired state.
		if !reflect.DeepEqual(driverA.GetConstraintsForTemplate(anyTemplate), constraints) {
			t.Errorf("Missing constraints: %v", cmp.Diff(driverA.GetConstraintsForTemplate(anyTemplate), constraints))
		}
		if len(driverB.GetConstraintsForTemplate(anyTemplate)) != 0 {
			t.Errorf("Driver B has unexpected state: %v", driverB.GetConstraintsForTemplate(anyTemplate))
		}
		if len(driverC.GetConstraintsForTemplate(anyTemplate)) != 0 {
			t.Errorf("Driver C has unexpected state: %v", driverC.GetConstraintsForTemplate(anyTemplate))
		}

		resp, err := client.Review(ctx, handlertest.NewReview("", "foo", "bar"))
		if err != nil {
			t.Fatal(err)
		}
		if len(resp.Results()) != len(constraints) {
			t.Errorf("Unexpected results: %v; wanted %d results", resp.Results(), len(constraints))
		}
		for _, result := range resp.Results() {
			if !strings.HasPrefix(result.Msg, fmt.Sprintf("rejected by driver %s:", driverA.Name())) {
				t.Errorf("Unexpected rejection message: %v", result.Msg)
			}
		}
	})

	t.Run("Recover From Error On Destination AddConstraint", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		driverB.SetErrOnAddConstraint(false)

		template := cts.New(cts.OptTargets(
			cts.TargetCustomEngines(
				"h1",
				cts.Code("driverB", (&schema.Source{RejectWith: "MUCH REJECTING"}).ToUnstructured()),
			),
		))
		if _, err := client.AddTemplate(ctx, template); err != nil {
			t.Fatal(err)
		}

		// test desired state.
		if !reflect.DeepEqual(driverB.GetConstraintsForTemplate(anyTemplate), constraints) {
			t.Errorf("Missing constraints: %v", cmp.Diff(driverB.GetConstraintsForTemplate(anyTemplate), constraints))
		}
		if len(driverA.GetConstraintsForTemplate(anyTemplate)) != 0 {
			t.Errorf("Driver A has unexpected state: %v", driverA.GetConstraintsForTemplate(anyTemplate))
		}
		if len(driverC.GetConstraintsForTemplate(anyTemplate)) != 0 {
			t.Errorf("Driver C has unexpected state: %v", driverC.GetConstraintsForTemplate(anyTemplate))
		}

		resp, err := client.Review(ctx, handlertest.NewReview("", "foo", "bar"))
		if err != nil {
			t.Fatal(err)
		}
		if len(resp.Results()) != len(constraints) {
			t.Errorf("Unexpected results: %v; wanted %d results", resp.Results(), len(constraints))
		}
		for _, result := range resp.Results() {
			if !strings.HasPrefix(result.Msg, fmt.Sprintf("rejected by driver %s:", driverB.Name())) {
				t.Errorf("Unexpected rejection message: %v", result.Msg)
			}
		}
	})

	t.Run("Error States Across Multiple Drivers Get Cleaned Up", func(t *testing.T) {
		driverA, driverB, driverC, client = cleanSlate()
		bootstrapTwoConstraints(t, client)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		driverB.SetErrOnAddConstraint(true)
		driverC.SetErrOnAddConstraint(true)

		if _, err := client.AddTemplate(ctx, templateB.DeepCopy()); err == nil {
			t.Fatal("wanted err; got nil")
		}

		if _, err := client.AddTemplate(ctx, templateC.DeepCopy()); err == nil {
			t.Fatal("wanted err; got nil")
		}

		// test desired state.
		if !reflect.DeepEqual(driverA.GetConstraintsForTemplate(anyTemplate), constraints) {
			t.Errorf("Missing constraints: %v", cmp.Diff(driverA.GetConstraintsForTemplate(anyTemplate), constraints))
		}
		if len(client.templates[anyTemplate.Name].activeDrivers) != 3 {
			t.Errorf("Wanted 3 active drivers, got %d", len(client.templates[anyTemplate.Name].activeDrivers))
		}
		if len(driverB.GetTemplateCode()) != 1 {
			t.Errorf("Wanted 1 template in driver B; got %d", len(driverB.GetTemplateCode()))
		}
		if len(driverC.GetTemplateCode()) != 1 {
			t.Errorf("Wanted 1 template in driver C; got %d", len(driverC.GetTemplateCode()))
		}

		resp, err := client.Review(ctx, handlertest.NewReview("", "foo", "bar"))
		if err != nil {
			t.Fatal(err)
		}
		if len(resp.Results()) != len(constraints) {
			t.Errorf("Unexpected results: %v; wanted %d results", resp.Results(), len(constraints))
		}
		for _, result := range resp.Results() {
			if !strings.HasPrefix(result.Msg, fmt.Sprintf("rejected by driver %s:", driverA.Name())) {
				t.Errorf("Unexpected rejection message: %v", result.Msg)
			}
		}

		driverB.SetErrOnAddConstraint(false)
		driverC.SetErrOnAddConstraint(false)

		// now that no errors are being raised, migration should happen successfully.
		if _, err := client.AddTemplate(ctx, templateB.DeepCopy()); err != nil {
			t.Fatal(err)
		}

		if !reflect.DeepEqual(driverB.GetConstraintsForTemplate(anyTemplate), constraints) {
			t.Errorf("Missing constraints: %v", cmp.Diff(driverB.GetConstraintsForTemplate(anyTemplate), constraints))
		}
		if len(driverA.GetConstraintsForTemplate(anyTemplate)) != 0 {
			t.Errorf("Driver A has unexpected state: %v", driverA.GetConstraintsForTemplate(anyTemplate))
		}
		if len(driverC.GetConstraintsForTemplate(anyTemplate)) != 0 {
			t.Errorf("Driver C has unexpected state: %v", driverC.GetConstraintsForTemplate(anyTemplate))
		}
		if len(driverA.GetTemplateCode()) != 0 {
			t.Errorf("Wanted 0 templates in driver A; got %d", len(driverA.GetTemplateCode()))
		}
		if len(driverC.GetTemplateCode()) != 0 {
			t.Errorf("Wanted 0 templates in driver C; got %d", len(driverC.GetTemplateCode()))
		}

		resp, err = client.Review(ctx, handlertest.NewReview("", "foo", "bar"))
		if err != nil {
			t.Fatal(err)
		}
		if len(resp.Results()) != len(constraints) {
			t.Errorf("Unexpected results: %v; wanted %d results", resp.Results(), len(constraints))
		}
		for _, result := range resp.Results() {
			if !strings.HasPrefix(result.Msg, fmt.Sprintf("rejected by driver %s:", driverB.Name())) {
				t.Errorf("Unexpected rejection message: %v", result.Msg)
			}
		}
	})

	t.Run("Adding a Constraint After Failed Migration Goes to Old Driver", func(t *testing.T) {
		driverA, driverB, driverC, client = cleanSlate()
		bootstrapTwoConstraints(t, client)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		driverB.SetErrOnAddConstraint(true)

		if _, err := client.AddTemplate(ctx, templateB.DeepCopy()); err == nil {
			t.Fatal("Wanted err; got nil")
		}

		if _, err := client.AddConstraint(ctx, constraint3.DeepCopy()); err != nil {
			t.Fatal(err)
		}

		// test desired state.
		if !reflect.DeepEqual(driverA.GetConstraintsForTemplate(anyTemplate), constraintsPlus) {
			t.Errorf("Missing constraints: %v", cmp.Diff(driverA.GetConstraintsForTemplate(anyTemplate), constraintsPlus))
		}
		if len(driverB.GetConstraintsForTemplate(anyTemplate)) != 0 {
			t.Errorf("Driver B has unexpected state: %v", driverB.GetConstraintsForTemplate(anyTemplate))
		}
		if len(driverC.GetConstraintsForTemplate(anyTemplate)) != 0 {
			t.Errorf("Driver C has unexpected state: %v", driverC.GetConstraintsForTemplate(anyTemplate))
		}

		resp, err := client.Review(ctx, handlertest.NewReview("", "foo", "bar"))
		if err != nil {
			t.Fatal(err)
		}
		if len(resp.Results()) != len(constraintsPlus) {
			t.Errorf("Unexpected results: %v; wanted %d results", resp.Results(), len(constraintsPlus))
		}
		for _, result := range resp.Results() {
			if !strings.HasPrefix(result.Msg, fmt.Sprintf("rejected by driver %s:", driverA.Name())) {
				t.Errorf("Unexpected rejection message: %v", result.Msg)
			}
		}
	})

	t.Run("But Will Migrate Successfully Once Error Clears", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		driverB.SetErrOnAddConstraint(false)

		if _, err := client.AddTemplate(ctx, templateB.DeepCopy()); err != nil {
			t.Fatal(err)
		}

		// test desired state.
		if !reflect.DeepEqual(driverB.GetConstraintsForTemplate(anyTemplate), constraintsPlus) {
			t.Errorf("Missing constraints: %v", cmp.Diff(driverB.GetConstraintsForTemplate(anyTemplate), constraintsPlus))
		}
		if len(driverA.GetConstraintsForTemplate(anyTemplate)) != 0 {
			t.Errorf("Driver B has unexpected state: %v", driverA.GetConstraintsForTemplate(anyTemplate))
		}
		if len(driverC.GetConstraintsForTemplate(anyTemplate)) != 0 {
			t.Errorf("Driver C has unexpected state: %v", driverC.GetConstraintsForTemplate(anyTemplate))
		}

		resp, err := client.Review(ctx, handlertest.NewReview("", "foo", "bar"))
		if err != nil {
			t.Fatal(err)
		}
		if len(resp.Results()) != len(constraintsPlus) {
			t.Errorf("Unexpected results: %v; wanted %d results", resp.Results(), len(constraintsPlus))
		}
		for _, result := range resp.Results() {
			if !strings.HasPrefix(result.Msg, fmt.Sprintf("rejected by driver %s:", driverB.Name())) {
				t.Errorf("Unexpected rejection message: %v", result.Msg)
			}
		}

		if _, err := client.RemoveConstraint(ctx, constraint3); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("No Zombie State On Re-Migration Post Failure", func(t *testing.T) {
		driverA, driverB, driverC, client = cleanSlate()
		bootstrapTwoConstraints(t, client)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		driverA.SetErrOnRemoveTemplate(true)

		if _, err := client.AddConstraint(ctx, constraint3.DeepCopy()); err != nil {
			t.Fatal(err)
		}

		if _, err := client.AddTemplate(ctx, templateB.DeepCopy()); err == nil {
			t.Fatal("Wanted err; got nil")
		}

		// test desired state.
		if !reflect.DeepEqual(driverA.GetConstraintsForTemplate(anyTemplate), constraintsPlus) {
			t.Errorf("Missing constraints: %v", cmp.Diff(driverA.GetConstraintsForTemplate(anyTemplate), constraintsPlus))
		}
		if len(driverB.GetConstraintsForTemplate(anyTemplate)) != len(constraintsPlus) {
			t.Errorf("Driver B has unexpected state: %v", driverB.GetConstraintsForTemplate(anyTemplate))
		}
		if len(driverC.GetConstraintsForTemplate(anyTemplate)) != 0 {
			t.Errorf("Driver C has unexpected state: %v", driverC.GetConstraintsForTemplate(anyTemplate))
		}

		resp, err := client.Review(ctx, handlertest.NewReview("", "foo", "bar"))
		if err != nil {
			t.Fatal(err)
		}
		if len(resp.Results()) != len(constraintsPlus) {
			t.Errorf("Unexpected results: %v; wanted %d results", resp.Results(), len(constraintsPlus))
		}
		for _, result := range resp.Results() {
			if !strings.HasPrefix(result.Msg, fmt.Sprintf("rejected by driver %s:", driverB.Name())) {
				t.Errorf("Unexpected rejection message: %v", result.Msg)
			}
		}

		driverA.SetErrOnRemoveTemplate(false)

		if _, err := client.RemoveConstraint(ctx, constraint3.DeepCopy()); err != nil {
			t.Fatal(err)
		}

		// driverB and driverA should have the constraint removed
		if !reflect.DeepEqual(driverA.GetConstraintsForTemplate(anyTemplate), constraints) {
			t.Errorf("Missing constraints: %v", cmp.Diff(driverA.GetConstraintsForTemplate(anyTemplate), constraintsPlus))
		}
		if len(driverB.GetConstraintsForTemplate(anyTemplate)) != len(constraints) {
			t.Errorf("Driver B has unexpected state: %v", driverB.GetConstraintsForTemplate(anyTemplate))
		}
		if len(driverC.GetConstraintsForTemplate(anyTemplate)) != 0 {
			t.Errorf("Driver C has unexpected state: %v", driverC.GetConstraintsForTemplate(anyTemplate))
		}

		resp, err = client.Review(ctx, handlertest.NewReview("", "foo", "bar"))
		if err != nil {
			t.Fatal(err)
		}
		if len(resp.Results()) != len(constraints) {
			t.Errorf("Unexpected results: %v; wanted %d results", resp.Results(), len(constraintsPlus))
		}
		for _, result := range resp.Results() {
			if !strings.HasPrefix(result.Msg, fmt.Sprintf("rejected by driver %s:", driverB.Name())) {
				t.Errorf("Unexpected rejection message: %v", result.Msg)
			}
		}

		// since we only add missing constraints on migration, if driverA had stale state when it's re-activated,
		// we'd expect to see zombie constraints.
		if _, err := client.AddTemplate(ctx, templateA.DeepCopy()); err != nil {
			t.Fatal(err)
		}

		// test desired state.
		if !reflect.DeepEqual(driverA.GetConstraintsForTemplate(anyTemplate), constraints) {
			t.Errorf("Missing constraints: %v", cmp.Diff(driverA.GetConstraintsForTemplate(anyTemplate), constraints))
		}
		if len(driverB.GetConstraintsForTemplate(anyTemplate)) != 0 {
			t.Errorf("Driver B has unexpected state: %v", driverB.GetConstraintsForTemplate(anyTemplate))
		}
		if len(driverC.GetConstraintsForTemplate(anyTemplate)) != 0 {
			t.Errorf("Driver C has unexpected state: %v", driverC.GetConstraintsForTemplate(anyTemplate))
		}

		resp, err = client.Review(ctx, handlertest.NewReview("", "foo", "bar"))
		if err != nil {
			t.Fatal(err)
		}
		if len(resp.Results()) != len(constraints) {
			t.Errorf("Unexpected results: %v; wanted %d results", resp.Results(), len(constraints))
		}
		for _, result := range resp.Results() {
			if !strings.HasPrefix(result.Msg, fmt.Sprintf("rejected by driver %s:", driverA.Name())) {
				t.Errorf("Unexpected rejection message: %v", result.Msg)
			}
		}
	})

	t.Run("Adding a Constraint After Half-Completed Migration Goes to New Driver", func(t *testing.T) {
		driverA, driverB, driverC, client = cleanSlate()
		bootstrapTwoConstraints(t, client)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		driverA.SetErrOnRemoveTemplate(true)

		if _, err := client.AddTemplate(ctx, templateB.DeepCopy()); err == nil {
			t.Fatal("Wanted err; got nil")
		}

		if _, err := client.AddConstraint(ctx, constraint3.DeepCopy()); err != nil {
			t.Fatal(err)
		}

		// test desired state.
		if !reflect.DeepEqual(driverB.GetConstraintsForTemplate(anyTemplate), constraintsPlus) {
			t.Errorf("Missing constraints: %v", cmp.Diff(driverB.GetConstraintsForTemplate(anyTemplate), constraintsPlus))
		}
		if len(driverA.GetConstraintsForTemplate(anyTemplate)) != len(constraints) {
			t.Errorf("Driver A has unexpected state: %v", driverA.GetConstraintsForTemplate(anyTemplate))
		}
		if len(driverC.GetConstraintsForTemplate(anyTemplate)) != 0 {
			t.Errorf("Driver C has unexpected state: %v", driverC.GetConstraintsForTemplate(anyTemplate))
		}

		resp, err := client.Review(ctx, handlertest.NewReview("", "foo", "bar"))
		if err != nil {
			t.Fatal(err)
		}
		if len(resp.Results()) != len(constraintsPlus) {
			t.Errorf("Unexpected results: %v; wanted %d results", resp.Results(), len(constraintsPlus))
		}
		for _, result := range resp.Results() {
			if !strings.HasPrefix(result.Msg, fmt.Sprintf("rejected by driver %s:", driverB.Name())) {
				t.Errorf("Unexpected rejection message: %v", result.Msg)
			}
		}
	})

	t.Run("And That Half-Completed Migrations Recover", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		driverA.SetErrOnRemoveTemplate(false)

		if _, err := client.AddTemplate(ctx, templateB.DeepCopy()); err != nil {
			t.Fatal(err)
		}

		// test desired state.
		if !reflect.DeepEqual(driverB.GetConstraintsForTemplate(anyTemplate), constraintsPlus) {
			t.Errorf("Missing constraints: %v", cmp.Diff(driverB.GetConstraintsForTemplate(anyTemplate), constraintsPlus))
		}
		if len(driverA.GetConstraintsForTemplate(anyTemplate)) != 0 {
			t.Errorf("Driver A has unexpected state: %v", driverA.GetConstraintsForTemplate(anyTemplate))
		}
		if len(driverC.GetConstraintsForTemplate(anyTemplate)) != 0 {
			t.Errorf("Driver C has unexpected state: %v", driverC.GetConstraintsForTemplate(anyTemplate))
		}

		resp, err := client.Review(ctx, handlertest.NewReview("", "foo", "bar"))
		if err != nil {
			t.Fatal(err)
		}
		if len(resp.Results()) != len(constraintsPlus) {
			t.Errorf("Unexpected results: %v; wanted %d results", resp.Results(), len(constraintsPlus))
		}
		for _, result := range resp.Results() {
			if !strings.HasPrefix(result.Msg, fmt.Sprintf("rejected by driver %s:", driverB.Name())) {
				t.Errorf("Unexpected rejection message: %v", result.Msg)
			}
		}
	})

	t.Run("Multi-Driver Template", func(t *testing.T) {
		driverA, driverB, driverC, client = cleanSlate()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		multiDriverTemplate := cts.New(cts.OptTargets(
			cts.TargetCustomEngines(
				"h1",
				cts.Code("driverA", (&schema.Source{RejectWith: "MUCH REJECTING"}).ToUnstructured()),
				cts.Code("driverB", (&schema.Source{RejectWith: "MUCH REJECTING"}).ToUnstructured()),
				cts.Code("driverC", (&schema.Source{RejectWith: "MUCH REJECTING"}).ToUnstructured()),
			),
		))

		if _, err := client.AddTemplate(ctx, multiDriverTemplate.DeepCopy()); err != nil {
			t.Fatal(err)
		}
		if _, err := client.AddConstraint(ctx, constraint1.DeepCopy()); err != nil {
			t.Fatal(err)
		}
		if _, err := client.AddConstraint(ctx, constraint2.DeepCopy()); err != nil {
			t.Fatal(err)
		}

		// test desired state.
		if !reflect.DeepEqual(driverA.GetConstraintsForTemplate(anyTemplate), constraints) {
			t.Errorf("Missing constraints: %v", cmp.Diff(driverA.GetConstraintsForTemplate(anyTemplate), constraints))
		}
		if len(driverB.GetConstraintsForTemplate(anyTemplate)) != 0 {
			t.Errorf("Driver B has unexpected state: %v", driverB.GetConstraintsForTemplate(anyTemplate))
		}
		if len(driverC.GetConstraintsForTemplate(anyTemplate)) != 0 {
			t.Errorf("Driver C has unexpected state: %v", driverC.GetConstraintsForTemplate(anyTemplate))
		}

		resp, err := client.Review(ctx, handlertest.NewReview("", "foo", "bar"))
		if err != nil {
			t.Fatal(err)
		}
		if len(resp.Results()) != len(constraints) {
			t.Errorf("Unexpected results: %v; wanted %d results", resp.Results(), len(constraints))
		}
		for _, result := range resp.Results() {
			if !strings.HasPrefix(result.Msg, fmt.Sprintf("rejected by driver %s:", driverA.Name())) {
				t.Errorf("Unexpected rejection message: %v", result.Msg)
			}
		}
	})

	t.Run("Multi-Driver Template, No driverA", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		multiDriverTemplate := cts.New(cts.OptTargets(
			cts.TargetCustomEngines(
				"h1",
				cts.Code("driverB", (&schema.Source{RejectWith: "MUCH REJECTING"}).ToUnstructured()),
				cts.Code("driverC", (&schema.Source{RejectWith: "MUCH REJECTING"}).ToUnstructured()),
			),
		))

		if _, err := client.AddTemplate(ctx, multiDriverTemplate.DeepCopy()); err != nil {
			t.Fatal(err)
		}
		if _, err := client.AddConstraint(ctx, constraint1.DeepCopy()); err != nil {
			t.Fatal(err)
		}
		if _, err := client.AddConstraint(ctx, constraint2.DeepCopy()); err != nil {
			t.Fatal(err)
		}

		// test desired state.
		if !reflect.DeepEqual(driverB.GetConstraintsForTemplate(anyTemplate), constraints) {
			t.Errorf("Missing constraints: %v", cmp.Diff(driverB.GetConstraintsForTemplate(anyTemplate), constraints))
		}
		if len(driverA.GetConstraintsForTemplate(anyTemplate)) != 0 {
			t.Errorf("Driver A has unexpected state: %v", driverA.GetConstraintsForTemplate(anyTemplate))
		}
		if len(driverC.GetConstraintsForTemplate(anyTemplate)) != 0 {
			t.Errorf("Driver C has unexpected state: %v", driverC.GetConstraintsForTemplate(anyTemplate))
		}

		resp, err := client.Review(ctx, handlertest.NewReview("", "foo", "bar"))
		if err != nil {
			t.Fatal(err)
		}
		if len(resp.Results()) != len(constraints) {
			t.Errorf("Unexpected results: %v; wanted %d results", resp.Results(), len(constraints))
		}
		for _, result := range resp.Results() {
			if !strings.HasPrefix(result.Msg, fmt.Sprintf("rejected by driver %s:", driverB.Name())) {
				t.Errorf("Unexpected rejection message: %v", result.Msg)
			}
		}
	})

	t.Run("Multi-Driver Template, Reverse Order", func(t *testing.T) {
		driverA := fake.New("driverA")
		driverB := fake.New("driverB")
		driverC := fake.New("driverC")

		client, err := NewClient(
			Targets(&handlertest.Handler{Name: pointer.String("h1")}),
			Driver(driverC),
			Driver(driverB),
			Driver(driverA),
		)
		if err != nil {
			t.Fatal(err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		multiDriverTemplate := cts.New(cts.OptTargets(
			cts.TargetCustomEngines(
				"h1",
				cts.Code("driverA", (&schema.Source{RejectWith: "MUCH REJECTING"}).ToUnstructured()),
				cts.Code("driverB", (&schema.Source{RejectWith: "MUCH REJECTING"}).ToUnstructured()),
				cts.Code("driverC", (&schema.Source{RejectWith: "MUCH REJECTING"}).ToUnstructured()),
			),
		))

		if _, err := client.AddTemplate(ctx, multiDriverTemplate.DeepCopy()); err != nil {
			t.Fatal(err)
		}
		if _, err := client.AddConstraint(ctx, constraint1.DeepCopy()); err != nil {
			t.Fatal(err)
		}
		if _, err := client.AddConstraint(ctx, constraint2.DeepCopy()); err != nil {
			t.Fatal(err)
		}

		// test desired state.
		if !reflect.DeepEqual(driverC.GetConstraintsForTemplate(anyTemplate), constraints) {
			t.Errorf("Missing constraints: %v", cmp.Diff(driverC.GetConstraintsForTemplate(anyTemplate), constraints))
		}
		if len(driverB.GetConstraintsForTemplate(anyTemplate)) != 0 {
			t.Errorf("Driver B has unexpected state: %v", driverB.GetConstraintsForTemplate(anyTemplate))
		}
		if len(driverA.GetConstraintsForTemplate(anyTemplate)) != 0 {
			t.Errorf("Driver A has unexpected state: %v", driverA.GetConstraintsForTemplate(anyTemplate))
		}

		resp, err := client.Review(ctx, handlertest.NewReview("", "foo", "bar"))
		if err != nil {
			t.Fatal(err)
		}
		if len(resp.Results()) != len(constraints) {
			t.Errorf("Unexpected results: %v; wanted %d results", resp.Results(), len(constraints))
		}
		for _, result := range resp.Results() {
			if !strings.HasPrefix(result.Msg, fmt.Sprintf("rejected by driver %s:", driverC.Name())) {
				t.Errorf("Unexpected rejection message: %v", result.Msg)
			}
		}
	})
}

func TestMultiDriverRemoveTemplate(t *testing.T) {
	templateA := cts.New(cts.OptTargets(
		cts.TargetCustomEngines(
			"h1",
			cts.Code("driverA", (&schema.Source{RejectWith: "MUCH REJECTING"}).ToUnstructured()),
		),
	))
	templateB := cts.New(cts.OptTargets(
		cts.TargetCustomEngines(
			"h1",
			cts.Code("driverB", (&schema.Source{RejectWith: "MUCH REJECTING"}).ToUnstructured()),
		),
	))

	// sometimes we don't care which template we use
	anyTemplate := templateA.DeepCopy()

	constraint1 := cts.MakeConstraint(t, "Fakes", "constraint1")
	constraint2 := cts.MakeConstraint(t, "Fakes", "constraint2")
	constraints := map[string]*unstructured.Unstructured{
		"constraint1": constraint1.DeepCopy(),
		"constraint2": constraint2.DeepCopy(),
	}

	cleanSlate := func() (*fake.Driver, *fake.Driver, *fake.Driver, *Client) {
		driverA := fake.New("driverA")
		driverB := fake.New("driverB")
		driverC := fake.New("driverC")

		client, err := NewClient(
			Targets(&handlertest.Handler{Name: pointer.String("h1")}),
			Driver(driverA),
			Driver(driverB),
			Driver(driverC),
		)
		if err != nil {
			t.Fatal(err)
		}

		return driverA, driverB, driverC, client
	}

	bootstrapTwoConstraints := func(t *testing.T, client *Client) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		if _, err := client.AddTemplate(ctx, templateA.DeepCopy()); err != nil {
			t.Fatal(err)
		}
		if _, err := client.AddConstraint(ctx, constraint1.DeepCopy()); err != nil {
			t.Fatal(err)
		}
		if _, err := client.AddConstraint(ctx, constraint2.DeepCopy()); err != nil {
			t.Fatal(err)
		}
	}

	driverA, driverB, driverC, client := cleanSlate()
	t.Run("Remove Partial Migration", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		bootstrapTwoConstraints(t, client)

		driverA.SetErrOnRemoveTemplate(true)

		if _, err := client.AddTemplate(ctx, templateB.DeepCopy()); err == nil {
			t.Fatal("error expected; got nil")
		}

		// test desired intermediate state.
		if !reflect.DeepEqual(driverA.GetConstraintsForTemplate(anyTemplate), constraints) {
			t.Errorf("Missing constraints: %v", cmp.Diff(driverA.GetConstraintsForTemplate(anyTemplate), constraints))
		}
		if len(driverB.GetConstraintsForTemplate(anyTemplate)) != len(constraints) {
			t.Errorf("Driver B has unexpected state: %v", driverB.GetConstraintsForTemplate(anyTemplate))
		}
		if len(driverC.GetConstraintsForTemplate(anyTemplate)) != 0 {
			t.Errorf("Driver C has unexpected state: %v", driverC.GetConstraintsForTemplate(anyTemplate))
		}

		driverA.SetErrOnRemoveTemplate(false)

		if _, err := client.RemoveTemplate(ctx, templateA.DeepCopy()); err != nil {
			t.Fatal(err)
		}

		// test desired state.
		if len(driverA.GetConstraintsForTemplate(anyTemplate)) != 0 {
			t.Errorf("Driver A has unexpected state: %v", driverA.GetConstraintsForTemplate(anyTemplate))
		}
		if len(driverB.GetConstraintsForTemplate(anyTemplate)) != 0 {
			t.Errorf("Driver B has unexpected state: %v", driverB.GetConstraintsForTemplate(anyTemplate))
		}
		if len(driverC.GetConstraintsForTemplate(anyTemplate)) != 0 {
			t.Errorf("Driver C has unexpected state: %v", driverC.GetConstraintsForTemplate(anyTemplate))
		}
	})
}

// test remove template with multiple active drivers

func TestDriverForTemplate(t *testing.T) {
	tests := []struct {
		name     string
		options  []Opt
		template *templates.ConstraintTemplate
		expected string
	}{
		{
			name: "One Driver",
			options: []Opt{
				Targets(&handlertest.Handler{Name: pointer.String("h1")}),
				Driver(fake.New("driverA")),
			},
			template: cts.New(cts.OptTargets(
				cts.TargetCustomEngines(
					"h1",
					cts.Code("driverA", (&schema.Source{RejectWith: "MUCH REJECTING"}).ToUnstructured()),
				),
			)),
			expected: "driverA",
		},
		{
			name: "One Driver, Mismatch",
			options: []Opt{
				Targets(&handlertest.Handler{Name: pointer.String("h1")}),
				Driver(fake.New("driverA")),
			},
			template: cts.New(cts.OptTargets(
				cts.TargetCustomEngines(
					"h1",
					cts.Code("driverNoExist", (&schema.Source{RejectWith: "MUCH REJECTING"}).ToUnstructured()),
				),
			)),
			expected: "",
		},
		{
			name: "Multi Driver",
			options: []Opt{
				Targets(&handlertest.Handler{Name: pointer.String("h1")}),
				Driver(fake.New("driverA")),
				Driver(fake.New("driverB")),
			},
			template: cts.New(cts.OptTargets(
				cts.TargetCustomEngines(
					"h1",
					cts.Code("driverA", (&schema.Source{RejectWith: "MUCH REJECTING"}).ToUnstructured()),
				),
			)),
			expected: "driverA",
		},
		{
			name: "Multi Driver, Second",
			options: []Opt{
				Targets(&handlertest.Handler{Name: pointer.String("h1")}),
				Driver(fake.New("driverB")),
				Driver(fake.New("driverA")),
			},
			template: cts.New(cts.OptTargets(
				cts.TargetCustomEngines(
					"h1",
					cts.Code("driverA", (&schema.Source{RejectWith: "MUCH REJECTING"}).ToUnstructured()),
				),
			)),
			expected: "driverA",
		},
		{
			name: "One Driver, Multi-Template",
			options: []Opt{
				Targets(&handlertest.Handler{Name: pointer.String("h1")}),
				Driver(fake.New("driverA")),
			},
			template: cts.New(cts.OptTargets(
				cts.TargetCustomEngines(
					"h1",
					cts.Code("driverA", (&schema.Source{RejectWith: "MUCH REJECTING"}).ToUnstructured()),
					cts.Code("driverB", (&schema.Source{RejectWith: "MUCH REJECTING"}).ToUnstructured()),
				),
			)),
			expected: "driverA",
		},
		{
			name: "One Driver, Multi-Template Second",
			options: []Opt{
				Targets(&handlertest.Handler{Name: pointer.String("h1")}),
				Driver(fake.New("driverB")),
			},
			template: cts.New(cts.OptTargets(
				cts.TargetCustomEngines(
					"h1",
					cts.Code("driverA", (&schema.Source{RejectWith: "MUCH REJECTING"}).ToUnstructured()),
					cts.Code("driverB", (&schema.Source{RejectWith: "MUCH REJECTING"}).ToUnstructured()),
				),
			)),
			expected: "driverB",
		},
		{
			name: "Two Driver, Multi-Template",
			options: []Opt{
				Targets(&handlertest.Handler{Name: pointer.String("h1")}),
				Driver(fake.New("driverA")),
				Driver(fake.New("driverB")),
			},
			template: cts.New(cts.OptTargets(
				cts.TargetCustomEngines(
					"h1",
					cts.Code("driverA", (&schema.Source{RejectWith: "MUCH REJECTING"}).ToUnstructured()),
					cts.Code("driverB", (&schema.Source{RejectWith: "MUCH REJECTING"}).ToUnstructured()),
				),
			)),
			expected: "driverA",
		},
		{
			name: "Two Driver, Multi-Template, Second",
			options: []Opt{
				Targets(&handlertest.Handler{Name: pointer.String("h1")}),
				Driver(fake.New("driverB")),
				Driver(fake.New("driverA")),
			},
			template: cts.New(cts.OptTargets(
				cts.TargetCustomEngines(
					"h1",
					cts.Code("driverA", (&schema.Source{RejectWith: "MUCH REJECTING"}).ToUnstructured()),
					cts.Code("driverB", (&schema.Source{RejectWith: "MUCH REJECTING"}).ToUnstructured()),
				),
			)),
			expected: "driverB",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, err := NewClient(test.options...)
			if err != nil {
				t.Fatal(err)
			}
			result := client.driverForTemplate(test.template)
			if result != test.expected {
				t.Errorf("got %v; wanted %v", result, test.expected)
			}
		})
	}
}
