package client

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	"github.com/pkg/errors"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8schema "k8s.io/apimachinery/pkg/runtime/schema"
)

var ctx = context.Background()

func newConstraintTemplate(name, rego string) *templates.ConstraintTemplate {
	return &templates.ConstraintTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: strings.ToLower(name)},
		Spec: templates.ConstraintTemplateSpec{
			CRD: templates.CRD{
				Spec: templates.CRDSpec{
					Names: templates.Names{
						Kind: name,
					},
					Validation: &templates.Validation{
						OpenAPIV3Schema: &apiextensions.JSONSchemaProps{
							Properties: map[string]apiextensions.JSONSchemaProps{
								"expected": apiextensions.JSONSchemaProps{Type: "string"},
							},
						},
					},
				},
			},
			Targets: []templates.Target{
				templates.Target{Target: "test.target", Rego: rego},
			},
		},
	}
}

func e(s string, r *types.Responses) error {
	return fmt.Errorf("%s\n%s", s, r.TraceDump())
}

func newConstraint(kind, name string, params map[string]string) *unstructured.Unstructured {
	c := &unstructured.Unstructured{}
	c.SetGroupVersionKind(k8schema.GroupVersionKind{
		Group:   "constraints.gatekeeper.sh",
		Version: "v1alpha1",
		Kind:    kind,
	})
	c.SetName(name)
	unstructured.SetNestedStringMap(c.Object, params, "spec", "parameters")
	return c
}

var tests = map[string]func(Client) error{

	"Add Template": func(c Client) error {
		_, err := c.AddTemplate(ctx, newConstraintTemplate("Foo", `package foo
violation[{"msg": "DENIED", "details": {}}] {
	"always" == "always"
}`))
		return errors.Wrap(err, "AddTemplate")
	},

	"Deny All": func(c Client) error {
		_, err := c.AddTemplate(ctx, newConstraintTemplate("Foo", `package foo
violation[{"msg": "DENIED", "details": {}}] {
	"always" == "always"
}`))
		if err != nil {
			return errors.Wrap(err, "AddTemplate")
		}
		cstr := newConstraint("Foo", "ph", nil)
		if _, err := c.AddConstraint(ctx, cstr); err != nil {
			return errors.Wrap(err, "AddConstraint")
		}
		rsps, err := c.Review(ctx, targetData{Name: "Sara", ForConstraint: "Foo"})
		if err != nil {
			return errors.Wrap(err, "Review")
		}
		if len(rsps.ByTarget) == 0 {
			return errors.New("No responses returned")
		}
		if len(rsps.Results()) != 1 {
			return e("Bad number of results", rsps)
		}
		if !reflect.DeepEqual(rsps.Results()[0].Constraint, cstr) {
			return e(fmt.Sprintf("Constraint %s != %s", spew.Sdump(rsps.Results()[0].Constraint), spew.Sdump(cstr)), rsps)
		}
		if rsps.Results()[0].Msg != "DENIED" {
			return e(fmt.Sprintf("res.Msg = %s; wanted DENIED", rsps.Results()[0].Msg), rsps)
		}
		return nil
	},

	"Deny By Parameter": func(c Client) error {
		_, err := c.AddTemplate(ctx, newConstraintTemplate("Foo", `package foo
violation[{"msg": "DENIED", "details": {}}] {
	input.parameters.name == input.review.Name
}`))
		if err != nil {
			return errors.Wrap(err, "AddTemplate")
		}
		cstr := newConstraint("Foo", "ph", map[string]string{"name": "deny_me"})
		if _, err := c.AddConstraint(ctx, cstr); err != nil {
			return errors.Wrap(err, "AddConstraint")
		}
		rsps, err := c.Review(ctx, targetData{Name: "deny_me", ForConstraint: "Foo"})
		if err != nil {
			return errors.Wrap(err, "Review")
		}
		if len(rsps.ByTarget) == 0 {
			return errors.New("No responses returned")
		}
		if len(rsps.Results()) != 1 {
			return e("Bad number of results", rsps)
		}
		if !reflect.DeepEqual(rsps.Results()[0].Constraint, cstr) {
			return e(fmt.Sprintf("Constraint %s != %s", spew.Sdump(rsps.Results()[0].Constraint), spew.Sdump(cstr)), rsps)
		}
		if rsps.Results()[0].Msg != "DENIED" {
			return e(fmt.Sprintf("res.Msg = %s; wanted DENIED", rsps.Results()[0].Msg), rsps)
		}

		rsps, err = c.Review(ctx, targetData{Name: "Sara", ForConstraint: "Foo"})
		if err != nil {
			return errors.Wrap(err, "Review")
		}
		if len(rsps.ByTarget) == 0 {
			return errors.New("No responses returned for second test")
		}
		if len(rsps.Results()) != 0 {
			return e("Expected no results", rsps)
		}
		return nil
	},

	"Deny All Audit x2": func(c Client) error {
		_, err := c.AddTemplate(ctx, newConstraintTemplate("Foo", `package foo
	violation[{"msg": "DENIED", "details": {}}] {
		"always" == "always"
	}`))
		if err != nil {
			return errors.Wrap(err, "AddTemplate")
		}
		cstr := newConstraint("Foo", "ph", nil)
		if _, err := c.AddConstraint(ctx, cstr); err != nil {
			return errors.Wrap(err, "AddConstraint")
		}
		obj := &targetData{Name: "Sara", ForConstraint: "Foo"}
		if _, err := c.AddData(ctx, obj); err != nil {
			return errors.Wrap(err, "AddData")
		}
		obj2 := &targetData{Name: "Max", ForConstraint: "Foo"}
		if _, err := c.AddData(ctx, obj2); err != nil {
			return errors.Wrap(err, "AddDataX2")
		}
		rsps, err := c.Audit(ctx)
		if err != nil {
			return errors.Wrap(err, "Audit")
		}
		if len(rsps.ByTarget) == 0 {
			return errors.New("No responses returned")
		}
		if len(rsps.Results()) != 2 {
			return e("Bad number of results", rsps)
		}
		for _, r := range rsps.Results() {
			if !reflect.DeepEqual(r.Constraint, cstr) {
				return e(fmt.Sprintf("Constraint %s != %s", spew.Sdump(rsps.Results()[0].Constraint), spew.Sdump(cstr)), rsps)
			}
			if r.Msg != "DENIED" {
				return e(fmt.Sprintf("res.Msg = %s; wanted DENIED", rsps.Results()[0].Msg), rsps)
			}
		}
		return nil
	},

	"Deny All Audit": func(c Client) error {
		_, err := c.AddTemplate(ctx, newConstraintTemplate("Foo", `package foo
	violation[{"msg": "DENIED", "details": {}}] {
		"always" == "always"
	}`))
		if err != nil {
			return errors.Wrap(err, "AddTemplate")
		}
		cstr := newConstraint("Foo", "ph", nil)
		if _, err := c.AddConstraint(ctx, cstr); err != nil {
			return errors.Wrap(err, "AddConstraint")
		}
		obj := &targetData{Name: "Sara", ForConstraint: "Foo"}
		if _, err := c.AddData(ctx, obj); err != nil {
			return errors.Wrap(err, "AddData")
		}
		rsps, err := c.Audit(ctx)
		if err != nil {
			return errors.Wrap(err, "Audit")
		}
		if len(rsps.ByTarget) == 0 {
			return errors.New("No responses returned")
		}
		if len(rsps.Results()) != 1 {
			return e("Bad number of results", rsps)
		}
		if !reflect.DeepEqual(rsps.Results()[0].Constraint, cstr) {
			return e(fmt.Sprintf("Constraint %s != %s", spew.Sdump(rsps.Results()[0].Constraint), spew.Sdump(cstr)), rsps)
		}
		if rsps.Results()[0].Msg != "DENIED" {
			return e(fmt.Sprintf("res.Msg = %s; wanted DENIED", rsps.Results()[0].Msg), rsps)
		}
		if !reflect.DeepEqual(rsps.Results()[0].Resource, obj) {
			return e(fmt.Sprintf("Resource %s != %s", spew.Sdump(rsps.Results()[0].Resource), spew.Sdump(obj)), rsps)
		}
		return nil
	},

	"Autoreject All": func(c Client) error {
		_, err := c.AddTemplate(ctx, newConstraintTemplate("Foo", `package foo
violation[{"msg": "DENIED", "details": {}}] {
	"always" == "always"
}`))
		if err != nil {
			return errors.Wrap(err, "AddTemplate")
		}
		goodNamespaceSelectorConstraint := `
{
	"apiVersion": "constraints.gatekeeper.sh/v1alpha1",
	"kind": "Foo",
	"metadata": {
  	"name": "foo-pod"
	},
	"spec": {
  	"match": {
    	"kinds": [
      	{
			"apiGroups": [""],
        	"kinds": ["Pod"]
		}],
		"namespaceSelector": {
			"matchExpressions": [{
	     		"key": "someKey",
				"operator": "Blah",
				"values": ["some value"]
			}]
		}
	},
  	"parameters": {
    	"key": ["value"]
		}
	}
}
`
		u := &unstructured.Unstructured{}
		err = json.Unmarshal([]byte(goodNamespaceSelectorConstraint), u)
		if err != nil {
			return errors.Wrap(err, "Unable to parse constraint JSON")
		}
		if _, err := c.AddConstraint(ctx, u); err != nil {
			return errors.Wrap(err, "AddConstraint")
		}
		rsps, err := c.Review(ctx, targetData{Name: "Sara", ForConstraint: "Foo"})
		if err != nil {
			return errors.Wrap(err, "Review")
		}
		if len(rsps.ByTarget) == 0 {
			return errors.New("No responses returned")
		}
		if len(rsps.Results()) != 2 {
			return e("Bad number of results", rsps)
		}
		if rsps.Results()[0].Msg != "REJECTION" && rsps.Results()[1].Msg != "REJECTION" {
			return e(fmt.Sprintf("res.Msg = %s; wanted at least one REJECTION", rsps.Results()[0].Msg), rsps)
		}
		for _, r := range rsps.Results() {
			if r.Msg == "REJECTION" && !reflect.DeepEqual(r.Constraint, u) {
				return e(fmt.Sprintf("Constraint %s != %s", spew.Sdump(r.Constraint), spew.Sdump(u)), rsps)
			}
		}
		return nil
	},

	"Remove Data": func(c Client) error {
		_, err := c.AddTemplate(ctx, newConstraintTemplate("Foo", `package foo
	violation[{"msg": "DENIED", "details": {}}] {
		"always" == "always"
	}`))
		if err != nil {
			return errors.Wrap(err, "AddTemplate")
		}
		cstr := newConstraint("Foo", "ph", nil)
		if _, err := c.AddConstraint(ctx, cstr); err != nil {
			return errors.Wrap(err, "AddConstraint")
		}
		obj := &targetData{Name: "Sara", ForConstraint: "Foo"}
		if _, err := c.AddData(ctx, obj); err != nil {
			return errors.Wrap(err, "AddData")
		}
		obj2 := &targetData{Name: "Max", ForConstraint: "Foo"}
		if _, err := c.AddData(ctx, obj2); err != nil {
			return errors.Wrap(err, "AddDataX2")
		}
		rsps, err := c.Audit(ctx)
		if err != nil {
			return errors.Wrap(err, "Audit")
		}
		if len(rsps.ByTarget) == 0 {
			return errors.New("No responses returned")
		}
		if len(rsps.Results()) != 2 {
			return e("Bad number of results", rsps)
		}
		for _, r := range rsps.Results() {
			if !reflect.DeepEqual(r.Constraint, cstr) {
				return e(fmt.Sprintf("Constraint %s != %s", spew.Sdump(rsps.Results()[0].Constraint), spew.Sdump(cstr)), rsps)
			}
			if r.Msg != "DENIED" {
				return e(fmt.Sprintf("res.Msg = %s; wanted DENIED", rsps.Results()[0].Msg), rsps)
			}
		}

		if _, err := c.RemoveData(ctx, obj2); err != nil {
			return errors.Wrapf(err, "RemoveData")
		}
		rsps2, err := c.Audit(ctx)
		if err != nil {
			return errors.Wrapf(err, "AuditX2")
		}
		if len(rsps2.ByTarget) == 0 {
			return errors.New("No responses returned")
		}
		if len(rsps2.Results()) != 1 {
			return e("Bad number of results", rsps2)
		}
		if !reflect.DeepEqual(rsps2.Results()[0].Constraint, cstr) {
			return e(fmt.Sprintf("Constraint %s != %s", spew.Sdump(rsps2.Results()[0].Constraint), spew.Sdump(cstr)), rsps2)
		}
		if rsps2.Results()[0].Msg != "DENIED" {
			return e(fmt.Sprintf("res.Msg = %s; wanted DENIED", rsps2.Results()[0].Msg), rsps2)
		}
		if !reflect.DeepEqual(rsps2.Results()[0].Resource, obj) {
			return e(fmt.Sprintf("Resource %s != %s", spew.Sdump(rsps2.Results()[0].Resource), spew.Sdump(obj)), rsps2)
		}
		return nil
	},

	"Remove Constraint": func(c Client) error {
		_, err := c.AddTemplate(ctx, newConstraintTemplate("Foo", `package foo
	violation[{"msg": "DENIED", "details": {}}] {
		"always" == "always"
	}`))
		if err != nil {
			return errors.Wrap(err, "AddTemplate")
		}
		cstr := newConstraint("Foo", "ph", nil)
		if _, err := c.AddConstraint(ctx, cstr); err != nil {
			return errors.Wrap(err, "AddConstraint")
		}
		obj := &targetData{Name: "Sara", ForConstraint: "Foo"}
		if _, err := c.AddData(ctx, obj); err != nil {
			return errors.Wrap(err, "AddData")
		}
		rsps, err := c.Audit(ctx)
		if err != nil {
			return errors.Wrap(err, "Audit")
		}
		if len(rsps.ByTarget) == 0 {
			return errors.New("No responses returned")
		}
		if len(rsps.Results()) != 1 {
			return e("Bad number of results", rsps)
		}
		if !reflect.DeepEqual(rsps.Results()[0].Constraint, cstr) {
			return e(fmt.Sprintf("Constraint %s != %s", spew.Sdump(rsps.Results()[0].Constraint), spew.Sdump(cstr)), rsps)
		}
		if rsps.Results()[0].Msg != "DENIED" {
			return e(fmt.Sprintf("res.Msg = %s; wanted DENIED", rsps.Results()[0].Msg), rsps)
		}
		if !reflect.DeepEqual(rsps.Results()[0].Resource, obj) {
			return e(fmt.Sprintf("Resource %s != %s", spew.Sdump(rsps.Results()[0].Resource), spew.Sdump(obj)), rsps)
		}

		if _, err := c.RemoveConstraint(ctx, cstr); err != nil {
			return errors.Wrap(err, "RemoveConstraint")
		}
		rsps2, err := c.Audit(ctx)
		if err != nil {
			return errors.Wrap(err, "AuditX2")
		}
		if len(rsps2.Results()) != 0 {
			return e("Responses returned", rsps2)
		}
		return nil
	},

	"Remove Template": func(c Client) error {
		tmpl := newConstraintTemplate("Foo", `package foo
	violation[{"msg": "DENIED", "details": {}}] {
		"always" == "always"
	}`)
		_, err := c.AddTemplate(ctx, tmpl)
		if err != nil {
			return errors.Wrap(err, "AddTemplate")
		}
		cstr := newConstraint("Foo", "ph", nil)
		if _, err := c.AddConstraint(ctx, cstr); err != nil {
			return errors.Wrap(err, "AddConstraint")
		}
		obj := &targetData{Name: "Sara", ForConstraint: "Foo"}
		if _, err := c.AddData(ctx, obj); err != nil {
			return errors.Wrap(err, "AddData")
		}
		rsps, err := c.Audit(ctx)
		if err != nil {
			return errors.Wrap(err, "Audit")
		}
		if len(rsps.ByTarget) == 0 {
			return errors.New("No responses returned")
		}
		if len(rsps.Results()) != 1 {
			return e("Bad number of results", rsps)
		}
		if !reflect.DeepEqual(rsps.Results()[0].Constraint, cstr) {
			return e(fmt.Sprintf("Constraint %s != %s", spew.Sdump(rsps.Results()[0].Constraint), spew.Sdump(cstr)), rsps)
		}
		if rsps.Results()[0].Msg != "DENIED" {
			return e(fmt.Sprintf("res.Msg = %s; wanted DENIED", rsps.Results()[0].Msg), rsps)
		}
		if !reflect.DeepEqual(rsps.Results()[0].Resource, obj) {
			return e(fmt.Sprintf("Resource %s != %s", spew.Sdump(rsps.Results()[0].Resource), spew.Sdump(obj)), rsps)
		}

		if _, err := c.RemoveTemplate(ctx, tmpl); err != nil {
			return errors.Wrap(err, "RemoveTemplate")
		}
		rsps2, err := c.Audit(ctx)
		if err != nil {
			return errors.Wrap(err, "AuditX2")
		}
		if len(rsps2.Results()) != 0 {
			return e("Responses returned", rsps2)
		}
		return nil
	},

	"Tracing Off": func(c Client) error {
		_, err := c.AddTemplate(ctx, newConstraintTemplate("Foo", `package foo
violation[{"msg": "DENIED", "details": {}}] {
	"always" == "always"
}`))
		if err != nil {
			return errors.Wrap(err, "AddTemplate")
		}
		cstr := newConstraint("Foo", "ph", nil)
		if _, err := c.AddConstraint(ctx, cstr); err != nil {
			return errors.Wrap(err, "AddConstraint")
		}
		rsps, err := c.Review(ctx, targetData{Name: "Sara", ForConstraint: "Foo"})
		if err != nil {
			return errors.Wrap(err, "Review")
		}
		if len(rsps.ByTarget) == 0 {
			return errors.New("No responses returned")
		}
		if len(rsps.Results()) != 1 {
			return e("Bad number of results", rsps)
		}
		for _, r := range rsps.ByTarget {
			if r.Trace != nil {
				return e("Trace dump not nil", rsps)
			}
		}
		return nil
	},

	"Tracing On": func(c Client) error {
		_, err := c.AddTemplate(ctx, newConstraintTemplate("Foo", `package foo
violation[{"msg": "DENIED", "details": {}}] {
	"always" == "always"
}`))
		if err != nil {
			return errors.Wrap(err, "AddTemplate")
		}
		cstr := newConstraint("Foo", "ph", nil)
		if _, err := c.AddConstraint(ctx, cstr); err != nil {
			return errors.Wrap(err, "AddConstraint")
		}
		rsps, err := c.Review(ctx, targetData{Name: "Sara", ForConstraint: "Foo"}, Tracing(true))
		if err != nil {
			return errors.Wrap(err, "Review")
		}
		if len(rsps.ByTarget) == 0 {
			return errors.New("No responses returned")
		}
		if len(rsps.Results()) != 1 {
			return e("Bad number of results", rsps)
		}
		for _, r := range rsps.ByTarget {
			if r.Trace == nil {
				return e("Trace dump nil", rsps)
			}
		}
		return nil
	},

	"Audit Tracing Enabled": func(c Client) error {
		_, err := c.AddTemplate(ctx, newConstraintTemplate("Foo", `package foo
	violation[{"msg": "DENIED", "details": {}}] {
		"always" == "always"
	}`))
		if err != nil {
			return errors.Wrap(err, "AddTemplate")
		}
		cstr := newConstraint("Foo", "ph", nil)
		if _, err := c.AddConstraint(ctx, cstr); err != nil {
			return errors.Wrap(err, "AddConstraint")
		}
		obj := &targetData{Name: "Sara", ForConstraint: "Foo"}
		if _, err := c.AddData(ctx, obj); err != nil {
			return errors.Wrap(err, "AddData")
		}
		obj2 := &targetData{Name: "Max", ForConstraint: "Foo"}
		if _, err := c.AddData(ctx, obj2); err != nil {
			return errors.Wrap(err, "AddDataX2")
		}
		rsps, err := c.Audit(ctx, Tracing(true))
		if err != nil {
			return errors.Wrap(err, "Audit")
		}
		if len(rsps.ByTarget) == 0 {
			return errors.New("No responses returned")
		}
		if len(rsps.Results()) != 2 {
			return e("Bad number of results", rsps)
		}
		for _, r := range rsps.ByTarget {
			if r.Trace == nil {
				return e("Trace dump nil", rsps)
			}
		}
		return nil
	},

	"Audit Tracing Disabled": func(c Client) error {
		_, err := c.AddTemplate(ctx, newConstraintTemplate("Foo", `package foo
	violation[{"msg": "DENIED", "details": {}}] {
		"always" == "always"
	}`))
		if err != nil {
			return errors.Wrap(err, "AddTemplate")
		}
		cstr := newConstraint("Foo", "ph", nil)
		if _, err := c.AddConstraint(ctx, cstr); err != nil {
			return errors.Wrap(err, "AddConstraint")
		}
		obj := &targetData{Name: "Sara", ForConstraint: "Foo"}
		if _, err := c.AddData(ctx, obj); err != nil {
			return errors.Wrap(err, "AddData")
		}
		obj2 := &targetData{Name: "Max", ForConstraint: "Foo"}
		if _, err := c.AddData(ctx, obj2); err != nil {
			return errors.Wrap(err, "AddDataX2")
		}
		rsps, err := c.Audit(ctx, Tracing(false))
		if err != nil {
			return errors.Wrap(err, "Audit")
		}
		if len(rsps.ByTarget) == 0 {
			return errors.New("No responses returned")
		}
		if len(rsps.Results()) != 2 {
			return e("Bad number of results", rsps)
		}
		for _, r := range rsps.ByTarget {
			if r.Trace != nil {
				return e("Trace dump not nil", rsps)
			}
		}
		return nil
	},
}

// TODO: Test metadata, test idempotence, test multiple targets
