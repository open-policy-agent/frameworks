package k8scel

// import (
// 	"context"
// 	"errors"
// 	"fmt"
// 	"strings"
// 	"sync"

// 	apiconstraints "github.com/open-policy-agent/frameworks/constraint/pkg/apis/constraints"
// 	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers"
// 	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
// 	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
// 	"github.com/open-policy-agent/opa/storage"
// 	admissionv1alpha1 "k8s.io/api/admissionregistration/v1alpha1"
// 	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
// 	"k8s.io/apimachinery/pkg/runtime"
// 	"k8s.io/apimachinery/pkg/runtime/schema"
// 	"k8s.io/apiserver/pkg/admission"
// 	"k8s.io/apiserver/pkg/admission/plugin/validatingadmissionpolicy"
// 	"k8s.io/apiserver/pkg/admission/plugin/webhook/generic"
// )

// Friction log:
//   there is no way to re-use the matcher interface here, as it requires an informer... not sure we need to use
//   the matchers, as match Criteria should take care of things

//   "Expression" is a bit confusing, since it doesn't tell me whether "true" implies violation or not: "requirement", "mustSatisfy"?
//
//
//   From the Validation help text:
//      Equality on arrays with list type of 'set' or 'map' ignores element order, i.e. [1, 2] == [2, 1].
//      Concatenation on arrays with x-kubernetes-list-type use the semantics of the list type:
//   Is this type metadata available shift-left? Likely not. Can the expectation be built into the operators?
//
//   Other friction points are commented with the keyword FRICTION

// const Name = "K8sValidation"

// var _ drivers.Driver = &Driver{}

// type Driver struct {
// 	mux        sync.RWMutex
// 	compiler   *validatingadmissionpolicy.CELValidatorCompiler
// 	validators map[string]validatingadmissionpolicy.Validator
// }

// func New() *Driver {
// 	return &Driver{validators: map[string]validatingadmissionpolicy.Validator{}}
// }

// func (d *Driver) Name() string {
// 	return Name
// }

// func (d *Driver) AddTemplate(ctx context.Context, ct *templates.ConstraintTemplate) error {
// 	if len(ct.Spec.Targets) != 1 {
// 		return errors.New("wrong number of targets defined, only 1 target allowed")
// 	}
// 	var rawCode map[string]interface{}
// 	for _, code := range ct.Spec.Targets[0].Code {
// 		if code.Engine != Name {
// 			continue
// 		}
// 		objMap, ok := code.Source.Value.(map[string]interface{})
// 		if !ok {
// 			return errors.New("K8sValidation code malformed")
// 		}
// 		rawCode = objMap
// 		break
// 	}
// 	if rawCode == nil {
// 		return errors.New("K8sValidation code not defined")
// 	}

// 	validatorCode := &admissionv1alpha1.ValidatingAdmissionPolicy{}
// 	if err := runtime.DefaultUnstructuredConverter.FromUnstructuredWithValidation(rawCode, validatorCode, true); err != nil {
// 		return err
// 	}

// 	// FRICTION: Note that compilation errors are possible, but we cannot introspect to see whether any
// 	// occurred
// 	validator := d.compiler.Compile(validatorCode)

// 	d.mux.Lock()
// 	defer d.mux.Unlock()
// 	d.validators[ct.GetName()] = validator
// 	return nil
// }

// func (d *Driver) RemoveTemplate(ctx context.Context, ct *templates.ConstraintTemplate) error {
// 	d.mux.Lock()
// 	defer d.mux.Unlock()
// 	delete(d.validators, ct.GetName())
// 	return nil
// }

// func (d *Driver) AddConstraint(ctx context.Context, constraint *unstructured.Unstructured) error {
// 	return nil
// }

// func (d *Driver) RemoveConstraint(ctx context.Context, constraint *unstructured.Unstructured) error {
// 	return nil
// }

// func (d *Driver) AddData(ctx context.Context, target string, path storage.Path, data interface{}) error {
// 	return nil
// }

// func (d *Driver) RemoveData(ctx context.Context, target string, path storage.Path) error {
// 	return nil
// }

// func (d *Driver) Query(ctx context.Context, target string, constraints []*unstructured.Unstructured, review interface{}, opts ...drivers.QueryOpt) ([]*types.Result, *string, error) {
// 	d.mux.RLock()
// 	defer d.mux.RUnlock()

// 	typedReview, ok := review.(admission.Attributes)
// 	if !ok {
// 		return nil, nil, errors.New("cannot convert review to typed review")
// 	}

// 	results := []*types.Result{}

// 	for _, constraint := range constraints {
// 		// FRICTION/design question: should parameters be created as a "mock" object so that users don't have to type `params.spec.parameters`? How do we prevent visibility into other,
// 		// non-parameter fields, such as `spec.match`? Does it matter? Note that creating a special "parameters" object means that we'd need to copy the constraint contents to
// 		// a special "parameters" object for on-server enforcement with a clean value for "params", which is non-ideal. Could we provide the field of the parameters object and limit scoping to that?
// 		// Then how would we implement custom matchers? Maybe adding variable assignments to the Policy Definition is a better idea? That would at least allow for a convenience handle, even if
// 		// it doesn't scope visibility.

// 		// template name is the lowercase of its kind
// 		validator := d.validators[strings.ToLower(constraint.GetKind())]
// 		if validator == nil {
// 			return nil, nil, fmt.Errorf("unknown constraint template validator: %s", constraint.GetKind())
// 		}
// 		versionedAttr := &generic.VersionedAttributes{
// 			Attributes:         typedReview,
// 			VersionedKind:      typedReview.GetKind(),
// 			VersionedOldObject: typedReview.GetOldObject(),
// 			VersionedObject:    typedReview.GetObject(),
// 		}
// 		// FRICTION: member variables of `decision` are private, which makes it impossible to consume the results. I got around this by forking the apiserver code
// 		decisions, err := validator.Validate(versionedAttr, constraint)
// 		if err != nil {
// 			return nil, nil, err
// 		}

// 		enforcementAction, found, err := unstructured.NestedString(constraint.Object, "spec", "enforcementAction")
// 		if err != nil {
// 			return nil, nil, err
// 		}
// 		if !found {
// 			enforcementAction = apiconstraints.EnforcementActionDeny
// 		}
// 		for _, decision := range decisions {
// 			if decision.Action == validatingadmissionpolicy.ActionDeny {
// 				results = append(results, &types.Result{
// 					Target:            target,
// 					Msg:               decision.Message,
// 					Constraint:        constraint,
// 					EnforcementAction: enforcementAction,
// 				})
// 			}
// 		}
// 	}
// 	return results, nil, nil
// }

// func (d *Driver) Dump(ctx context.Context) (string, error) {
// 	return "", nil
// }

// // FRICTION we should not need to create mocks to use this library offline... this is used for version conversion, which
// // cannot be done reliably offline and is superfluous for audit, as audit scrapes all versions anyway
// // Currently, creating a mock that returns nil and/or errors risks the code breaking on library upgrade. It would be good
// // to have a contract here.
// var _ admission.ObjectInterfaces = &mockObjectInterfaces{}

// type mockObjectInterfaces struct{}

// type mockObjectCreater struct{}

// func (m *mockObjectCreater) New(gvk schema.GroupVersionKind) (runtime.Object, error) {
// 	return nil, errors.New("OBJECT CREATOR NOT IMPLEMENTED")
// }

// func (m *mockObjectInterfaces) GetObjectCreater() runtime.ObjectCreater { return &mockObjectCreater{} }

// func (m *mockObjectInterfaces) GetObjectTyper() runtime.ObjectTyper { return nil }

// func (m *mockObjectInterfaces) GetObjectDefaulter() runtime.ObjectDefaulter { return nil }

// func (m *mockObjectInterfaces) GetObjectConvertor() runtime.ObjectConvertor { return nil }

// func (m *mockObjectInterfaces) GetEquivalentResourceMapper() runtime.EquivalentResourceMapper {
// 	return nil
// }
