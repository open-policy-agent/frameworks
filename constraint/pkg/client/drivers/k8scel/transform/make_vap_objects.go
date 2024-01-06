package transform

import (
	"fmt"
	"strings"

	apiconstraints "github.com/open-policy-agent/frameworks/constraint/pkg/apis/constraints"
	templatesv1beta1 "github.com/open-policy-agent/frameworks/constraint/pkg/apis/templates/v1beta1"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/k8scel/schema"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	admissionregistrationv1alpha1 "k8s.io/api/admissionregistration/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

func TemplateToPolicyDefinition(template *templates.ConstraintTemplate) (*admissionregistrationv1alpha1.ValidatingAdmissionPolicy, error) {
	source, err := schema.GetSourceFromTemplate(template)
	if err != nil {
		return nil, err
	}

	matchConditions, err := source.GetV1Alpha1MatchConditions()
	if err != nil {
		return nil, err
	}
	matchConditions = append(matchConditions, AllMatchersV1Alpha1()...)

	validations, err := source.GetV1Alpha1Validatons()
	if err != nil {
		return nil, err
	}

	variables, err := source.GetV1Alpha1Variables()
	if err != nil {
		return nil, err
	}
	variables = append(variables, AllVariablesV1Alpha1()...)

	failurePolicy, err := source.GetV1alpha1FailurePolicy()
	if err != nil {
		return nil, err
	}

	policy := &admissionregistrationv1alpha1.ValidatingAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("g8r-%s", template.GetName()),
		},
		Spec: admissionregistrationv1alpha1.ValidatingAdmissionPolicySpec{
			ParamKind: &admissionregistrationv1alpha1.ParamKind{
				APIVersion: templatesv1beta1.SchemeGroupVersion.Version,
				Kind:       template.Spec.CRD.Spec.Names.Kind,
			},
			MatchConstraints: nil, // We cannot support match constraints since `resource` is not available shift-left
			MatchConditions:  matchConditions,
			Validations:      validations,
			FailurePolicy:    failurePolicy,
			AuditAnnotations: nil,
			Variables:        variables,
		},
	}
	return policy, nil
}

func ConstraintToBinding(constraint *unstructured.Unstructured) (*admissionregistrationv1alpha1.ValidatingAdmissionPolicyBinding, error) {
	enforcementActionStr, err := apiconstraints.GetEnforcementAction(constraint)
	if err != nil {
		return nil, err
	}

	var enforcementAction admissionregistrationv1alpha1.ValidationAction
	switch enforcementActionStr {
	case apiconstraints.EnforcementActionDeny:
		enforcementAction = admissionregistrationv1alpha1.Deny
	case "warn":
		enforcementAction = admissionregistrationv1alpha1.Warn
	default:
		return nil, fmt.Errorf("%w: unrecognized enforcement action %s, must be `warn` or `deny`", ErrBadEnforcementAction, enforcementActionStr)
	}

	binding := &admissionregistrationv1alpha1.ValidatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("g8r-%s", constraint.GetName()),
		},
		Spec: admissionregistrationv1alpha1.ValidatingAdmissionPolicyBindingSpec{
			PolicyName: fmt.Sprintf("g8r-%s", strings.ToLower(constraint.GetKind())),
			ParamRef: &admissionregistrationv1alpha1.ParamRef{
				Name: constraint.GetName(),
			},
			MatchResources:    &admissionregistrationv1alpha1.MatchResources{},
			ValidationActions: []admissionregistrationv1alpha1.ValidationAction{enforcementAction},
		},
	}
	objectSelectorMap, found, err := unstructured.NestedMap(constraint.Object, "spec", "match", "labelSelector")
	if err != nil {
		return nil, err
	}
	var objectSelector *metav1.LabelSelector
	if found {
		objectSelector = &metav1.LabelSelector{}
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(objectSelectorMap, objectSelector); err != nil {
			return nil, err
		}
		binding.Spec.MatchResources.ObjectSelector = objectSelector
	}

	namespaceSelectorMap, found, err := unstructured.NestedMap(constraint.Object, "spec", "match", "namespaceSelector")
	if err != nil {
		return nil, err
	}
	var namespaceSelector *metav1.LabelSelector
	if found {
		namespaceSelector = &metav1.LabelSelector{}
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(namespaceSelectorMap, namespaceSelector); err != nil {
			return nil, err
		}
		binding.Spec.MatchResources.NamespaceSelector = namespaceSelector
	}
	return binding, nil
}
