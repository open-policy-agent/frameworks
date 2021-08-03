package v1beta1

import (
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"k8s.io/apimachinery/pkg/runtime"
)

// ToVersionless runs defaulting functions and then converts the ConstraintTemplate to the
// versionless api representation
func (versioned *ConstraintTemplate) ToVersionless() (*templates.ConstraintTemplate, error) {
	scheme := runtime.NewScheme()
	if err := AddToScheme(scheme); err != nil {
		return nil, err
	}

	versionedCopy := versioned.DeepCopy()
	scheme.Default(versionedCopy)

	versionless := &templates.ConstraintTemplate{}
	if err := scheme.Convert(versionedCopy, versionless, nil); err != nil {
		return nil, err
	}

	return versionless, nil
}
