package v1beta1

import (
	"fmt"

	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"k8s.io/apimachinery/pkg/runtime"
)

// ToVersionless runs defaulting functions and then converts the ConstraintTemplate to the
// versionless api representation
func (versioned *ConstraintTemplate) ToVersionless(scheme *runtime.Scheme) (*templates.ConstraintTemplate, error) {
	if scheme == nil {
		return nil, fmt.Errorf("Cannot convert using nil scheme")
	}

	if !scheme.IsVersionRegistered(SchemeGroupVersion) {
		return nil, fmt.Errorf("GroupVersion '%v/%v' not registered in scheme", SchemeGroupVersion.Group, SchemeGroupVersion.Version)
	}

	versionedCopy := versioned.DeepCopy()
	scheme.Default(versionedCopy)

	versionless := &templates.ConstraintTemplate{}
	if err := scheme.Convert(versionedCopy, versionless, nil); err != nil {
		return nil, err
	}

	return versionless, nil
}
