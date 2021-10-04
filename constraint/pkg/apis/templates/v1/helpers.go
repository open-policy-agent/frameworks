package v1

import (
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
)

// ToVersionless runs defaulting functions and then converts the ConstraintTemplate to the
// versionless api representation.
func (versioned *ConstraintTemplate) ToVersionless() (*templates.ConstraintTemplate, error) {
	versionedCopy := versioned.DeepCopy()
	sch.Default(versionedCopy)

	versionless := &templates.ConstraintTemplate{}
	if err := sch.Convert(versionedCopy, versionless, nil); err != nil {
		return nil, err
	}

	return versionless, nil
}
