package client

import (
	"bytes"
	"fmt"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/regolib"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// NewClient creates a new client.
func NewClient(opts ...Opt) (*Client, error) {
	c := &Client{
		constraints: make(map[schema.GroupKind]map[string]*unstructured.Unstructured),
		templates:   make(map[templateKey]*templateEntry),
	}

	for _, opt := range opts {
		if err := opt(c); err != nil {
			return nil, err
		}
	}

	if len(c.targets) == 0 {
		return nil, fmt.Errorf("%w: must specify at least one target with client.Targets",
			ErrCreatingClient)
	}

	for targetName := range c.targets {
		hooks := fmt.Sprintf(`hooks["%s"]`, targetName)
		templMap := map[string]string{"Target": targetName}

		libBuiltin := &bytes.Buffer{}
		if err := regolib.TargetLib.Execute(libBuiltin, templMap); err != nil {
			return nil, err
		}

		builtinPath := fmt.Sprintf("%s.hooks_builtin", hooks)
		err := c.driver.PutModule(builtinPath, libBuiltin.String())
		if err != nil {
			return nil, err
		}
	}

	return c, nil
}
