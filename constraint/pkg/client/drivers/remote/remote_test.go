package remote

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

type testClient struct {
	queryResponse json.RawMessage
}

func (c *testClient) InsertPolicy(id string, bs []byte) error {
	return errors.New("NOT IMPLEMENTED")
}

func (c *testClient) DeletePolicy(id string) error {
	return errors.New("NOT IMPLEMENTED")
}

func (c *testClient) ListPolicies() (*QueryResult, error) {
	return nil, errors.New("NOT IMPLEMENTED")
}

func (c *testClient) Prefix(path string) Data {
	return c
}

func (c *testClient) PatchData(path string, op string, value *interface{}) error {
	return errors.New("NOT IMPLEMENTED")
}

func (c *testClient) PutData(path string, value interface{}) error {
	return errors.New("NOT IMPLEMENTED")
}

func (c *testClient) PostData(path string, value interface{}) (json.RawMessage, error) {
	return nil, errors.New("NOT IMPLEMENTED")
}

func (c *testClient) DeleteData(path string) error {
	return errors.New("NOT IMPLEMENTED")
}

func (c *testClient) Query(path string, value interface{}) (*QueryResult, error) {
	return &QueryResult{Result: c.queryResponse}, nil
}

func newTestClient(resp string) *testClient {
	return &testClient{queryResponse: json.RawMessage(resp)}
}

const response = `
[
	{
		"msg": "totally invalid",
		"metadata": {"details": {"not": "good"}},
		"constraint": {
			"apiVersion": "constraints.gatekeeper.sh/v1",
			"kind": "RequiredLabels",
			"metadata": {
				"name": "require-a-label"
			},
			"spec": {
				"parameters": {"hello": "world"}
			}
		},
		"resource": {"hi": "there"}
	},
	{
		"msg": "yep"
	}
]
`

func TestQuery(t *testing.T) {
	t.Run("Parse Response", func(t *testing.T) {
		d := driver{opa: newTestClient(response)}
		res, err := d.Query(context.Background(), "random", nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Results) != 2 {
			t.Errorf("Expected length to be 2 but got: %d", len(res.Results))
		}
		if res.Results[0].Msg != "totally invalid" {
			t.Errorf("Expected res[0].Msg to be `totally invalid` but got: %s", res.Results[0].Msg)
		}
		if res.Results[1].Msg != "yep" {
			t.Errorf("Expected res[1].Msg to be `yep` but got: %s", res.Results[1].Msg)
		}
	})
}
