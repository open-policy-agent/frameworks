package client

import (
	"errors"
	"reflect"
	"testing"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/fake"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler/handlertest"
	"k8s.io/utils/pointer"
)

func TestAddingDrivers(t *testing.T) {
	c, err := NewClient(Targets(&handlertest.Handler{Name: pointer.String("foo")}), Driver(fake.New("driver1")), Driver(fake.New("driver2")))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.driverPriority, map[string]int{"driver1": 1, "driver2": 2}) {
		t.Errorf("driver priority wrong, got %v", c.driverPriority)
	}
	if _, ok := c.drivers["driver1"]; !ok {
		t.Errorf("driver1 missing from driverset")
	}
	if _, ok := c.drivers["driver2"]; !ok {
		t.Errorf("driver2 missing from driverset")
	}
}

func TestNoDuplicates(t *testing.T) {
	_, err := NewClient(Targets(&handlertest.Handler{Name: pointer.String("foo")}), Driver(fake.New("driver1")), Driver(fake.New("driver1")))
	if err == nil {
		t.Fatal("expected error, got none")
	}
	if !errors.Is(err, ErrDuplicateDriver) {
		t.Errorf("wanted duplicate driver error, got %v", err)
	}
}
