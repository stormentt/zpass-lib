package canister_test

import (
	"testing"
	"zpass-lib/canister"
	"zpass-lib/util"
)

func TestCanister(t *testing.T) {
	c := canister.New()
	c.Set("testString", "hello world")
	c.Set("testInt", 5)
	c.Set("testFloat", 5.5)

	json, _ := util.EncodeJson(c.Contents)
	t.Logf("%v", json)
	got, _ := c.GetString("testString")
	if got != "hello world" {
		t.Error("Retrieved value not equal to set value")
	}

	gotInt, _ := c.GetInt("testInt")
	if gotInt != 5 {
		t.Error("Retrieved value not equal to set value")
	}

	gotFloat, _ := c.GetFloat("testFloat")
	if gotFloat != 5.5 {
		t.Error("Retrieved value not equal to set value")
	}
}

func TestOverwriting(t *testing.T) {
	c := canister.New()
	c.Set("testing", 1)
	c.Set("testing", 2)
	json, _ := util.EncodeJson(c.Contents)
	t.Logf("%v", json)
	got, _ := c.GetInt("testing")
	if got != 2 {
		t.Error("Overwriting isn't working")
	}
}

func TestNesting(t *testing.T) {
	c := canister.New()
	c.Set("test.in.a.giant.nested.map.this.is.a.lot.of.insides", "hello")
	json, _ := util.EncodeJson(c.Contents)
	t.Logf("%v", json)

	got, _ := c.GetString("test.in.a.giant.nested.map.this.is.a.lot.of.insides")
	if got != "hello" {
		t.Error("Nesting isn't working")
	}
}

func TestFilling(t *testing.T) {
	c, err := canister.Fill(`{"this": 5, "is":{"a":"test"}}`)
	if err != nil {
		t.Errorf("Filling isn't working: %v", err)
	}
	gotThis, _ := c.GetInt("this")
	gotTest, _ := c.GetString("is.a")

	json, _ := util.EncodeJson(c.Contents)
	t.Logf("%v", json)
	if gotThis != 5 {
		t.Error("Retrieving after a fill isn't working")
	}

	if gotTest != "test" {
		t.Error("Retrieving after a fill isn't working")
	}
}
