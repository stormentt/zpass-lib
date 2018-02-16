package canister

import (
	"io/ioutil"
	"os"
	"strings"

	"github.com/spf13/cast"
	"github.com/stormentt/zpass-lib/util"
)

// Canister provides a dynamically allocated nestable map
type Canister struct {
	contents map[string]interface{}
}

// New initializes & returns a new Canister
func New() *Canister {
	return &Canister{make(map[string]interface{})}
}

// Fill decodes an input string into a Canister
func Fill(input string) (*Canister, error) {
	tmp := make(map[string]interface{})
	err := util.DecodeJson(input, &tmp)
	if err != nil {
		return nil, err
	}

	return &Canister{tmp}, nil
}

// FillFrom decodes the file at path into a Canister
func FillFrom(path string) (*Canister, error) {
	in, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer in.Close()

	bytes, err := ioutil.ReadAll(in)
	if err != nil {
		return nil, err
	}

	return Fill(string(bytes))
}

// Release returns the json representation of a Canister
func (c *Canister) Release() (string, error) {
	return util.EncodeJson(c.contents)
}

// ReleaseTo writes the json representation of a Canister to a new file
//
// If the file exists, ReleaseTo will overwrite it.
func (c *Canister) ReleaseTo(path string) error {
	json, err := c.Release()
	if err != nil {
		return err
	}

	out, err := os.Create(path)
	if err != nil {
		return err
	}

	_, err = out.Write([]byte(json))
	if err != nil {
		return err
	}

	err = out.Close()
	if err != nil {
		return err
	}

	return nil
}

// Has returns true if the canister has a value for that property, false otherwise
func (c *Canister) Has(property string) bool {
	_, ok := c.Get(property)
	return ok
}

// GetFloat64 returns the float64 representation of a property
func (c *Canister) GetFloat64(property string) (casted float64, ok bool, err error) {
	val, ok := c.Get(property)
	casted, err = cast.ToFloat64E(val)
	return
}

// GetInt64 returns the int64 representation of a property
func (c *Canister) GetInt64(property string) (casted int64, ok bool, err error) {
	val, ok := c.Get(property)
	casted, err = cast.ToInt64E(val)
	return
}

// GetBytes returns the []byte representation of a property
func (c *Canister) GetBytes(property string) (casted []byte, ok bool, err error) {
	castString, ok, err := c.GetString(property)
	if !ok || err != nil {
		return
	}

	casted = []byte(castString)
	return
}

// GetString returns the string representation of a property
func (c *Canister) GetString(property string) (casted string, ok bool, err error) {
	val, ok := c.Get(property)
	casted, err = cast.ToStringE(val)
	return
}

// Get returns the value at the property
func (c *Canister) Get(property string) (interface{}, bool) {
	path := strings.Split(property, ".")
	return c.get(path, c.contents)
}

// get searches for a map and returns the value at that property and a boolean indicating if the value was found
func (c *Canister) get(path []string, searchMap map[string]interface{}) (interface{}, bool) {
	next, ok := searchMap[path[0]]
	if !ok {
		return nil, false
	}

	if len(path) == 1 {
		return next, true
	}

	switch next.(type) {
	case map[interface{}]interface{}:
		return c.get(path[1:], cast.ToStringMap(next))
	case map[string]interface{}:
		return c.get(path[1:], cast.ToStringMap(next))
	default:
		return next, true
	}
}

// Set sets the property to the value
func (c *Canister) Set(property string, value interface{}) *Canister {
	path := strings.Split(property, ".")
	c.set(path, value, c.contents)
	return c
}

// set dynamically allocates nested maps and sets the property's value
func (c *Canister) set(path []string, value interface{}, setMap map[string]interface{}) {
	next, ok := setMap[path[0]]
	if ok {
		switch next.(type) {
		case map[interface{}]interface{}:
			c.set(path[1:], value, cast.ToStringMap(next))
		case map[string]interface{}:
			c.set(path[1:], value, cast.ToStringMap(next))
		default:
			setMap[path[0]] = value
		}
	} else {
		if len(path) == 1 {
			setMap[path[0]] = value
		} else {
			setMap[path[0]] = make(map[string]interface{})
			c.set(path[1:], value, cast.ToStringMap(setMap[path[0]]))
		}
	}
}
