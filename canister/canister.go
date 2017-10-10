package canister

import (
	"github.com/spf13/cast"
	"strings"
	"zpass-lib/util"
)

type Canister struct {
	Contents map[string]interface{}
}

func New() *Canister {
	var c Canister
	c.Contents = make(map[string]interface{})
	return &c
}

func Fill(input string) (*Canister, error) {
	tempMap := make(map[string]interface{})
	err := util.DecodeJson(input, &tempMap)
	if err != nil {
		return nil, err
	}

	var c Canister
	c.Contents = tempMap
	return &c, nil
}

func (c *Canister) Get(property string) interface{} {
	properties := strings.Split(property, ".")
	return c.find(properties, c.Contents)
}

func (c *Canister) GetString(property string) (string, error) {
	found := c.Get(property)
	return cast.ToStringE(found)
}

func (c *Canister) GetInt(property string) (int, error) {
	found := c.Get(property)
	return cast.ToIntE(found)
}

func (c *Canister) GetFloat(property string) (float64, error) {
	found := c.Get(property)
	return cast.ToFloat64E(found)
}

func (c *Canister) find(properties []string, searchMap map[string]interface{}) interface{} {
	next, ok := searchMap[properties[0]]

	if ok {
		if len(properties) == 1 {
			return next
		}

		switch next.(type) {
		case map[interface{}]interface{}:
			// gotta recurse bc we found a map
			return c.find(properties[1:], cast.ToStringMap(next))
		case map[string]interface{}:
			// gotta recurse bc we found a map
			return c.find(properties[1:], cast.ToStringMap(next))
		default:
			return next
		}
	} else {
		return nil
	}
}
func (c *Canister) Set(property string, value interface{}) *Canister {
	properties := strings.Split(property, ".")
	c.set(properties, value, c.Contents)
	return c
}
func (c *Canister) set(path []string, value interface{}, setMap map[string]interface{}) {
	next, ok := setMap[path[0]]
	if ok == false {
		if len(path) == 1 {
			setMap[path[0]] = value
		} else {
			setMap[path[0]] = make(map[string]interface{})
			c.set(path[1:], value, cast.ToStringMap(setMap[path[0]]))
		}
	} else {
		switch next.(type) {
		case map[interface{}]interface{}:
			c.set(path[1:], value, cast.ToStringMap(next))
		case map[string]interface{}:
			c.set(path[1:], value, cast.ToStringMap(next))
		default:
			setMap[path[0]] = value
		}
	}
}
