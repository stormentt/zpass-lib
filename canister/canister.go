// Package Canister provides easy methods to manipulate arbitrary JSON objects
package canister

import (
	"encoding/json"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cast"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"github.com/stormentt/zpass-lib/util"
)

type Canister struct {
	Contents map[string]interface{}
}

// New initializes & returns a new Canister
func New() *Canister {
	var c Canister
	c.Contents = make(map[string]interface{})
	return &c
}

// Release encodes the canister's contents and writes it to the specified writer, returning any error that occurs
func (c *Canister) Release(w io.Writer) error {
	encoder := json.NewEncoder(w)
	err := encoder.Encode(c.Contents)
	if err != nil {
		log.WithFields(log.Fields{
			"Error": err,
		}).Debug("Unable to release canister")
	}
	return err
}

// ToJson returns the result of encoding the canister's contents to json
func (c *Canister) ToJson() (string, error) {
	json, err := util.EncodeJson(c.Contents)
	if err != nil {
		return "", err
	}
	return json, nil
}

// Fill decodes a json string and stores the resulting object in a new canister's contents
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

// FillFrom returns a new canister created from decoding the contents of the specified file
func FillFrom(path string) (*Canister, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	return Fill(string(bytes))
}

// Get returns the value of the specified property.
// Property should be a string of the form "path.to.property". Every . represents peaking into a map, so path.to.property is looking inside the map "path" for the map "to" for the property "property".
// Get uses the internal method find() to find the specified interface
func (c *Canister) Get(property string) interface{} {
	properties := strings.Split(property, ".")
	return c.find(properties, c.Contents)
}

// Has returns true if the canister has that property, false otherwise
func (c *Canister) Has(property string) bool {
	value := c.Get(property)
	if value == nil {
		return false
	}
	return true
}

// GetString retrieves the specified property & casts it to string
func (c *Canister) GetString(property string) (string, bool) {
	found := c.Get(property)
	if found == nil {
		return "", false
	}
	return cast.ToString(found), true
}

// GetBytes retrieves the specified property & attempts to decode it from Base64 into bytes
func (c *Canister) GetBytes(property string) ([]byte, error) {
	str, ok := c.GetString(property)
	if ok == false {
		return nil, nil
	}
	bytes, err := util.DecodeB64(str)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// GetInt retrieves the specified property & attempts to cast it as an int64
func (c *Canister) GetInt(property string) (int64, error) {
	found := c.Get(property)
	return cast.ToInt64E(found)
}

// GetFloat retrieves the specified property & attempts to cast it as a float64
func (c *Canister) GetFloat(property string) (float64, error) {
	found := c.Get(property)
	return cast.ToFloat64E(found)
}

// find recursively searches a map for the specified key/value pair
// Properties should be a list of keys in nested maps
// Operation:
// 1. Check if the first string in properties has a value in searchMap. If it does not, return nil
// 2. Check the type of the associated value
// 3. If the type is not a map, return that value
// 4. If the type is a map, call find again on the found map
//
// Example:
// configMap:
// {
//   "server": {
//     "database": {
//       "password": "hunter2"
//     }
//   }
// }
//
// find([]string{"server", "database", "password"}, configMap) will return "hunter2"
// First, it would search configMap for the key "server". It would find a map.
// Second, it would search the found map for the key "database". It would find another map.
// Third, it would search that map for the key "password". It would find a non-map and would return that value.
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

// Set will associate the given property with the value
func (c *Canister) Set(property string, value interface{}) *Canister {
	properties := strings.Split(property, ".")
	c.set(properties, value, c.Contents)
	return c
}

// set follows similar rules as find, but if set doesn't find a key at one of its stages it will create a new map.
//
// Example
// setMap:
// {
// }
//
// set([]string{"response", "error"}, "Unable to parse json", setMap) would create a map at the key "response" and assign "error" in that map to "Unable to parse json"
// First, it would search the setMap for the key "response". It would find nothing, so it would create a new map at that location
// Second, it would search the new map for the key "error". It would find nothing, so it would create a new key "error" and give it the value "Unable to parse json"
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
