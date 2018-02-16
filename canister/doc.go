/*
Package canister provides a dynamically allocated nested map structure for storing and retrieving arbitrary values.

Simple example usage

	func main() {
		c := canister.New()
		c.Set("user.name", "SternRottenMan")
		c.Set("user.id", 1)
		c.Set("user.money", 12.42)

		c.Set("meaningOfLife", 42)
		c.Set("for.some.reason.you.have.to.nest.a.lot", 9.9999)
	}

Internally, c will look like this:
  {
    "for": {
      "some": {
        "reason": {
          "you": {
            "have": {
              "to": {
                "nest": {
                  "a": {
                    "lot": 12
                  }
                }
              }
            }
          }
        }
      }
    },
    "meaningOfLife": 42,
    "user": {
      "id": 1,
      "money": 12.42,
      "name": "SternRottenMan"
    }
  }

Retrieving values later is easy
	name, ok, err := c.GetString("user.name")
	// "SternRottenMan", true, nil

	id, ok, err := c.GetInt64("user.id")
	// 1, true, nil

	lot, ok, err := c.GetFloat64("for.some.reason.you.have.to.nest.a.lot")
	// 12, true, nil


	dogs, ok, err := c.GetInt64("user.dogs")
	// 0, false, nil

	badType := c.GetInt64("user.name")
	// 0, true, `unable to cast "SternRottenMan" of type string to int64`

ok is true if the canister has the property

err is an error for if the value can't be cast to the requested type

To check if a canister has a value, use Has
	hasMoney := c.Has("user.money")
	// true

	hasDogs := c.Has("user.dogs")
	// false

If you already have a json string and want a canister, converting the two is simple
	c, err := canister.Fill(`{"nonce": 12340972347, "value": "hello world!"}`)
	nonce, ok, err := c.GetInt64("nonce")
	value, ok, err := c.GetString("value")

Canisters can also be filled from files
	c, err := canister.FillFrom("example.json")

To convert a canister to json
	json, err := c.Release()

Canisters can also be released to files
	err := c.ReleaseTo("example.json")
*/
package canister
