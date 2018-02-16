/*
Package canister provides a dynamically allocated nested map structure for storing and retrieving arbitrary values.

Simple example usage

	func main() {
		c := canister.New()
		c.Set("user.name", "SternRottenMan")
		c.Set("user.id", 1)
		c.Set("user.money", 12.42)

		c.Set("meaning-of-life", 42)
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
		"meaning-of-life": 42,
		"user": {
			"id": 1,
			"money": 12.42,
			"name": "SternRottenMan"
		}
	}

Retrieving values later is easy
	name, ok, err := c.GetString("user.name")
	id, ok, err := c.GetInt64("user.id")
	lot, ok, err := c.GetFloat64("for.some.reason.you.have.to.nest.a.lot")

ok is true if the canister has the property

err is an error for if the value can't be cast to the requested type

If you already have a json string and want a canister, converting the two is also easy

	c, err := canister.Fill("{\"nonce\": 12340972347, \"value\": \"hello world!\"}")
	nonce, ok, err := c.GetInt64("nonce")
	value, ok, err := c.GetString("value")
*/
package canister
