# zpass-lib
utility library for the [zpass server](https://github.com/stormentt/zpass-server) &amp; [client](https://github.com/stormentt/zpass-client)
## Features
### JSON Canister
Canister is an easy way to manage arbitrary JSON objects. 
It essentially decodes json objects into nested map[string]interface{}'s and allows access to nested properties with "path.to.property" style arguments
Example:
```
canister.Get("server.database.host")
```

### Cryptography interfaces
Zpass-lib provides two interfaces for cryptography: Crypter & Hasher. 
Both come with functions to generate/derive appropriately sized keys & nonces.
I intend to support more than just ChaCha20-Poly1305 and HMAC-SHA512. Asymmetric cryptography support is on the way. 
```
Crypter.Encrypt("message")
```

### Nonce creation
Easy creation of timestamped nonces through the nonces package.
```
nonces.New()
```

### Random
Easy generation of different types of cryptographically secure random generation through the crypto/rand package
* Bytes(): Generates random bytes
* Int(): Generates a random integer
* AlphaNum(): Generates a random alphanumeric string

### Utilities for commonly used functions
* Json/B64 encoding/decoding
* Asking for passwords with masking
* Combining byte slices

## Testing
Every package in zpass-lib has unit tests associated with them. Some of them even have benchmarks.

```
go test zpass-lib/crypt
```

## Libraries used

* [Cast](https://github.com/spf13/cast)
* [Logrus](https://github.com/sirupsen/logrus)

## Contributing

I'll review pull requests & potentially integrate them. I'll have a contribution guide eventually.

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/stormentt/zpass-client/tags). 

## Authors

* Tanner Storment - Everything so far

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgements
* [Viper](https://github.com/spf13/viper) for inspiring the JSON canister syntax
