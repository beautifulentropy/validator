# Package `validator`

```
This is a fork of https://github.com/go-playground/validator/v10 which has been
stripped of tags we don't plan to use. 
```

Package validator implements value validations for structs and individual fields based on tags.

It has the following **unique** features:

- Cross Field and Cross Struct validations by using validation tags or custom validators.
- Slice, Array and Map diving, which allows any or all levels of a multidimensional field to be validated.
- Ability to dive into both map keys and values for validation
- Handles type interface by determining it's underlying type prior to validation.
- Handles custom field types such as sql driver Valuer see [Valuer](https://golang.org/src/database/sql/driver/types.go?s=1210:1293#L29)
- Alias validation tags, which allows for mapping of several validations to a single tag for easier defining of validations on structs
- Extraction of custom defined Field Name e.g. can specify to extract the JSON name while validating and have it available in the resulting FieldError
- Customizable i18n aware error messages.

## Installation

Use go get.
```shell
go get github.com/beautifulentropy/validator/v10
```

Then import the validator package into your own code.
```go
import "github.com/beautifulentropy/validator/v10"
```

## Error Return Value

Validation functions return type error

They return type error to avoid the issue discussed in the following, where err is always != nil:

* http://stackoverflow.com/a/29138676/3158232
* https://github.com/go-playground/validator/issues/134

Validator returns only InvalidValidationError for bad validation input, nil or ValidationErrors as type error; so, in your code all you need to do is check if the error returned is not nil, and if it's not check if error is InvalidValidationError ( if necessary, most of the time it isn't ) type cast it to type ValidationErrors like so:

```go
err := validate.Struct(mystruct)
validationErrors := err.(validator.ValidationErrors)
 ```

## Usage and documentation

Please see https://pkg.go.dev/github.com/go-playground/validator/v10 for detailed usage docs.

## Baked-in Validations

### Fields:

| Tag | Description |
| - | - |
| eqcsfield | Field Equals Another Field (relative)|
| eqfield | Field Equals Another Field |
| fieldcontains | NOT DOCUMENTED IN doc.go |
| fieldexcludes | NOT DOCUMENTED IN doc.go |
| gtcsfield | Field Greater Than Another Relative Field |
| gtecsfield | Field Greater Than or Equal To Another Relative Field |
| gtefield | Field Greater Than or Equal To Another Field |
| gtfield | Field Greater Than Another Field |
| ltcsfield | Less Than Another Relative Field |
| ltecsfield | Less Than or Equal To Another Relative Field |
| ltefield | Less Than or Equal To Another Field |
| ltfield | Less Than Another Field |
| necsfield | Field Does Not Equal Another Field (relative) |
| nefield | Field Does Not Equal Another Field |

### Network:

| Tag | Description |
| - | - |
| cidr | Classless Inter-Domain Routing CIDR |
| cidrv4 | Classless Inter-Domain Routing CIDRv4 |
| cidrv6 | Classless Inter-Domain Routing CIDRv6 |
| fqdn | Full Qualified Domain Name (FQDN) |
| hostname | Hostname RFC 952 |
| hostname_port | HostPort |
| hostname_rfc1123 | Hostname RFC 1123 |
| ip | Internet Protocol Address IP |
| ip4_addr | Internet Protocol Address IPv4 |
| ip6_addr | Internet Protocol Address IPv6 |
| ip_addr | Internet Protocol Address IP |
| ipv4 | Internet Protocol Address IPv4 |
| ipv6 | Internet Protocol Address IPv6 |
| tcp4_addr | Transmission Control Protocol Address TCPv4 |
| tcp6_addr | Transmission Control Protocol Address TCPv6 |
| tcp_addr | Transmission Control Protocol Address TCP |
| udp4_addr | User Datagram Protocol Address UDPv4 |
| udp6_addr | User Datagram Protocol Address UDPv6 |
| udp_addr | User Datagram Protocol Address UDP |
| uri | URI String |
| url | URL String |
| url_encoded | URL Encoded |

### Strings:

| Tag | Description |
| - | - |
| alpha | Alpha Only |
| alphanum | Alphanumeric |
| alphanumunicode | Alphanumeric Unicode |
| alphaunicode | Alpha Unicode |
| ascii | ASCII |
| boolean | Boolean |
| contains | Contains |
| containsany | Contains Any |
| containsrune | Contains Rune |
| endsnotwith | Ends Not With |
| endswith | Ends With |
| excludes | Excludes |
| excludesall | Excludes All |
| excludesrune | Excludes Rune |
| lowercase | Lowercase |
| multibyte | Multi-Byte Characters |
| number | NOT DOCUMENTED IN doc.go |
| numeric | Numeric |
| printascii | Printable ASCII |
| startsnotwith | Starts Not With |
| startswith | Starts With |
| uppercase | Uppercase |

### Format:

| Tag | Description |
| - | - |
| base64 | Base64 String |
| base64url | Base64URL String |
| datetime | Datetime |
| email | E-mail String
| hexadecimal | Hexadecimal String |
| json | JSON |
| uuid | Universally Unique Identifier UUID |
| uuid3 | Universally Unique Identifier UUID v3 |
| uuid3_rfc4122 | Universally Unique Identifier UUID v3 RFC4122 |
| uuid4 | Universally Unique Identifier UUID v4 |
| uuid4_rfc4122 | Universally Unique Identifier UUID v4 RFC4122 |
| uuid5 | Universally Unique Identifier UUID v5 |
| uuid5_rfc4122 | Universally Unique Identifier UUID v5 RFC4122 |
| uuid_rfc4122 | Universally Unique Identifier UUID RFC4122 |
| md4 | MD4 hash |
| md5 | MD5 hash |
| sha256 | SHA256 hash |
| sha384 | SHA384 hash |
| sha512 | SHA512 hash |
| semver | Semantic Versioning 2.0.0 |

### Comparisons:

| Tag | Description |
| - | - |
| eq | Equals |
| gt | Greater than|
| gte | Greater than or equal |
| lt | Less Than |
| lte | Less Than or Equal |
| ne | Not Equal |

### Other:

| Tag | Description |
| - | - |
| dir | Directory |
| file | File path |
| isdefault | Is Default |
| len | Length |
| max | Maximum |
| min | Minimum |
| oneof | One Of |
| required | Required |
| required_if | Required If |
| required_unless | Required Unless |
| required_with | Required With |
| required_with_all | Required With All |
| required_without | Required Without |
| required_without_all | Required Without All |
| excluded_if | Excluded If |
| excluded_unless | Excluded Unless |
| excluded_with | Excluded With |
| excluded_with_all | Excluded With All |
| excluded_without | Excluded Without |
| excluded_without_all | Excluded Without All |
| unique | Unique |

#### Aliases:

| Tag | Description |
| - | - |

# License

Distributed under MIT License, please see license file within the code for more details.
