package validator

import "regexp"

const (
	alphaRegexString               = "^[a-zA-Z]+$"
	alphaNumericRegexString        = "^[a-zA-Z0-9]+$"
	alphaUnicodeRegexString        = "^[\\p{L}]+$"
	alphaUnicodeNumericRegexString = "^[\\p{L}\\p{N}]+$"
	numericRegexString             = "^[-+]?[0-9]+(?:\\.[0-9]+)?$"
	numberRegexString              = "^[0-9]+$"
	hexadecimalRegexString         = "^(0[xX])?[0-9a-fA-F]+$"
	emailRegexString               = "^(?:(?:(?:(?:[a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+(?:\\.([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+)*)|(?:(?:\\x22)(?:(?:(?:(?:\\x20|\\x09)*(?:\\x0d\\x0a))?(?:\\x20|\\x09)+)?(?:(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x21|[\\x23-\\x5b]|[\\x5d-\\x7e]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(?:(?:[\\x01-\\x09\\x0b\\x0c\\x0d-\\x7f]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}]))))*(?:(?:(?:\\x20|\\x09)*(?:\\x0d\\x0a))?(\\x20|\\x09)+)?(?:\\x22))))@(?:(?:(?:[a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(?:(?:[a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])(?:[a-zA-Z]|\\d|-|\\.|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*(?:[a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.)+(?:(?:[a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(?:(?:[a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])(?:[a-zA-Z]|\\d|-|\\.|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*(?:[a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.?$"
	base64RegexString              = "^(?:[A-Za-z0-9+\\/]{4})*(?:[A-Za-z0-9+\\/]{2}==|[A-Za-z0-9+\\/]{3}=|[A-Za-z0-9+\\/]{4})$"
	base64URLRegexString           = "^(?:[A-Za-z0-9-_]{4})*(?:[A-Za-z0-9-_]{2}==|[A-Za-z0-9-_]{3}=|[A-Za-z0-9-_]{4})$"
	iSBN10RegexString              = "^(?:[0-9]{9}X|[0-9]{10})$"
	iSBN13RegexString              = "^(?:(?:97(?:8|9))[0-9]{10})$"
	uUID3RegexString               = "^[0-9a-f]{8}-[0-9a-f]{4}-3[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}$"
	uUID4RegexString               = "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
	uUID5RegexString               = "^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
	uUIDRegexString                = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
	uUID3RFC4122RegexString        = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-3[0-9a-fA-F]{3}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
	uUID4RFC4122RegexString        = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
	uUID5RFC4122RegexString        = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-5[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
	uUIDRFC4122RegexString         = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
	uLIDRegexString                = "^[A-HJKMNP-TV-Z0-9]{26}$"
	md4RegexString                 = "^[0-9a-f]{32}$"
	md5RegexString                 = "^[0-9a-f]{32}$"
	sha256RegexString              = "^[0-9a-f]{64}$"
	sha384RegexString              = "^[0-9a-f]{96}$"
	sha512RegexString              = "^[0-9a-f]{128}$"
	aSCIIRegexString               = "^[\x00-\x7F]*$"
	printableASCIIRegexString      = "^[\x20-\x7E]*$"
	multibyteRegexString           = "[^\x00-\x7F]"
	hostnameRegexStringRFC952      = `^[a-zA-Z]([a-zA-Z0-9\-]+[\.]?)*[a-zA-Z0-9]$`                                                                   // https://tools.ietf.org/html/rfc952
	hostnameRegexStringRFC1123     = `^([a-zA-Z0-9]{1}[a-zA-Z0-9-]{0,62}){1}(\.[a-zA-Z0-9]{1}[a-zA-Z0-9-]{0,62})*?$`                                 // accepts hostname starting with a digit https://tools.ietf.org/html/rfc1123
	fqdnRegexStringRFC1123         = `^([a-zA-Z0-9]{1}[a-zA-Z0-9-]{0,62})(\.[a-zA-Z0-9]{1}[a-zA-Z0-9-]{0,62})*?(\.[a-zA-Z]{1}[a-zA-Z0-9]{0,62})\.?$` // same as hostnameRegexStringRFC1123 but must contain a non numerical TLD (possibly ending with '.')
	uRLEncodedRegexString          = `^(?:[^%]|%[0-9A-Fa-f]{2})*$`
	splitParamsRegexString         = `'[^']*'|\S+`
	bicRegexString                 = `^[A-Za-z]{6}[A-Za-z0-9]{2}([A-Za-z0-9]{3})?$`
	semverRegexString              = `^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$` // numbered capture groups https://semver.org/
	dnsRegexStringRFC1035Label     = "^[a-z]([-a-z0-9]*[a-z0-9]){0,62}$"
)

var (
	alphaRegex               = regexp.MustCompile(alphaRegexString)
	alphaNumericRegex        = regexp.MustCompile(alphaNumericRegexString)
	alphaUnicodeRegex        = regexp.MustCompile(alphaUnicodeRegexString)
	alphaUnicodeNumericRegex = regexp.MustCompile(alphaUnicodeNumericRegexString)
	numericRegex             = regexp.MustCompile(numericRegexString)
	numberRegex              = regexp.MustCompile(numberRegexString)
	hexadecimalRegex         = regexp.MustCompile(hexadecimalRegexString)
	emailRegex               = regexp.MustCompile(emailRegexString)
	base64Regex              = regexp.MustCompile(base64RegexString)
	base64URLRegex           = regexp.MustCompile(base64URLRegexString)
	uUID3Regex               = regexp.MustCompile(uUID3RegexString)
	uUID4Regex               = regexp.MustCompile(uUID4RegexString)
	uUID5Regex               = regexp.MustCompile(uUID5RegexString)
	uUIDRegex                = regexp.MustCompile(uUIDRegexString)
	uUID3RFC4122Regex        = regexp.MustCompile(uUID3RFC4122RegexString)
	uUID4RFC4122Regex        = regexp.MustCompile(uUID4RFC4122RegexString)
	uUID5RFC4122Regex        = regexp.MustCompile(uUID5RFC4122RegexString)
	uUIDRFC4122Regex         = regexp.MustCompile(uUIDRFC4122RegexString)
	md4Regex                 = regexp.MustCompile(md4RegexString)
	md5Regex                 = regexp.MustCompile(md5RegexString)
	sha256Regex              = regexp.MustCompile(sha256RegexString)
	sha384Regex              = regexp.MustCompile(sha384RegexString)
	sha512Regex              = regexp.MustCompile(sha512RegexString)
	aSCIIRegex               = regexp.MustCompile(aSCIIRegexString)
	printableASCIIRegex      = regexp.MustCompile(printableASCIIRegexString)
	multibyteRegex           = regexp.MustCompile(multibyteRegexString)
	hostnameRegexRFC952      = regexp.MustCompile(hostnameRegexStringRFC952)
	hostnameRegexRFC1123     = regexp.MustCompile(hostnameRegexStringRFC1123)
	fqdnRegexRFC1123         = regexp.MustCompile(fqdnRegexStringRFC1123)
	uRLEncodedRegex          = regexp.MustCompile(uRLEncodedRegexString)
	splitParamsRegex         = regexp.MustCompile(splitParamsRegexString)
	semverRegex              = regexp.MustCompile(semverRegexString)
	dnsRegexRFC1035Label     = regexp.MustCompile(dnsRegexStringRFC1035Label)
)
