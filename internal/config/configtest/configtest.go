// Package configtest holds test data that the tests of internal/config and
// cmd/phantom share. It has data only. Production code must not import this
// package.
package configtest

// BadURL is an https URL that the config refuses, with a part of the detail.
type BadURL struct {
	Name, URL, Detail string
}

// BadURLs are https URLs that fail on a host rule or on the query rule.
var BadURLs = []BadURL{
	{"empty label", "https://a..b/", "host name"},
	{"leading dot", "https://.example.com/", "host name"},
	{"semicolon", "https://169.254.169.254;/", "host name"},
	{"leading hyphen", "https://-h.example/", "host name"},
	{"underscore", "https://h_x.example/", "host name"},
	{"query", "https://h.example/p?t=x", "query"},
	{"empty query", "https://h.example/p?", "query"},
}

// EgressLiterals are IP-literal hosts that the egress rule refuses (T-S-11).
var EgressLiterals = []string{
	"127.0.0.1", "10.0.0.1", "100.100.100.200", "169.254.169.254", "224.0.0.1", "[fd00:ec2::254]",
	"[64:ff9b::a9fe:a9fe]", "[::169.254.169.254]", "[::ffff:10.0.0.1]", "[fec0::1]", "[2001:db8::1]",
}

// GlobalLiterals are IP-literal hosts that the egress rule permits (T-S-11).
var GlobalLiterals = []string{"8.8.8.8", "[2606:4700::1111]"}

// EmailMarks are the characters that an email value must refuse (T-S-11).
// They are a space, a C0 control, NEL, no-break space, and right-to-left
// override. They are also line separator, paragraph separator, ideographic
// space, and variation selector 16. Each is a rune value.
var EmailMarks = []rune{0x20, 0x01, 0x85, 0xa0, 0x202e, 0x2028, 0x2029, 0x3000, 0xfe0f}
