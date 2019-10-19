package util

import "strings"
import "gopkg.in/hlandau/madns.v2/merr"
import "fmt"
import "regexp"
import "net/mail"

// Split a domain name a.b.c.d.e into parts e (the head) and a.b.c.d (the rest).
func SplitDomainHead(name string) (head, rest string) {
	if len(name) > 0 && name[len(name)-1] == '.' {
		name = name[0 : len(name)-1]
	}

	parts := strings.Split(name, ".")

	head = parts[len(parts)-1]

	if len(parts) >= 2 {
		rest = strings.Join(parts[0:len(parts)-1], ".")
	}

	return
}

// Split a domain name a.b.c.d.e into parts a (the tail) and b.c.d.e (the rest).
func SplitDomainTail(name string) (tail, rest string) {
	s := strings.SplitN(name, ".", 2)

	if len(s) == 1 {
		return s[0], ""
	}

	return s[0], s[1]
}

// For domains of the form "Y1.Y2...Yn.ANCHOR.X1.X2...Xn.", returns the following values:
//
// basename is the name appearing directly beneath the anchor (Yn).
//
// subname contains any additional labels appearing beneath the anchor (Y1 through Y(n-1)),
// separated by dots.
//
// rootname contains ANCHOR through Xn inclusive, separated by dots.
//
// If no label corresponds to ANCHOR, an error is returned.
// If ANCHOR is the first label, basename is an empty string.
//
// Examples, where anchor="bit":
//   "a.b.c.d."           -> merr.ErrNotInZone
//   "a.b.c.d.bit."       -> subname="a.b.c", basename="d", rootname="bit"
//   "d.bit."             -> subname="",      basename="d", rootname="bit"
//   "bit."               -> subname="",      basename="",  rootname="bit"
//   "bit.x.y.z."         -> subname="",      basename="",  rootname="bit.x.y.z"
//   "d.bit.x.y.z."       -> subname="",      basename="d", rootname="bit.x.y.z"
//   "c.d.bit.x.y.z."     -> subname="c",     basename="d", rootname="bit.x.y.z"
//   "a.b.c.d.bit.x.y.z." -> subname="a.b.c",     basename="d", rootname="bit.x.y.z"
func SplitDomainByFloatingAnchor(qname, anchor string) (subname, basename, rootname string, err error) {
	qname = strings.TrimRight(qname, ".")
	parts := strings.Split(qname, ".")
	if len(parts) < 2 {
		if parts[0] != anchor {
			err = merr.ErrNotInZone
			return
		}

		rootname = parts[0]
		return
	}

	for i := len(parts) - 1; i >= 0; i-- {
		v := parts[i]

		// scanning for rootname
		if v == anchor {
			if i == 0 {
				// i is alreay zero, so we have something like bit.x.y.z.
				rootname = qname
				return
			}

			rootname = strings.Join(parts[i:], ".")
			basename = parts[i-1]
			subname = strings.Join(parts[0:i-1], ".")
			return
		}
	}

	err = merr.ErrNotInZone
	return
}

// Convert a domain name basename (e.g. "example") to a Namecoin domain name
// key name ("d/example").
func BasenameToNamecoinKey(basename string) (string, error) {
	if !ValidateDomainLabel(basename) {
		return "", fmt.Errorf("invalid domain name")
	}
	return basenameToNamecoinKey(basename), nil
}

func basenameToNamecoinKey(basename string) string {
	return "d/" + basename
}

// Convert a Namecoin domain name key name (e.g. "d/example") to a domain name
// basename ("example").
func NamecoinKeyToBasename(key string) (string, error) {
	if !strings.HasPrefix(key, "d/") {
		return "", fmt.Errorf("not a valid domain name key")
	}

	key = key[2:]
	if !ValidateDomainLabel(key) {
		return "", fmt.Errorf("not a valid domain name key")
	}

	return key, nil
}

// An owner name is any technically valid DNS name. RFC 2181 permits binary
// data in DNS labels (!), but this is ridiculous. The conventions which appear
// to be enforced by web browsers are used.
const sre_ownerLabel = `([a-z0-9_]|[a-z0-9_][a-z0-9_-]{0,61}[a-z0-9_])`
const sre_ownerName = `(` + sre_ownerLabel + `\.)*` + sre_ownerLabel + `\.?`             // must check length
const sre_relOwnerName = `(|@|(` + sre_ownerLabel + `\.)*` + sre_ownerLabel + `(\.@?)?)` // must check length
var re_ownerLabel = regexp.MustCompilePOSIX(`^` + sre_ownerLabel + `$`)
var re_ownerName = regexp.MustCompilePOSIX(`^` + sre_ownerName + `$`)
var re_relOwnerName = regexp.MustCompilePOSIX(`^` + sre_relOwnerName + `$`)

const sre_domainLabel = `(xn--)?([a-z0-9]+-)*[a-z0-9]+`                                     // must check length
const sre_domainName = `(` + sre_domainLabel + `\.)*` + sre_domainLabel + `\.?`             // must check length
const sre_relDomainName = `(|@|(` + sre_domainLabel + `\.)*` + sre_domainLabel + `(\.@?)?)` // must check length
var re_domainLabel = regexp.MustCompilePOSIX(`^` + sre_domainLabel + `$`)
var re_domainName = regexp.MustCompilePOSIX(`^` + sre_domainName + `$`)
var re_relDomainName = regexp.MustCompilePOSIX(`^` + sre_relDomainName + `$`)

const sre_hostLabel = `([a-z0-9]|[a-z0-9][a-z0-9-]*[a-z0-9])`                         // must check length
const sre_hostName = sre_hostLabel + `(\.` + sre_hostLabel + `)*\.?`                  // must check length
const sre_relHostName = `(|@|(` + sre_hostLabel + `\.)*` + sre_hostLabel + `(\.@?)?)` // must check length
var re_hostLabel = regexp.MustCompilePOSIX(`^` + sre_hostLabel + `$`)
var re_hostName = regexp.MustCompilePOSIX(`^` + sre_hostName + `$`)
var re_relHostName = regexp.MustCompilePOSIX(`^` + sre_relHostName + `$`)

func ValidateLabelLength(label string) bool {
	return len(label) <= 63
}

func ValidateNameLength(name string) bool {
	return len(name) <= 255 || (name[len(name)-1] == '.' && len(name) <= 256)
}

func ValidateOwnerLabel(label string) bool {
	return ValidateLabelLength(label) && re_ownerLabel.MatchString(label)
}

func ValidateServiceName(label string) bool {
	return len(label) <= 62 && ValidateOwnerLabel(label)
}

func ValidateOwnerName(name string) bool {
	return ValidateNameLength(name) && re_ownerName.MatchString(name)
}

func ValidateRelOwnerName(name string) bool {
	return ValidateNameLength(name) && re_relOwnerName.MatchString(name)
}

func ValidateDomainLabel(label string) bool {
	return ValidateLabelLength(label) && re_domainLabel.MatchString(label)
}

func ValidateDomainName(name string) bool {
	return ValidateNameLength(name) && re_domainName.MatchString(name)
}

func ValidateRelDomainName(name string) bool {
	return ValidateNameLength(name) && re_relDomainName.MatchString(name)
}

func ValidateHostLabel(label string) bool {
	return ValidateLabelLength(label) && re_hostLabel.MatchString(label)
}

func ValidateHostName(name string) bool {
	return ValidateNameLength(name) && re_hostName.MatchString(name)
}

func ValidateRelHostName(name string) bool {
	return ValidateNameLength(name) && re_relHostName.MatchString(name)
}

/*
var re_ownerName  = regexp.MustCompilePOSIX(`^([a-z0-9_][a-z0-9_-]{0,62}\.)*[a-z0-9_][a-z0-9_-]{0,62}\.?$`)
var re_ownerLabel = regexp.MustCompilePOSIX(`^([a-z0-9_]{1,2}|[a-z0-9_][a-z0-9_-]{0,61}[a-z0-9_])$`)

// A domain name is an owner name complying with the standard rules applied to
// domain names: No consecutive hyphens except as allowed by IDN, no underscores.
var re_domainName = regexp.MustCompilePOSIX(`^(([a-z0-9]+-)*[a-z0-9]+\.)*$`)



// This is used to validate NS records, targets in SRV records, etc. In these cases
// an IP address is not allowed. Therefore this regex must exclude all-numeric domain names.
// This is done by requiring the final part to start with an alphabetic character.
var re_hostName = regexp.MustCompilePOSIX(`^(([a-z0-9_][a-z0-9_-]{0,62}\.)*[a-z_][a-z0-9_-]{0,62}\.?|\.)$`)
var re_label = regexp.MustCompilePOSIX(`^[a-z_][a-z0-9_-]*$`)
var re_serviceName = regexp.MustCompilePOSIX(`^[a-z_][a-z0-9_-]*$`)
var re_domainNameLabel = regexp.MustCompilePOSIX(`^(xn--)?[a-z0-9]+(-[a-z0-9]+)*$`)
var re_ownerName = regexp.MustCompilePOSIX(`^(|@|([a-z0-9_-]{1,63}\.)*[a-z0-9_-]{1,63}(\.@?)?)$`)

func ValidateHostName(name string) bool {
	name = dns.Fqdn(name)
	return len(name) <= 255 && re_hostName.MatchString(name)
}

func ValidateLabel(name string) bool {
	return len(name) <= 63 && re_label.MatchString(name)
}

func ValidateServiceName(name string) bool {
	return len(name) < 63 && re_serviceName.MatchString(name)
}

func ValidateDomainNameLabel(name string) bool {
	return len(name) <= 63 && re_domainNameLabel.MatchString(name)
}

func ValidateOwnerName(name string) bool {
	return len(name) <= 255 && re_ownerName.MatchString(name)
}*/

func ValidateEmail(email string) bool {
	addr, err := mail.ParseAddress(email)
	if addr == nil || err != nil {
		return false
	}
	return addr.Name == ""
}

// Takes a name in the form "d/example" or "example.bit" and converts it to the
// bareword "example". Returns an error if the input is in neither form.
func ParseFuzzyDomainName(name string) (string, error) {
	if strings.HasPrefix(name, "d/") {
		return NamecoinKeyToBasename(name)
	}
	if len(name) > 0 && name[len(name)-1] == '.' {
		name = name[0 : len(name)-1]
	}
	if strings.HasSuffix(name, ".bit") {
		name = name[0 : len(name)-4]
		if !ValidateDomainLabel(name) {
			return "", fmt.Errorf("invalid domain name")
		}
		return name, nil
	}
	return "", fmt.Errorf("invalid domain name")
}

func ParseFuzzyDomainNameNC(name string) (bareName string, namecoinKey string, err error) {
	name, err = ParseFuzzyDomainName(name)
	if err != nil {
		return "", "", err
	}

	return name, basenameToNamecoinKey(name), nil
}

// © 2014 Hugo Landau <hlandau@devever.net>    GPLv3 or later
