package util

import "strings"

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

// © 2014 Hugo Landau <hlandau@devever.net>    GPLv3 or later
