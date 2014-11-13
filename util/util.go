package util

import "strings"

// Split a domain name a.b.c.d.e into parts a (the head) and b.c.d.e (the rest).
func SplitDomainHead(name string) (head string, rest string, err error) {
	parts := strings.Split(name, ".")

	head = parts[len(parts)-1]

	if len(parts) >= 2 {
		rest = strings.Join(parts[0:len(parts)-1], ".")
	}

	return
}

// © 2014 Hugo Landau <hlandau@devever.net>    GPLv3 or later
