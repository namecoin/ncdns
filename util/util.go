package util
import "strings"

// miekg/dns demands a superflous trailing dot, this makes sure it is correctly appended.
func Absname(n string) string {
  if n == "" {
    return "."
  }
  if n[len(n)-1] != '.' {
    return n + "."
  }
  return n
}

// Split a domain name a.b.c.d.e into parts a (the head) and b.c.d.e (the rest).
func SplitDomainHead(name string) (head string, rest string, err error) {
  parts := strings.Split(name, ".")

  head = parts[len(parts)-1]

  if len(parts) >= 2 {
    rest = strings.Join(parts[0:len(parts)-1], ".")
  }

  return
}
