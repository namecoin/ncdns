package tlsoverridefirefox

import (
	"fmt"
	"net"
	"strings"
)

// FilterOverrides accepts as input the contents of a Firefox cert_override.txt
// and a host suffix to blacklist (usually "bit").  It returns the contents of
// a new Firefox cert_override.txt that contains all overrides as the input
// file except for those that match the host suffix.
func FilterOverrides(overrides, blacklistedHostSuffix string) (string, error) {
	result := ""

	overridesSlice := strings.Split(overrides, "\n")

	for _, override := range overridesSlice {
		trimmed := strings.TrimSpace(override)
		if trimmed == "" {
			// This is a blank line; don't try to parse it or
			// include it in output.
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			// This is a comment; pass it through verbatim.
			result = result + override + "\n"
			continue
		}

		tabSplit := strings.Split(override, "\t")
		hostAndPort := tabSplit[0]

		host, _, err := net.SplitHostPort(hostAndPort)
		if err != nil {
			// Don't log err since it may contain private data.
			return "", fmt.Errorf("Error parsing hostport")
		}

		if host == blacklistedHostSuffix ||
			strings.HasSuffix(host, "."+blacklistedHostSuffix) {
			// Host is blacklisted; don't include it in output
			continue
		}

		result = result + override + "\n"
	}

	return result, nil
}
