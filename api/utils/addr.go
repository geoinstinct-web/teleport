package utils

import (
	"net"
	"strings"
)

// IsLoopback returns 'true' if a given hostname resolves *only* to the 
// local host's loopback interface
func IsLoopback(host string) bool {
	if strings.Contains(host, ":") {
		var err error
		host, _, err = net.SplitHostPort(host)
		if err != nil {
			return false
		}
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return false
	}

	if len(ips) == 0 {
		return false
	}

	for _, ip := range ips {
		if !ip.IsLoopback() {
			return false
		}
	}

	return true
}
