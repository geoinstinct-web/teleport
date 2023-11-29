/*
Copyright 2023 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package embeddedtbot

import (
	"flag"
	"strings"
	"time"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/tbot/config"
)

const (
	defaultCertificateTTL  = time.Hour
	defaultRenewalInterval = 30 * time.Minute
)

// BotConfig contains the embedded tbot configuration.
// This is a wrapper around the pure tbot config.BotConfig structure
// and exposes utils to parse configuration from CLI flags and operator-specific
// defaults.
type BotConfig config.BotConfig

// BindFlags binds BotConfig fields to CLI flags.
// When calling flag.Parse(), the bot configuration will be parsed and
// the structure populated.
func (c *BotConfig) BindFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.AuthServer, "auth-server", "127.0.0.1:3025", "Address of the Teleport Auth Server or Proxy Server")
	fs.StringVar(&c.Onboarding.TokenValue, "token", "teleport-operator", "A bot join token or path to file with token value.")
	fs.StringVar((*string)(&c.Onboarding.JoinMethod), "join-method", string(types.JoinMethodKubernetes), "Method to use to join the Teleport cluster.")
	fs.DurationVar(&c.CertificateTTL, "certificate-ttl", defaultCertificateTTL, "TTL of short-lived machine certificates.")
	fs.DurationVar(&c.RenewalInterval, "renewal-interval", defaultRenewalInterval, "Interval at which short-lived certificates are renewed; must be less than the certificate TTL.")
	caPinsFlag := StringListVar{
		list: &c.Onboarding.CAPins,
	}
	fs.Var(&caPinsFlag, "ca-pin", "CA pin to validate the Teleport Auth Server; used on first connect.")
	fs.BoolVar(&c.Insecure, "insecure", false, "Trust the certificates from the Auth Server or Proxy on first connect without verification. Do not use in production.")
}

// StringListVar is used to parse comma-separated strings with the flag library.
// The structure implements the flag.Value interface.
type StringListVar struct {
	list *[]string
}

// String implements the flag.Value interface. It joins all list items in
// a single comma-separated string.
func (f *StringListVar) String() string {
	if f.list == nil {
		return ""
	}
	return strings.Join(*f.list, ",")
}

// Set implements the flag.Value interface. It splits a single comma-separated
// string into a string slice.
func (f *StringListVar) Set(arg string) error {
	*f.list = strings.Split(arg, ",")
	return nil
}
