/*
Copyright 2022 Gravitational, Inc.

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

package config

import (
	"context"
	"strings"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/client/identityfile"
	"github.com/gravitational/teleport/lib/sshutils"
	"github.com/gravitational/teleport/lib/tbot/bot"
	"github.com/gravitational/teleport/lib/tbot/identity"
)

const (
	// defaultSSHHostCertPrefix is the default filename prefix for the SSH host
	// certificate
	defaultSSHHostCertPrefix = "ssh_host"

	// sshHostCertSuffix is the suffix appended to the generated host certificate.
	sshHostCertSuffix = "-cert.pub"

	// sshHostUserCASuffix is the suffix appended to the user CA file.
	sshHostUserCASuffix = "-user-ca.pub"

	// sshHostTrimPrefix is the prefix that should be removed from the generated
	// SSH CA.
	sshHostTrimPrefix = "cert-authority "
)

// TemplateSSHHostCert contains parameters for the ssh_config config
// template
type TemplateSSHHostCert struct {
	// Prefix is the filename prefix for the generated SSH host
	// certificates
	Prefix string `yaml:"prefix,omitempty"`

	// Principals is a list of principals to request for the host cert.
	Principals []string `yaml:"principals"`
}

// CheckAndSetDefaults validates a TemplateSSHHostCert.
func (c *TemplateSSHHostCert) CheckAndSetDefaults() error {
	if c.Prefix == "" {
		c.Prefix = defaultSSHHostCertPrefix
	}

	if len(c.Principals) == 0 {
		return trace.BadParameter("at least one principal must be specified")
	}

	return nil
}

// Name returns the name for the ssh_host_cert template.
func (c *TemplateSSHHostCert) Name() string {
	return TemplateSSHHostCertName
}

// Describe lists the files to be generated by the ssh_host_cert template.
func (c *TemplateSSHHostCert) Describe(destination bot.Destination) []FileDescription {
	ret := []FileDescription{
		{
			Name: c.Prefix,
		},
		{
			Name: c.Prefix + sshHostCertSuffix,
		},
		{
			Name: c.Prefix + sshHostUserCASuffix,
		},
	}

	return ret
}

// exportSSHUserCAs generates SSH CAs.
func exportSSHUserCAs(cas []types.CertAuthority, localAuthName string) (string, error) {
	var exported []string

	for _, ca := range cas {
		// Don't export trusted CAs.
		if ca.GetClusterName() != localAuthName {
			continue
		}

		for _, key := range ca.GetTrustedSSHKeyPairs() {
			s, err := sshutils.MarshalAuthorizedKeysFormat(ca.GetClusterName(), key.PublicKey)
			if err != nil {
				return "", trace.Wrap(err)
			}

			// remove "cert-authority "
			s = strings.TrimPrefix(s, sshHostTrimPrefix)

			exported = append(exported, s)
		}
	}

	return strings.Join(exported, "\n") + "\n", nil
}

// Render generates SSH host cert files.
func (c *TemplateSSHHostCert) Render(ctx context.Context, bot Bot, currentIdentity *identity.Identity, destination *DestinationConfig) error {
	dest, err := destination.GetDestination()
	if err != nil {
		return trace.Wrap(err)
	}

	// We'll need a client for the impersonated identity to request the certs.
	authClient, err := bot.AuthenticatedUserClientFromIdentity(ctx, currentIdentity)
	if err != nil {
		return trace.Wrap(err)
	}

	cn, err := authClient.GetClusterName()
	if err != nil {
		return trace.Wrap(err)
	}
	clusterName := cn.GetClusterName()

	// generate a keypair
	key, err := client.GenerateRSAKey()
	if err != nil {
		return trace.Wrap(err)
	}

	// For now, we'll reuse the bot's regular TTL, and hostID and nodeName are
	// left unset.
	botCfg := bot.Config()
	key.Cert, err = authClient.GenerateHostCert(ctx, key.MarshalSSHPublicKey(),
		"", "", c.Principals,
		clusterName, types.RoleNode, botCfg.CertificateTTL)
	if err != nil {
		return trace.Wrap(err)
	}

	cfg := identityfile.WriteConfig{
		OutputPath: c.Prefix,
		Writer: &BotConfigWriter{
			dest: dest,
		},
		Key:    key,
		Format: identityfile.FormatOpenSSH,

		// Always overwrite to avoid hitting our no-op Stat() and Remove() functions.
		OverwriteDestination: true,
	}

	files, err := identityfile.Write(cfg)
	if err != nil {
		return trace.Wrap(err)
	}

	userCAs, err := bot.GetCertAuthorities(ctx, types.UserCA)
	if err != nil {
		return trace.Wrap(err)
	}

	// get the local domain name, used to exclude trusted CAs
	localAuthName, err := bot.Client().GetDomainName(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	exportedCAs, err := exportSSHUserCAs(userCAs, localAuthName)
	if err != nil {
		return trace.Wrap(err)
	}

	userCAPath := c.Prefix + sshHostUserCASuffix
	if err := dest.Write(userCAPath, []byte(exportedCAs)); err != nil {
		return trace.Wrap(err)
	}

	files = append(files, userCAPath)

	log.Debugf("Wrote OpenSSH host cert files: %+v", files)

	return nil
}
