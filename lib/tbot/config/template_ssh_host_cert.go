/*
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package config

import (
	"context"
	"strings"

	"github.com/gravitational/trace"
	"google.golang.org/protobuf/types/known/durationpb"

	trustpb "github.com/gravitational/teleport/api/gen/proto/go/teleport/trust/v1"
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

// templateSSHHostCert contains parameters for the ssh_config config
// template
type templateSSHHostCert struct {
	// principals is a list of principals to request for the host cert.
	principals []string
}

// Name returns the name for the ssh_host_cert template.
func (c *templateSSHHostCert) name() string {
	return TemplateSSHHostCertName
}

// Describe lists the files to be generated by the ssh_host_cert template.
func (c *templateSSHHostCert) describe() []FileDescription {
	ret := []FileDescription{
		{
			Name: defaultSSHHostCertPrefix,
		},
		{
			Name: defaultSSHHostCertPrefix + sshHostCertSuffix,
		},
		{
			Name: defaultSSHHostCertPrefix + sshHostUserCASuffix,
		},
	}

	return ret
}

// exportSSHUserCAs generates SSH CAs.
func exportSSHUserCAs(cas []types.CertAuthority, localAuthName string) (string, error) {
	var exported string

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

			exported += s
		}
	}

	return exported, nil
}

// Render generates SSH host cert files.
func (c *templateSSHHostCert) render(
	ctx context.Context,
	bot provider,
	_ *identity.Identity,
	destination bot.Destination,
) error {
	ctx, span := tracer.Start(
		ctx,
		"templateSSHHostCert.render",
	)
	defer span.End()

	authPong, err := bot.AuthPing(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	clusterName := authPong.ClusterName

	// generate a keypair
	key, err := client.GenerateRSAKey()
	if err != nil {
		return trace.Wrap(err)
	}

	// For now, we'll reuse the bot's regular TTL, and hostID and nodeName are
	// left unset.
	res, err := bot.GenerateHostCert(ctx, &trustpb.GenerateHostCertRequest{
		Key:         key.MarshalSSHPublicKey(),
		HostId:      "",
		NodeName:    "",
		Principals:  c.principals,
		ClusterName: clusterName,
		Role:        string(types.RoleNode),
		Ttl:         durationpb.New(bot.Config().CertificateTTL),
	},
	)
	if err != nil {
		return trace.Wrap(err)
	}
	key.Cert = res.SshCertificate

	cfg := identityfile.WriteConfig{
		OutputPath: defaultSSHHostCertPrefix,
		Writer: &BotConfigWriter{
			ctx:  ctx,
			dest: destination,
		},
		Key:    key,
		Format: identityfile.FormatOpenSSH,

		// Always overwrite to avoid hitting our no-op Stat() and Remove() functions.
		OverwriteDestination: true,
	}

	files, err := identityfile.Write(ctx, cfg)
	if err != nil {
		return trace.Wrap(err)
	}

	userCAs, err := bot.GetCertAuthorities(ctx, types.UserCA)
	if err != nil {
		return trace.Wrap(err)
	}

	exportedCAs, err := exportSSHUserCAs(userCAs, clusterName)
	if err != nil {
		return trace.Wrap(err)
	}

	userCAPath := defaultSSHHostCertPrefix + sshHostUserCASuffix
	if err := destination.Write(ctx, userCAPath, []byte(exportedCAs)); err != nil {
		return trace.Wrap(err)
	}

	files = append(files, userCAPath)

	log.DebugContext(
		ctx,
		"Wrote OpenSSH host cert files",
		"files", files,
	)

	return nil
}
