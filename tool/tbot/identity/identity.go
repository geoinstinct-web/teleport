/*
Copyright 2021-2022 Gravitational, Inc.

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

package identity

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/client/proto"
	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	apiutils "github.com/gravitational/teleport/api/utils"
	apisshutils "github.com/gravitational/teleport/api/utils/sshutils"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/teleport/tool/tbot/destination"
	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

const (
	// TLSCertKey is the name under which TLS certificates exist in a destination.
	TLSCertKey = "tlscert"

	// TLSCertKey is the name under which SSH certificates exist in a destination.
	SSHCertKey = "sshcert"

	// SSHCACertsKey is the name under which SSH CA certificates exist in a destination.
	SSHCACertsKey = "sshcacerts"

	// TLSCACertsKey is the name under which SSH CA certificates exist in a destination.
	TLSCACertsKey = "tlscacerts"

	// PrivateKeyKey is the name under which the private key exists in a destination.
	// The same private key is used for SSH and TLS certificates.
	PrivateKeyKey = "key"

	// PublicKeyKey is the ssh public key, required for successful SSH connections.
	PublicKeyKey = "key.pub"

	// MetadataKey is the name under which additional metadata exists in a destination.
	MetadataKey = "meta"
)

var log = logrus.WithFields(logrus.Fields{
	trace.Component: teleport.ComponentTBot,
})

// Identity is collection of certificates and signers that represent server
// identity. This is derived from Teleport's usual auth.Identity with small
// modifications to work with user rather than host certificates.
type Identity struct {
	// KeyBytes is a PEM encoded private key
	KeyBytes []byte
	// SSHPublicKeyBytes contains bytes of the original SSH public key
	SSHPublicKeyBytes []byte
	// CertBytes is a PEM encoded SSH host cert
	CertBytes []byte
	// TLSCertBytes is a PEM encoded TLS x509 client certificate
	TLSCertBytes []byte
	// TLSCACertBytes is a list of PEM encoded TLS x509 certificate of certificate authority
	// associated with auth server services
	TLSCACertsBytes [][]byte
	// SSHCACertBytes is a list of SSH CAs encoded in the authorized_keys format.
	SSHCACertBytes [][]byte
	// KeySigner is an SSH host certificate signer
	KeySigner ssh.Signer
	// Cert is a parsed SSH certificate
	Cert *ssh.Certificate
	// XCert is X509 client certificate
	XCert *x509.Certificate
	// ClusterName is a name of host's cluster
	ClusterName string
}

// String returns user-friendly representation of the identity.
func (i *Identity) String() string {
	var out []string
	if i.XCert != nil {
		out = append(out, fmt.Sprintf("cert(%v issued by %v:%v)", i.XCert.Subject.CommonName, i.XCert.Issuer.CommonName, i.XCert.Issuer.SerialNumber))
	}
	for j := range i.TLSCACertsBytes {
		cert, err := tlsca.ParseCertificatePEM(i.TLSCACertsBytes[j])
		if err != nil {
			out = append(out, err.Error())
		} else {
			out = append(out, fmt.Sprintf("trust root(%v:%v)", cert.Subject.CommonName, cert.Subject.SerialNumber))
		}
	}
	return fmt.Sprintf("Identity(%v)", strings.Join(out, ","))
}

// CertInfo returns diagnostic information about certificate
func CertInfo(cert *x509.Certificate) string {
	return fmt.Sprintf("cert(%v issued by %v:%v)", cert.Subject.CommonName, cert.Issuer.CommonName, cert.Issuer.SerialNumber)
}

// TLSCertInfo returns diagnostic information about certificate
func TLSCertInfo(cert *tls.Certificate) string {
	x509cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err.Error()
	}
	return CertInfo(x509cert)
}

// CertAuthorityInfo returns debugging information about certificate authority
func CertAuthorityInfo(ca types.CertAuthority) string {
	var out []string
	for _, keyPair := range ca.GetTrustedTLSKeyPairs() {
		cert, err := tlsca.ParseCertificatePEM(keyPair.Cert)
		if err != nil {
			out = append(out, err.Error())
		} else {
			out = append(out, fmt.Sprintf("trust root(%v:%v)", cert.Subject.CommonName, cert.Subject.SerialNumber))
		}
	}
	return fmt.Sprintf("cert authority(state: %v, phase: %v, roots: %v)", ca.GetRotation().State, ca.GetRotation().Phase, strings.Join(out, ", "))
}

// HasTSLConfig returns true if this identity has TLS certificate and private key
func (i *Identity) HasTLSConfig() bool {
	return len(i.TLSCACertsBytes) != 0 && len(i.TLSCertBytes) != 0
}

// HasPrincipals returns whether identity has principals
func (i *Identity) HasPrincipals(additionalPrincipals []string) bool {
	set := utils.StringsSet(i.Cert.ValidPrincipals)
	for _, principal := range additionalPrincipals {
		if _, ok := set[principal]; !ok {
			return false
		}
	}
	return true
}

// HasDNSNames returns true if TLS certificate has required DNS names
func (i *Identity) HasDNSNames(dnsNames []string) bool {
	if i.XCert == nil {
		return false
	}
	set := utils.StringsSet(i.XCert.DNSNames)
	for _, dnsName := range dnsNames {
		if _, ok := set[dnsName]; !ok {
			return false
		}
	}
	return true
}

// TLSConfig returns TLS config for mutual TLS authentication
// can return NotFound error if there are no TLS credentials setup for identity
func (i *Identity) TLSConfig(cipherSuites []uint16) (*tls.Config, error) {
	tlsConfig := utils.TLSConfig(cipherSuites)
	if !i.HasTLSConfig() {
		return nil, trace.NotFound("no TLS credentials setup for this identity")
	}
	tlsCert, err := tls.X509KeyPair(i.TLSCertBytes, i.KeyBytes)
	if err != nil {
		return nil, trace.BadParameter("failed to parse private key: %v", err)
	}
	certPool := x509.NewCertPool()
	for j := range i.TLSCACertsBytes {
		parsedCert, err := tlsca.ParseCertificatePEM(i.TLSCACertsBytes[j])
		if err != nil {
			return nil, trace.Wrap(err, "failed to parse CA certificate")
		}
		certPool.AddCert(parsedCert)
	}
	tlsConfig.Certificates = []tls.Certificate{tlsCert}
	tlsConfig.RootCAs = certPool
	tlsConfig.ClientCAs = certPool
	tlsConfig.ServerName = apiutils.EncodeClusterName(i.ClusterName)
	return tlsConfig, nil
}

func (i *Identity) getSSHCheckers() ([]ssh.PublicKey, error) {
	checkers, err := apisshutils.ParseAuthorizedKeys(i.SSHCACertBytes)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return checkers, nil
}

// SSHClientConfig returns a ssh.ClientConfig used by nodes to connect to
// the reverse tunnel server.
func (i *Identity) SSHClientConfig() (*ssh.ClientConfig, error) {
	callback, err := apisshutils.NewHostKeyCallback(
		apisshutils.HostKeyCallbackConfig{
			GetHostCheckers: i.getSSHCheckers,
		})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if len(i.Cert.ValidPrincipals) < 1 {
		return nil, trace.BadParameter("user cert has no valid principals")
	}
	return &ssh.ClientConfig{
		User:            i.Cert.ValidPrincipals[0],
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(i.KeySigner)},
		HostKeyCallback: callback,
		Timeout:         apidefaults.DefaultDialTimeout,
	}, nil
}

// ReadIdentityFromKeyPair reads SSH and TLS identity from key pair.
func ReadIdentityFromKeyPair(privateKey []byte, publicKey []byte, certs *proto.Certs) (*Identity, error) {
	identity, err := ReadSSHIdentityFromKeyPair(privateKey, publicKey, certs.SSH)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if len(certs.SSHCACerts) != 0 {
		identity.SSHCACertBytes = certs.SSHCACerts
	}

	if len(certs.TLSCACerts) != 0 {
		// Parse the key pair to verify that identity parses properly for future use.
		i, err := ReadTLSIdentityFromKeyPair(privateKey, certs.TLS, certs.TLSCACerts)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		identity.XCert = i.XCert
		identity.TLSCertBytes = certs.TLS
		identity.TLSCACertsBytes = certs.TLSCACerts
	}

	return identity, nil
}

// ReadTLSIdentityFromKeyPair reads TLS identity from key pair
func ReadTLSIdentityFromKeyPair(keyBytes, certBytes []byte, caCertsBytes [][]byte) (*Identity, error) {
	if len(keyBytes) == 0 {
		return nil, trace.BadParameter("missing private key")
	}

	if len(certBytes) == 0 {
		return nil, trace.BadParameter("missing certificate")
	}

	cert, err := tlsca.ParseCertificatePEM(certBytes)
	if err != nil {
		return nil, trace.Wrap(err, "failed to parse TLS certificate")
	}

	if len(cert.Issuer.Organization) == 0 {
		return nil, trace.BadParameter("missing CA organization")
	}

	clusterName := cert.Issuer.Organization[0]
	if clusterName == "" {
		return nil, trace.BadParameter("misssing cluster name")
	}
	identity := &Identity{
		ClusterName:     clusterName,
		KeyBytes:        keyBytes,
		TLSCertBytes:    certBytes,
		TLSCACertsBytes: caCertsBytes,
		XCert:           cert,
	}
	// The passed in ciphersuites don't appear to matter here since the returned
	// *tls.Config is never actually used?
	_, err = identity.TLSConfig(utils.DefaultCipherSuites())
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return identity, nil
}

// ReadSSHIdentityFromKeyPair reads identity from initialized keypair
func ReadSSHIdentityFromKeyPair(keyBytes, publicKeyBytes, certBytes []byte) (*Identity, error) {
	if len(keyBytes) == 0 {
		return nil, trace.BadParameter("PrivateKey: missing private key")
	}

	if len(publicKeyBytes) == 0 {
		return nil, trace.BadParameter("PublicKey: missing public key")
	}

	if len(certBytes) == 0 {
		return nil, trace.BadParameter("Cert: missing parameter")
	}

	cert, err := apisshutils.ParseCertificate(certBytes)
	if err != nil {
		return nil, trace.BadParameter("failed to parse server certificate: %v", err)
	}

	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, trace.BadParameter("failed to parse private key: %v", err)
	}
	// this signer authenticates using certificate signed by the cert authority
	// not only by the public key
	certSigner, err := ssh.NewCertSigner(cert, signer)
	if err != nil {
		return nil, trace.BadParameter("unsupported private key: %v", err)
	}

	// check principals on certificate
	if len(cert.ValidPrincipals) < 1 {
		return nil, trace.BadParameter("valid principals: at least one valid principal is required")
	}
	for _, validPrincipal := range cert.ValidPrincipals {
		if validPrincipal == "" {
			return nil, trace.BadParameter("valid principal can not be empty: %q", cert.ValidPrincipals)
		}
	}

	// check permissions on certificate
	// TODO: do we care to even verify this at all?
	// if len(cert.Permissions.Extensions) == 0 {
	// 	return nil, trace.BadParameter("extensions: misssing needed extensions for host roles")
	// }

	// roleString := cert.Permissions.Extensions[utils.CertExtensionRole]
	// if roleString == "" {
	// 	return nil, trace.BadParameter("misssing cert extension %v", utils.CertExtensionRole)
	// }
	// roles, err := types.ParseTeleportRoles(roleString)
	// if err != nil {
	// 	return nil, trace.Wrap(err)
	// }
	// foundRoles := len(roles)
	// if foundRoles != 1 {
	// 	return nil, trace.Errorf("expected one role per certificate. found %d: '%s'",
	// 		foundRoles, roles.String())
	// }

	// TODO: host certs use CertExtensionAuthority, client certs use CertExtensionTeleportRouteToCluster
	// (or at least, teleport-route-to-cluster _appears_ to be a sane cluster name, but I have no idea
	// how it is actually set.)
	//clusterName := cert.Permissions.Extensions[utils.CertExtensionAuthority]
	clusterName := cert.Permissions.Extensions[teleport.CertExtensionTeleportRouteToCluster]
	if clusterName == "" {
		return nil, trace.BadParameter("missing cert extension %v", utils.CertExtensionAuthority)
	}

	return &Identity{
		ClusterName:       clusterName,
		KeyBytes:          keyBytes,
		SSHPublicKeyBytes: publicKeyBytes,
		CertBytes:         certBytes,
		KeySigner:         certSigner,
		Cert:              cert,
	}, nil
}

func SaveIdentity(id *Identity, d destination.Destination) error {
	for _, data := range []struct {
		name     string
		data     []byte
		modeHint destination.ModeHint
	}{
		{TLSCertKey, id.TLSCertBytes, destination.ModeHintSecret},
		{SSHCertKey, id.CertBytes, destination.ModeHintSecret},
		{TLSCACertsKey, bytes.Join(id.TLSCACertsBytes, []byte("$")), destination.ModeHintSecret},
		{SSHCACertsKey, bytes.Join(id.SSHCACertBytes, []byte("$")), destination.ModeHintSecret},
		{PrivateKeyKey, id.KeyBytes, destination.ModeHintSecret},
		{PublicKeyKey, id.SSHPublicKeyBytes, destination.ModeHintUnspecified},
	} {
		log.Debugf("Writing %s", data.name)
		if err := d.Write(data.name, data.data, data.modeHint); err != nil {
			return trace.Wrap(err, "could not write to %v", data.name)
		}
	}
	return nil
}

func LoadIdentity(d destination.Destination) (*Identity, error) {
	// TODO: encode the whole thing using the identityfile package?
	var key, sshPublicKey, tlsCA, sshCA []byte
	var certs proto.Certs
	var err error

	for _, item := range []struct {
		name string
		out  *[]byte
	}{
		{TLSCertKey, &certs.TLS},
		{SSHCertKey, &certs.SSH},
		{TLSCACertsKey, &tlsCA},
		{SSHCACertsKey, &sshCA},
		{PrivateKeyKey, &key},
		{PublicKeyKey, &sshPublicKey},
	} {
		*item.out, err = d.Read(item.name)
		if err != nil {
			return nil, trace.Wrap(err, "could not read %v", item.name)
		}
	}

	certs.SSHCACerts = bytes.Split(sshCA, []byte("$"))
	certs.TLSCACerts = bytes.Split(tlsCA, []byte("$"))

	log.Debugf("Loaded %d SSH CA certs and %d TLS CA certs", len(certs.SSHCACerts), len(certs.TLSCACerts))

	return ReadIdentityFromKeyPair(key, sshPublicKey, &certs)
}
