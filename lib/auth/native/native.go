/*
Copyright 2015 Gravitational, Inc.

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
package native

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"runtime/debug"
	"sync/atomic"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/utils"

	log "github.com/Sirupsen/logrus"
	"github.com/gravitational/trace"
	"golang.org/x/crypto/ssh"
)

var PrecalculatedKeysNum = 20

type keyPair struct {
	privPem  []byte
	pubBytes []byte
}

type nauth struct {
	generatedKeysC chan keyPair
	closeC         chan bool
	closed         int32
}

func New() *nauth {
	n := nauth{
		generatedKeysC: make(chan keyPair, PrecalculatedKeysNum),
		closeC:         make(chan bool),
	}
	go n.precalculateKeys()
	return &n
}

func (n *nauth) GetNewKeyPairFromPool() ([]byte, []byte, error) {
	fmt.Println("[KEYS] getting a key...")
	debug.PrintStack()

	select {
	case key := <-n.generatedKeysC:
		return key.privPem, key.pubBytes, nil
	default:
		return n.GenerateKeyPair("")
	}
}

func (n *nauth) precalculateKeys() {
	for {
		privPem, pubBytes, err := n.GenerateKeyPair("")
		if err != nil {
			log.Errorf(err.Error())
			continue
		}
		key := keyPair{
			privPem:  privPem,
			pubBytes: pubBytes,
		}

		select {
		case <-n.closeC:
			return
		case n.generatedKeysC <- key:
			continue
		}
	}
}

func (n *nauth) Close() error {
	if atomic.CompareAndSwapInt32(&n.closed, 0, 1) {
		close(n.closeC)
	}
	return nil
}

func (n *nauth) GenerateKeyPair(passphrase string) ([]byte, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	privDer := x509.MarshalPKCS1PrivateKey(priv)
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDer,
	}
	privPem := pem.EncodeToMemory(&privBlock)

	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	pubBytes := ssh.MarshalAuthorizedKey(pub)
	return privPem, pubBytes, nil
}

func (n *nauth) GenerateHostCert(privateSigningKey, publicKey []byte, hostname, authDomain string, role teleport.Role, ttl time.Duration) ([]byte, error) {
	if err := role.Check(); err != nil {
		return nil, trace.Wrap(err)
	}
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(publicKey)
	if err != nil {
		return nil, err
	}
	validBefore := uint64(ssh.CertTimeInfinity)
	if ttl != 0 {
		b := time.Now().Add(ttl)
		validBefore = uint64(b.UnixNano())
	}
	cert := &ssh.Certificate{
		ValidPrincipals: []string{hostname},
		Key:             pubKey,
		ValidBefore:     validBefore,
		CertType:        ssh.HostCert,
	}
	cert.Permissions.Extensions = make(map[string]string)
	cert.Permissions.Extensions[utils.CertExtensionRole] = string(role)
	cert.Permissions.Extensions[utils.CertExtensionAuthority] = string(authDomain)

	signer, err := ssh.ParsePrivateKey(privateSigningKey)
	if err != nil {
		return nil, err
	}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		return nil, err
	}
	return ssh.MarshalAuthorizedKey(cert), nil
}

func (n *nauth) GenerateUserCert(pkey, key []byte, teleportUsername string, allowedLogins []string, ttl time.Duration) ([]byte, error) {
	if (ttl > defaults.MaxCertDuration) || (ttl < defaults.MinCertDuration) {
		return nil, trace.Wrap(teleport.BadParameter("teleport", "wrong certificate TTL"))
	}
	if len(allowedLogins) == 0 {
		return nil, trace.Wrap(teleport.BadParameter("allowedLogins", "need allowed OS logins"))
	}
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(key)
	if err != nil {
		return nil, err
	}
	validBefore := uint64(ssh.CertTimeInfinity)
	if ttl != 0 {
		b := time.Now().Add(ttl)
		validBefore = uint64(b.Unix())
	}
	// we do not use any extensions in users certs because of this:
	// https://bugzilla.mindrot.org/show_bug.cgi?id=2387
	cert := &ssh.Certificate{
		KeyId:           teleportUsername, // we have to use key id to identify teleport user
		ValidPrincipals: allowedLogins,
		Key:             pubKey,
		ValidBefore:     validBefore,
		CertType:        ssh.UserCert,
	}
	signer, err := ssh.ParsePrivateKey(pkey)
	if err != nil {
		return nil, err
	}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		return nil, err
	}
	return ssh.MarshalAuthorizedKey(cert), nil
}
