//go:build piv

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

package keys

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-piv/piv-go/piv"
	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api"
	attestation "github.com/gravitational/teleport/api/gen/proto/go/attestation/v1"
	"github.com/gravitational/teleport/api/utils/retryutils"
)

const (
	// PIVCardTypeYubiKey is the PIV card type assigned to yubiKeys.
	PIVCardTypeYubiKey = "yubikey"
)

var (
	// We use slot 9a for Teleport Clients which require `private_key_policy: hardware_key`.
	pivSlotNoTouch = piv.SlotAuthentication
	// We use slot 9c for Teleport Clients which require `private_key_policy: hardware_key_touch`.
	// Private keys generated on this slot will use TouchPolicy=Cached.
	pivSlotWithTouch = piv.SlotSignature
)

// getOrGenerateYubiKeyPrivateKey connects to a connected yubiKey and gets a private key
// matching the given touch requirement. This private key will either be newly generated
// or previously generated by a Teleport client and reused.
func getOrGenerateYubiKeyPrivateKey(touchRequired bool) (*PrivateKey, error) {
	// Use the first yubiKey we find.
	y, err := findYubiKey(0)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Get the correct PIV slot and Touch policy for the given touch requirement.
	pivSlot := pivSlotNoTouch
	touchPolicy := piv.TouchPolicyNever
	if touchRequired {
		pivSlot = pivSlotWithTouch
		touchPolicy = piv.TouchPolicyCached
	}

	// First, check if there is already a private key set up by a Teleport Client.
	priv, err := y.getPrivateKey(pivSlot)
	if trace.IsNotFound(err) {
		// Generate a new private key on the PIV slot.
		if priv, err = y.generatePrivateKey(pivSlot, touchPolicy); err != nil {
			return nil, trace.Wrap(err)
		}
	} else if err != nil {
		return nil, trace.Wrap(err)
	}

	keyPEM, err := priv.keyPEM()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return NewPrivateKey(priv, keyPEM)
}

// YubiKeyPrivateKey is a YubiKey PIV private key. Cryptographical operations open
// a new temporary connection to the PIV card to perform the operation.
type YubiKeyPrivateKey struct {
	// yubiKey is a specific yubiKey PIV module.
	*yubiKey
	pivSlot piv.Slot
	pub     crypto.PublicKey
	signMux sync.Mutex
}

// yubiKeyPrivateKeyData is marshalable data used to retrieve a specific yubiKey PIV private key.
type yubiKeyPrivateKeyData struct {
	SerialNumber uint32 `json:"serial_number"`
	SlotKey      uint32 `json:"slot_key"`
}

func newYubiKeyPrivateKey(y *yubiKey, slot piv.Slot, pub crypto.PublicKey) (*YubiKeyPrivateKey, error) {
	return &YubiKeyPrivateKey{
		yubiKey: y,
		pivSlot: slot,
		pub:     pub,
	}, nil
}

func parseYubiKeyPrivateKeyData(keyDataBytes []byte) (*YubiKeyPrivateKey, error) {
	var keyData yubiKeyPrivateKeyData
	if err := json.Unmarshal(keyDataBytes, &keyData); err != nil {
		return nil, trace.Wrap(err)
	}

	pivSlot, err := parsePIVSlot(keyData.SlotKey)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	y, err := findYubiKey(keyData.SerialNumber)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	priv, err := y.getPrivateKey(pivSlot)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return priv, nil
}

// Public returns the public key corresponding to this private key.
func (y *YubiKeyPrivateKey) Public() crypto.PublicKey {
	return y.pub
}

// Sign implements crypto.Signer.
func (y *YubiKeyPrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	signCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// To prevent concurrent calls to Sign from failing due to PIV only handling a
	// single connection, use a lock to queue through signature requests one at a time.
	y.signMux.Lock()
	defer y.signMux.Unlock()

	yk, err := y.open()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer yk.Close()

	privateKey, err := yk.PrivateKey(y.pivSlot, y.pub, piv.KeyAuth{})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if y.pivSlot == pivSlotWithTouch {
		touchPromptDelayTimer := time.NewTimer(signTouchPromptDelay)
		defer touchPromptDelayTimer.Stop()

		go func() {
			select {
			case <-touchPromptDelayTimer.C:
				// Prompt for touch after a delay, in case the function succeeds without touch due to a cached touch.
				fmt.Fprintln(os.Stderr, "Tap your YubiKey")
				return
			case <-signCtx.Done():
				// touch cached, skip prompt.
				return
			}
		}()
	}

	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, trace.BadParameter("private key type %T does not implement crypto.Signer", privateKey)
	}

	signature, err := signer.Sign(rand, digest, opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return signature, nil
}

func (y *YubiKeyPrivateKey) keyPEM() ([]byte, error) {
	keyDataBytes, err := json.Marshal(yubiKeyPrivateKeyData{
		SerialNumber: y.serialNumber,
		SlotKey:      y.pivSlot.Key,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:    pivYubiKeyPrivateKeyType,
		Headers: nil,
		Bytes:   keyDataBytes,
	}), nil
}

// GetAttestationStatement returns an AttestationStatement for this YubiKeyPrivateKey.
func (y *YubiKeyPrivateKey) GetAttestationStatement() (*AttestationStatement, error) {
	yk, err := y.open()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer yk.Close()

	slotCert, err := yk.Attest(y.pivSlot)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	attCert, err := yk.AttestationCertificate()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if _, err = piv.Verify(attCert, slotCert); err != nil {
		return nil, trace.Wrap(err)
	}

	return &AttestationStatement{
		AttestationStatement: &attestation.AttestationStatement_YubikeyAttestationStatement{
			YubikeyAttestationStatement: &attestation.YubiKeyAttestationStatement{
				SlotCert:        slotCert.Raw,
				AttestationCert: attCert.Raw,
			},
		},
	}, nil
}

// GetPrivateKeyPolicy returns the PrivateKeyPolicy supported by this YubiKeyPrivateKey.
func (y *YubiKeyPrivateKey) GetPrivateKeyPolicy() PrivateKeyPolicy {
	switch y.pivSlot {
	case pivSlotNoTouch:
		return PrivateKeyPolicyHardwareKey
	case pivSlotWithTouch:
		return PrivateKeyPolicyHardwareKeyTouch
	default:
		return PrivateKeyPolicyNone
	}
}

// yubiKey is a specific yubiKey PIV card.
type yubiKey struct {
	// card is a reader name used to find and connect to this yubiKey.
	// This value may change between OS's, or with other system changes.
	card string
	// serialNumber is the yubiKey's 8 digit serial number.
	serialNumber uint32
}

func newYubiKey(card string) (*yubiKey, error) {
	y := &yubiKey{card: card}

	yk, err := y.open()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer yk.Close()

	y.serialNumber, err = yk.Serial()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return y, nil
}

// generatePrivateKey generates a new private key from the given PIV slot with the given PIV policies.
func (y *yubiKey) generatePrivateKey(slot piv.Slot, touchPolicy piv.TouchPolicy) (*YubiKeyPrivateKey, error) {
	yk, err := y.open()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer yk.Close()

	opts := piv.Key{
		Algorithm:   piv.AlgorithmEC256,
		PINPolicy:   piv.PINPolicyNever,
		TouchPolicy: touchPolicy,
	}

	pub, err := yk.GenerateKey(piv.DefaultManagementKey, slot, opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Generate a self signed cert to provide metadata about the private key in the slot.
	// This is useful for users to discern where the key came from with tools like `ykman piv info`.
	cert, err := selfSignedMetadataCertificate()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Store a self-signed certificate to mark this slot as used by tsh.
	if err = yk.SetCertificate(piv.DefaultManagementKey, slot, cert); err != nil {
		return nil, trace.Wrap(err)
	}

	return newYubiKeyPrivateKey(y, slot, pub)
}

// getPrivateKey gets an existing private key from the given PIV slot.
func (y *yubiKey) getPrivateKey(slot piv.Slot) (*YubiKeyPrivateKey, error) {
	yk, err := y.open()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer yk.Close()

	// Check the slot's certificate to see if it contains a self signed Teleport Client cert.
	cert, err := yk.Certificate(slot)
	if err != nil || cert == nil {
		return nil, trace.NotFound("YubiKey certificate slot is empty, expected a Teleport Client cert")
	} else if len(cert.Subject.Organization) == 0 || cert.Subject.Organization[0] != certOrgName {
		return nil, trace.NotFound("YubiKey certificate slot contained unknown certificate:\n%+v", cert)
	}

	attestCert, err := yk.Attest(slot)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return newYubiKeyPrivateKey(y, slot, attestCert.PublicKey)
}

// open a connection to YubiKey PIV module. The returned connection should be closed once
// it's been used. The YubiKey PIV module itself takes some additional time to handle closed
// connections, so we use a retry loop to give the PIV module time to close prior connections.
func (y *yubiKey) open() (yk *piv.YubiKey, err error) {
	linearRetry, err := retryutils.NewLinear(retryutils.LinearConfig{
		// If a PIV connection has just been closed, it take ~5 ms to become
		// available to new connections. For this reason, we initially wait a
		// short 10ms before stepping up to a longer 50ms retry.
		First: time.Millisecond * 10,
		Step:  time.Millisecond * 10,
		// Since PIV modules only allow a single connection, it is a bottleneck
		// resource. To maximize usage, we use a short 50ms retry to catch the
		// connection opening up as soon as possible.
		Max: time.Millisecond * 50,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Backoff and retry for up to 1 second.
	retryCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err = linearRetry.For(retryCtx, func() error {
		yk, err = piv.Open(y.card)
		if err != nil && !isRetryError(err) {
			return retryutils.PermanentRetryError(err)
		}
		return trace.Wrap(err)
	})
	if trace.IsLimitExceeded(err) {
		// Using PIV synchronously causes issues since only one connection is allowed at a time.
		// This shouldn't be an issue for `tsh` which primarily runs consecutively, but Teleport
		// Connect works through callbacks, etc. and may try to open multiple connections at a time.
		// If this error is being emitted more than rarely, the 1 second timeout may need to be increased.
		//
		// It's also possible that the user is running another PIV program, which may hold the PIV
		// connection indefinitely (yubikey-agent). In this case, user action is necessary, so we
		// alert them with this issue.
		return nil, trace.LimitExceeded("could not connect to YubiKey as another application is using it. Please try again once the program that uses the YubiKey, such as yubikey-agent is closed")
	} else if err != nil {
		return nil, trace.Wrap(err)
	}
	return yk, nil
}

func isRetryError(err error) bool {
	const retryError = "connecting to smart card: the smart card cannot be accessed because of other connections outstanding"
	return strings.Contains(err.Error(), retryError)
}

// findYubiKey finds a yubiKey PIV card by serial number. If no serial
// number is provided, the first yubiKey found will be returned.
func findYubiKey(serialNumber uint32) (*yubiKey, error) {
	yubiKeyCards, err := findYubiKeyCards()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if len(yubiKeyCards) == 0 {
		if serialNumber != 0 {
			return nil, trace.ConnectionProblem(nil, "no YubiKey device connected with serial number %d", serialNumber)
		}
		return nil, trace.ConnectionProblem(nil, "no YubiKey device connected")
	}

	for _, card := range yubiKeyCards {
		y, err := newYubiKey(card)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		if serialNumber == 0 || y.serialNumber == serialNumber {
			return y, nil
		}
	}

	return nil, trace.ConnectionProblem(nil, "no YubiKey device connected with serial number %d", serialNumber)
}

// findYubiKeyCards returns a list of connected yubiKey PIV card names.
func findYubiKeyCards() ([]string, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var yubiKeyCards []string
	for _, card := range cards {
		if strings.Contains(strings.ToLower(card), PIVCardTypeYubiKey) {
			yubiKeyCards = append(yubiKeyCards, card)
		}
	}

	return yubiKeyCards, nil
}

func parsePIVSlot(slotKey uint32) (piv.Slot, error) {
	switch slotKey {
	case piv.SlotAuthentication.Key:
		return piv.SlotAuthentication, nil
	case piv.SlotSignature.Key:
		return piv.SlotSignature, nil
	case piv.SlotCardAuthentication.Key:
		return piv.SlotCardAuthentication, nil
	case piv.SlotKeyManagement.Key:
		return piv.SlotKeyManagement, nil
	default:
		retiredSlot, ok := piv.RetiredKeyManagementSlot(slotKey)
		if !ok {
			return piv.Slot{}, trace.BadParameter("slot %X does not exist", slotKey)
		}
		return retiredSlot, nil
	}
}

// certOrgName is used to identify Teleport Client self-signed certificates stored in yubiKey PIV slots.
const certOrgName = "teleport"

// selfSignedMetadataCertificate creates a self signed certificate to be stored in the
// YubiKey's PIV slot. This certificate is purely used as metadata to determine when a
// slot is in used by a Teleport Client and is not fit to be used in cryptographic operations.
func selfSignedMetadataCertificate() (*x509.Certificate, error) {
	// generate a small rsa key to quickly generate a metadata cert.
	priv, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit) // see crypto/tls/generate_cert.go
	if err != nil {
		return nil, trace.Wrap(err)
	}
	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		PublicKey:    priv.Public(),
		Subject: pkix.Name{
			Organization:       []string{certOrgName},
			OrganizationalUnit: []string{api.Version},
		},
	}
	if cert.Raw, err = x509.CreateCertificate(rand.Reader, cert, cert, priv.Public(), priv); err != nil {
		return nil, trace.Wrap(err)
	}
	return cert, nil
}

// YubiKeys require touch when signing with a private key that requires touch.
// Unfortunately, there is no good way to check whether touch is cached by the
// PIV module at a given time. In order to require touch only when needed, we
// prompt for touch after a short delay when we expect the request would succeed
// if touch were not required.
//
// There are some X factors which determine how long a request may take, such as the
// YubiKey model and firmware version, so the delays below may need to be adjusted to
// suit more models. The durations mentioned below were retrieved from testing with a
// YubiKey 5 nano (5.2.7) and a YubiKey NFC (5.4.3).
const (
	// piv.ECDSAPrivateKey.Sign consistently takes ~70 milliseconds. However, 200ms
	// should be imperceptible the the user and should avoid misfired prompts for
	// slower cards (if there are any).
	signTouchPromptDelay = time.Millisecond * 200
)
