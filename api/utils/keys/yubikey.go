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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-piv/piv-go/piv"
	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api"
	attestation "github.com/gravitational/teleport/api/gen/proto/go/attestation/v1"
	"github.com/gravitational/teleport/api/utils/prompt"
	"github.com/gravitational/teleport/api/utils/retryutils"
)

const (
	// PIVCardTypeYubiKey is the PIV card type assigned to yubiKeys.
	PIVCardTypeYubiKey = "yubikey"
)

// getOrGenerateYubiKeyPrivateKey connects to a connected yubiKey and gets a private key
// matching the given touch requirement. This private key will either be newly generated
// or previously generated by a Teleport client and reused.
func getOrGenerateYubiKeyPrivateKey(ctx context.Context, requiredKeyPolicy PrivateKeyPolicy, slot string) (*PrivateKey, error) {
	// Use the first yubiKey we find.
	y, err := FindYubiKey(0)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	promptOverwriteSlot := func(msg string) error {
		promptQuestion := fmt.Sprintf("%v\nWould you like to overwrite this slot's private key and certificate?", msg)
		if confirmed, confirmErr := prompt.Confirmation(ctx, os.Stderr, prompt.Stdin(), promptQuestion); confirmErr != nil {
			return trace.Wrap(confirmErr)
		} else if !confirmed {
			return trace.Wrap(trace.CompareFailed(msg), "user declined to overwrite slot")
		}
		return nil
	}

	// If a specific slot was specified, use that. Otherwise, check for a key in the
	// default slot for the given policy and generate a new one if needed.
	var pivSlot piv.Slot
	if slot != "" {
		pivSlot, err = parsePIVSlotString(slot)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	} else {
		pivSlot, err = GetDefaultKeySlot(requiredKeyPolicy)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		// Check the client certificate in the slot.
		switch cert, err := y.getCertificate(pivSlot); {
		case err == nil && (len(cert.Subject.Organization) == 0 || cert.Subject.Organization[0] != certOrgName):
			// Unknown cert found, prompt the user before we overwrite the slot.
			if err := promptOverwriteSlot(nonTeleportCertificateMessage(pivSlot, cert)); err != nil {
				return nil, trace.Wrap(err)
			}

			// user confirmed, generate a new key.
			fallthrough
		case errors.Is(err, piv.ErrNotFound):
			// no cert found, generate a new key.
			priv, err := y.generatePrivateKeyAndCert(pivSlot, requiredKeyPolicy)
			return priv, trace.Wrap(err)
		case err != nil:
			return nil, trace.Wrap(err)
		}
	}

	// Get the key in the slot, or generate a new one if needed.
	priv, err := y.getPrivateKey(pivSlot)
	switch {
	case err == nil && requiredKeyPolicy.VerifyPolicy(priv.GetPrivateKeyPolicy()) != nil:
		// Key does not meet the required key policy, prompt the user before we overwrite the slot.
		msg := fmt.Sprintf("private key in YubiKey PIV slot %q does not meet private key policy %q.", pivSlot, requiredKeyPolicy)
		if err := promptOverwriteSlot(msg); err != nil {
			return nil, trace.Wrap(err)
		}

		// user confirmed, generate a new key.
		fallthrough
	case trace.IsNotFound(err):
		// no key found, generate a new key.
		priv, err := y.generatePrivateKeyAndCert(pivSlot, requiredKeyPolicy)
		return priv, trace.Wrap(err)
	case err != nil:
		return nil, trace.Wrap(err)
	}

	return priv, nil
}

func GetDefaultKeySlot(policy PrivateKeyPolicy) (piv.Slot, error) {
	switch policy {
	case PrivateKeyPolicyHardwareKey:
		// private_key_policy: hardware_key -> 9a
		return piv.SlotAuthentication, nil
	case PrivateKeyPolicyHardwareKeyTouch:
		// private_key_policy: hardware_key_touch -> 9c
		return piv.SlotSignature, nil
	default:
		return piv.Slot{}, trace.BadParameter("unexpected private key policy %v", policy)
	}
}

func getKeyPolicies(policy PrivateKeyPolicy) (piv.TouchPolicy, piv.PINPolicy, error) {
	switch policy {
	case PrivateKeyPolicyHardwareKey:
		return piv.TouchPolicyNever, piv.PINPolicyNever, nil
	case PrivateKeyPolicyHardwareKeyTouch:
		return piv.TouchPolicyCached, piv.PINPolicyNever, nil
	default:
		return piv.TouchPolicyNever, piv.PINPolicyNever, trace.BadParameter("unexpected private key policy %v", policy)
	}
}

func nonTeleportCertificateMessage(slot piv.Slot, cert *x509.Certificate) string {
	// Gather a small list of user-readable x509 certificate fields to display to the user.
	sum := sha256.Sum256(cert.Raw)
	fingerPrint := hex.EncodeToString(sum[:])
	return fmt.Sprintf(`Certificate in YubiKey PIV slot %q is not a Teleport client cert:
Slot %s:
	Algorithm:		%v	
	Subject DN:		%v	
	Issuer DN:		%v	
	Serial:			%v	
	Fingerprint:	%v	
	Not before:		%v	
	Not after:		%v
`,
		slot, slot,
		cert.SignatureAlgorithm,
		cert.Subject,
		cert.Issuer,
		cert.SerialNumber,
		fingerPrint,
		cert.NotBefore,
		cert.NotAfter,
	)
}

// YubiKeyPrivateKey is a YubiKey PIV private key. Cryptographical operations open
// a new temporary connection to the PIV card to perform the operation.
type YubiKeyPrivateKey struct {
	// YubiKey is a specific YubiKey PIV module.
	*YubiKey

	pivSlot piv.Slot
	signMux sync.Mutex

	slotCert        *x509.Certificate
	attestationCert *x509.Certificate
	attestation     *piv.Attestation
}

// yubiKeyPrivateKeyData is marshalable data used to retrieve a specific yubiKey PIV private key.
type yubiKeyPrivateKeyData struct {
	SerialNumber uint32 `json:"serial_number"`
	SlotKey      uint32 `json:"slot_key"`
}

func parseYubiKeyPrivateKeyData(keyDataBytes []byte) (*PrivateKey, error) {
	var keyData yubiKeyPrivateKeyData
	if err := json.Unmarshal(keyDataBytes, &keyData); err != nil {
		return nil, trace.Wrap(err)
	}

	pivSlot, err := parsePIVSlot(keyData.SlotKey)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	y, err := FindYubiKey(keyData.SerialNumber)
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
	return y.slotCert.PublicKey
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

	privateKey, err := yk.PrivateKey(y.pivSlot, y.Public(), piv.KeyAuth{})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if y.attestation.TouchPolicy != piv.TouchPolicyNever {
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

func (y *YubiKeyPrivateKey) toPrivateKey() (*PrivateKey, error) {
	keyPEM, err := y.keyPEM()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return NewPrivateKey(y, keyPEM)
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
func (y *YubiKeyPrivateKey) GetAttestationStatement() *AttestationStatement {
	return &AttestationStatement{
		AttestationStatement: &attestation.AttestationStatement_YubikeyAttestationStatement{
			YubikeyAttestationStatement: &attestation.YubiKeyAttestationStatement{
				SlotCert:        y.slotCert.Raw,
				AttestationCert: y.attestationCert.Raw,
			},
		},
	}
}

// GetPrivateKeyPolicy returns the PrivateKeyPolicy supported by this YubiKeyPrivateKey.
func (y *YubiKeyPrivateKey) GetPrivateKeyPolicy() PrivateKeyPolicy {
	return GetPrivateKeyPolicyFromAttestation(y.attestation)
}

// GetPrivateKeyPolicyFromAttestation returns the PrivateKeyPolicy met by the given hardware key attestation.
func GetPrivateKeyPolicyFromAttestation(att *piv.Attestation) PrivateKeyPolicy {
	switch att.TouchPolicy {
	case piv.TouchPolicyCached, piv.TouchPolicyAlways:
		return PrivateKeyPolicyHardwareKeyTouch
	default:
		return PrivateKeyPolicyHardwareKey
	}
}

// YubiKey is a specific YubiKey PIV card.
type YubiKey struct {
	// card is a reader name used to find and connect to this yubiKey.
	// This value may change between OS's, or with other system changes.
	card string
	// serialNumber is the yubiKey's 8 digit serial number.
	serialNumber uint32
}

func newYubiKey(card string) (*YubiKey, error) {
	y := &YubiKey{card: card}

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

// Reset resets the YubiKey PIV module to default settings.
func (y *YubiKey) Reset() error {
	yk, err := y.open()
	if err != nil {
		return trace.Wrap(err)
	}
	defer yk.Close()

	err = yk.Reset()
	return trace.Wrap(err)
}

// generatePrivateKeyAndCert generates a new private key and client metadata cert in the given PIV slot.
func (y *YubiKey) generatePrivateKeyAndCert(slot piv.Slot, requiredKeyPolicy PrivateKeyPolicy) (*PrivateKey, error) {
	if err := y.generatePrivateKey(slot, requiredKeyPolicy); err != nil {
		return nil, trace.Wrap(err)
	}

	if err := y.SetMetadataCertificate(slot, pkix.Name{
		Organization:       []string{certOrgName},
		OrganizationalUnit: []string{api.Version},
	}); err != nil {
		return nil, trace.Wrap(err)
	}

	return y.getPrivateKey(slot)
}

// SetMetadataCertificate creates a self signed certificate and stores it in the YubiKey's
// PIV certificate slot. This certificate is purely used as metadata to determine when a
// slot is in used by a Teleport Client and is not fit to be used in cryptographic operations.
// This cert is also useful for users to discern where the key came with tools like `ykman piv info`.
func (y *YubiKey) SetMetadataCertificate(slot piv.Slot, subject pkix.Name) error {
	yk, err := y.open()
	if err != nil {
		return trace.Wrap(err)
	}
	defer yk.Close()

	cert, err := SelfSignedMetadataCertificate(subject)
	if err != nil {
		return trace.Wrap(err)
	}

	err = yk.SetCertificate(piv.DefaultManagementKey, slot, cert)
	return trace.Wrap(err)
}

// getCertificate gets a certificate from the given PIV slot.
func (y *YubiKey) getCertificate(slot piv.Slot) (*x509.Certificate, error) {
	yk, err := y.open()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer yk.Close()

	cert, err := yk.Certificate(slot)
	return cert, trace.Wrap(err)
}

// generatePrivateKey generates a new private key in the given PIV slot.
func (y *YubiKey) generatePrivateKey(slot piv.Slot, requiredKeyPolicy PrivateKeyPolicy) error {
	yk, err := y.open()
	if err != nil {
		return trace.Wrap(err)
	}
	defer yk.Close()

	touchPolicy, pinPolicy, err := getKeyPolicies(requiredKeyPolicy)
	if err != nil {
		return trace.Wrap(err)
	}

	opts := piv.Key{
		Algorithm:   piv.AlgorithmEC256,
		PINPolicy:   pinPolicy,
		TouchPolicy: touchPolicy,
	}

	_, err = yk.GenerateKey(piv.DefaultManagementKey, slot, opts)
	return trace.Wrap(err)
}

// getPrivateKey gets an existing private key from the given PIV slot.
func (y *YubiKey) getPrivateKey(slot piv.Slot) (*PrivateKey, error) {
	yk, err := y.open()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer yk.Close()

	slotCert, err := yk.Attest(slot)
	if errors.Is(err, piv.ErrNotFound) {
		return nil, trace.NotFound("private key in YubiKey PIV slot %q not found.", slot.String())
	} else if err != nil {
		return nil, trace.Wrap(err)
	}

	attCert, err := yk.AttestationCertificate()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	attestation, err := piv.Verify(attCert, slotCert)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// We don't yet support pin policies so we must return a user readable error in case
	// they passed a mis-configured slot. Otherwise they will get a PIV auth error during signing.
	// TODO(Joerger): remove this check once PIN prompt is supported.
	if attestation.PINPolicy != piv.PINPolicyNever {
		return nil, trace.NotImplemented(`PIN policy is not currently supported. Please generate a key with PIN policy "never"`)
	}

	priv := &YubiKeyPrivateKey{
		YubiKey:         y,
		pivSlot:         slot,
		slotCert:        slotCert,
		attestationCert: attCert,
		attestation:     attestation,
	}

	keyPEM, err := priv.keyPEM()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return NewPrivateKey(priv, keyPEM)
}

// open a connection to YubiKey PIV module. The returned connection should be closed once
// it's been used. The YubiKey PIV module itself takes some additional time to handle closed
// connections, so we use a retry loop to give the PIV module time to close prior connections.
func (y *YubiKey) open() (yk *piv.YubiKey, err error) {
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

// FindYubiKey finds a yubiKey PIV card by serial number. If no serial
// number is provided, the first yubiKey found will be returned.
func FindYubiKey(serialNumber uint32) (*YubiKey, error) {
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

func validatePIVSlotKey(slotKeyString string) error {
	_, err := parsePIVSlotString(slotKeyString)
	return trace.Wrap(err)
}

func parsePIVSlotString(slotKeyString string) (piv.Slot, error) {
	slotKey, err := strconv.ParseUint(slotKeyString, 16, 32)
	if err != nil {
		return piv.Slot{}, trace.Wrap(err)
	}

	return parsePIVSlot(uint32(slotKey))
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

func SelfSignedMetadataCertificate(subject pkix.Name) (*x509.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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
		Subject:      subject,
		PublicKey:    priv.Public(),
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
