/*
Copyright 2021 Gravitational, Inc.

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

package client

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/trace"

	wanlib "github.com/gravitational/teleport/lib/auth/webauthn"
	wancli "github.com/gravitational/teleport/lib/auth/webauthncli"
)

// promptWebauthn provides indirection for tests.
var promptWebauthn = wancli.Login

type stdinRead struct {
	value string
	err   error
}

// stdinHijack hijacks stdin for a single password-like read.
// After startRead is called the read will be sent to the C channel.
type stdinHijack struct {
	C       chan stdinRead
	started int32
}

func (h *stdinHijack) startRead() {
	if !atomic.CompareAndSwapInt32(&h.started, 0, 1) {
		return // Already started
	}
	h.C = make(chan stdinRead)
	go func() {
		value, err := PasswordFromConsole(context.Background())
		h.C <- stdinRead{value: value, err: err}
	}()
}

// mfaPrompt implements wancli.LoginPrompt for MFA logins.
// In most cases authenticators shouldn't require PINs or additional touches for
// MFA, but the implementation exists in case we find some unusual
// authenticators out there.
type mfaPrompt struct {
	// stdin and cancel are used in case of PIN reads.
	stdin  *stdinHijack
	cancel context.CancelFunc
}

func (p *mfaPrompt) PromptPIN() (string, error) {
	p.cancel()          // cancel OTP read, if any
	p.stdin.startRead() // as late as possible, in case it's not needed
	fmt.Fprintln(os.Stderr, "Enter your security key PIN:")
	read := <-p.stdin.C
	return read.value, read.err
}

func (p *mfaPrompt) PromptAdditionalTouch() error {
	fmt.Fprintf(os.Stderr, "Tap your security key again to complete login")
	return nil
}

// PromptMFAChallenge prompts the user to complete MFA authentication
// challenges.
// If promptDevicePrefix is set, it will be printed in prompts before "security
// key" or "device". This is used to emphasize between different kinds of
// devices, like registered vs new.
// Note that PromptMFAChallenge hijacks stdin for a possible OTP/PIN read.
func PromptMFAChallenge(
	ctx context.Context,
	proxyAddr string, c *proto.MFAAuthenticateChallenge, promptDevicePrefix string, quiet bool) (*proto.MFAAuthenticateResponse, error) {
	// Is there a challenge present?
	if c.TOTP == nil && c.WebauthnChallenge == nil {
		return &proto.MFAAuthenticateResponse{}, nil
	}

	hasTOTP := c.TOTP != nil
	hasWebauthn := c.WebauthnChallenge != nil

	// Does the current platform support hardware MFA? Adjust accordingly.
	switch {
	case !hasTOTP && !wancli.HasPlatformSupport():
		return nil, trace.BadParameter("hardware device MFA not supported by your platform, please register an OTP device")
	case !wancli.HasPlatformSupport():
		// Do not prompt for hardware devices, it won't work.
		hasWebauthn = false
	}

	var numGoroutines int
	if hasTOTP && hasWebauthn {
		numGoroutines = 2
	} else {
		numGoroutines = 1
	}

	type response struct {
		kind string
		resp *proto.MFAAuthenticateResponse
		err  error
	}
	respC := make(chan response, numGoroutines)

	// Use ctx and wg to clean up after ourselves.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	cancelAndWait := func() {
		cancel()
		wg.Wait()
	}

	otpCtx, otpCancel := context.WithCancel(ctx)
	defer otpCancel()

	// Fire TOTP goroutine.
	stdin := &stdinHijack{}
	if hasTOTP {
		wg.Add(1)
		go func() {
			defer wg.Done()
			const kind = "TOTP"
			if !quiet {
				if hasWebauthn {
					fmt.Fprintf(os.Stderr, "Tap any %[1]ssecurity key or enter a code from a %[1]sOTP device\n", promptDevicePrefix, promptDevicePrefix)
				} else {
					fmt.Fprintf(os.Stderr, "Enter an OTP code from a %sdevice\n", promptDevicePrefix)
				}
			}

			stdin.startRead()
			select {
			case <-otpCtx.Done():
				respC <- response{kind: kind, err: otpCtx.Err()}
				return
			case read := <-stdin.C:
				if read.err != nil {
					respC <- response{kind: kind, err: read.err}
					return
				}
				respC <- response{
					kind: kind,
					resp: &proto.MFAAuthenticateResponse{
						Response: &proto.MFAAuthenticateResponse_TOTP{
							TOTP: &proto.TOTPResponse{Code: read.value},
						},
					},
				}
			}
		}()
	} else if !quiet {
		fmt.Fprintf(os.Stderr, "Tap any %ssecurity key\n", promptDevicePrefix)
	}

	// Fire Webauthn goroutine.
	if hasWebauthn {
		origin := proxyAddr
		if !strings.HasPrefix(origin, "https://") {
			origin = "https://" + origin
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Debugf("WebAuthn: prompting devices with origin %q", origin)
			const user = ""
			prompt := &mfaPrompt{stdin: stdin, cancel: otpCancel}
			resp, _, err := promptWebauthn(ctx, origin, user, wanlib.CredentialAssertionFromProto(c.WebauthnChallenge), prompt)
			respC <- response{kind: "WEBAUTHN", resp: resp, err: err}
		}()
	}

	for i := 0; i < numGoroutines; i++ {
		select {
		case resp := <-respC:
			if err := resp.err; err != nil {
				log.WithError(err).Debugf("%s authentication failed", resp.kind)
				continue
			}

			// Cleanup in-flight goroutines.
			cancelAndWait()
			return resp.resp, nil
		case <-ctx.Done():
			cancelAndWait()
			return nil, trace.Wrap(ctx.Err())
		}
	}
	cancelAndWait()
	return nil, trace.BadParameter(
		"failed to authenticate using all MFA devices, rerun the command with '-d' to see error details for each device")
}

// MFAAuthenticateChallenge is an MFA authentication challenge sent on user
// login / authentication ceremonies.
type MFAAuthenticateChallenge struct {
	// WebauthnChallenge contains a WebAuthn credential assertion used for
	// login/authentication ceremonies.
	WebauthnChallenge *wanlib.CredentialAssertion `json:"webauthn_challenge"`
	// TOTPChallenge specifies whether TOTP is supported for this user.
	TOTPChallenge bool `json:"totp_challenge"`
}

// MakeAuthenticateChallenge converts proto to JSON format.
func MakeAuthenticateChallenge(protoChal *proto.MFAAuthenticateChallenge) *MFAAuthenticateChallenge {
	chal := &MFAAuthenticateChallenge{
		TOTPChallenge: protoChal.GetTOTP() != nil,
	}
	if protoChal.GetWebauthnChallenge() != nil {
		chal.WebauthnChallenge = wanlib.CredentialAssertionFromProto(protoChal.WebauthnChallenge)
	}
	return chal
}

type TOTPRegisterChallenge struct {
	QRCode []byte `json:"qrCode"`
}

// MFARegisterChallenge is an MFA register challenge sent on new MFA register.
type MFARegisterChallenge struct {
	// Webauthn contains webauthn challenge.
	Webauthn *wanlib.CredentialCreation `json:"webauthn"`
	// TOTP contains TOTP challenge.
	TOTP *TOTPRegisterChallenge `json:"totp"`
}

// MakeRegisterChallenge converts proto to JSON format.
func MakeRegisterChallenge(protoChal *proto.MFARegisterChallenge) *MFARegisterChallenge {
	switch protoChal.GetRequest().(type) {
	case *proto.MFARegisterChallenge_TOTP:
		return &MFARegisterChallenge{
			TOTP: &TOTPRegisterChallenge{
				QRCode: protoChal.GetTOTP().GetQRCode(),
			},
		}
	case *proto.MFARegisterChallenge_Webauthn:
		return &MFARegisterChallenge{
			Webauthn: wanlib.CredentialCreationFromProto(protoChal.GetWebauthn()),
		}
	}
	return nil
}
