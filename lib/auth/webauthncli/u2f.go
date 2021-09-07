// Copyright 2021 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package webauthncli

import (
	"context"
	"errors"
	"time"

	"github.com/flynn/u2f/u2fhid"
	"github.com/flynn/u2f/u2ftoken"
	"github.com/gravitational/trace"

	log "github.com/sirupsen/logrus"
)

// DevicePollInterval is the interval between polling attempts on Webauthn or
// U2F devices.
// Used by otherwise tight loops such as RunOnU2FDevices and related methods,
// like Login.
var DevicePollInterval = 200 * time.Millisecond

var errKeyMissingOrNotVerified = errors.New("key missing or user presence not verified")

// Token represents the actions possible using an U2F/CTAP1 token.
type Token interface {
	CheckAuthenticate(req u2ftoken.AuthenticateRequest) error
	Authenticate(req u2ftoken.AuthenticateRequest) (*u2ftoken.AuthenticateResponse, error)
	Register(req u2ftoken.RegisterRequest) ([]byte, error)
}

// u2fDevices, u2fOpen and u2fNewToken allows tests to fake interactions with
// devices.
var u2fDevices = u2fhid.Devices
var u2fOpen = u2fhid.Open
var u2fNewToken = func(d u2ftoken.Device) Token {
	return u2ftoken.NewToken(d)
}

type unknownHandleKey struct {
	Callback int
	Path     string
}

// RunOnU2FDevices polls for new U2F/CTAP1 devices and invokes the callbacks
// against them in regular intervals, running until either one callback succeeds
// or the context is cancelled.
// Typically, each callback represents a {credential,rpid} pair to check against
// the device.
// Calling this method using a context without a cancel or deadline means it
// will execute until successful (which may be never).
// Most callers should prefer higher-abstraction functions such as Login.
func RunOnU2FDevices(ctx context.Context, runCredentials ...func(Token) error) error {
	ticker := time.NewTicker(DevicePollInterval)
	defer ticker.Stop()

	unknownHandles := make(map[unknownHandleKey]bool)
	for {
		switch err := runOnU2FDevicesOnce(unknownHandles, runCredentials); {
		case err == errKeyMissingOrNotVerified:
			// This is expected to happen a few times.
		case err != nil:
			log.WithError(err).Debug("Error interacting with U2F devices")
		default: // OK, success.
			return nil
		}

		select {
		case <-ticker.C:
		case <-ctx.Done():
			return trace.Wrap(ctx.Err())
		}
	}
}

func runOnU2FDevicesOnce(unknownHandles map[unknownHandleKey]bool, runCredentials []func(Token) error) error {
	// Ask for devices every iteration, the user may plug a new device.
	infos, err := u2fDevices()
	if err != nil {
		return trace.Wrap(err)
	}

	var swallowed []error
	for _, info := range infos {
		dev, err := u2fOpen(info)
		if err != nil {
			// u2fhid.Open is a bit more prone to errors, especially "hid: privilege
			// violation" errors. Try other devices before bailing.
			swallowed = append(swallowed, err)
			continue
		}

		token := u2fNewToken(dev)
		for i, fn := range runCredentials {
			key := unknownHandleKey{Callback: i, Path: info.Path}
			if info.Path != "" && unknownHandles[key] {
				// Device doesn't know the KeyHandle+RPID pair. This won't change during
				// the attempt.
				// We may get to a situation where none of the devices know the
				// {KeyHandle,RPID} pair, but we keep on trying because the user may
				// plug another device.
				continue
			}

			switch err := fn(token); {
			case err == nil:
				return nil // OK, we got it.
			case err == u2ftoken.ErrPresenceRequired:
				// Wait for user action, they will choose the device to use.
			case err == u2ftoken.ErrUnknownKeyHandle:
				unknownHandles[key] = true // No need to try this anymore.
			case err != nil:
				swallowed = append(swallowed, err)
			}
		}
	}
	if len(swallowed) > 0 {
		return trace.NewAggregate(swallowed...)
	}

	return errKeyMissingOrNotVerified // don't wrap, simplifies comparisons
}
