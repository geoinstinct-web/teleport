// Copyright 2022 Gravitational, Inc
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

package touchid

import (
	"errors"

	"github.com/gravitational/trace"

	wanlib "github.com/gravitational/teleport/lib/auth/webauthn"
)

// ErrAttemptFailed is returned by AttemptLogin for attempts that failed before
// user interaction.
type ErrAttemptFailed struct {
	// Err is the underlying failure for the attempt.
	Err error
}

func (e *ErrAttemptFailed) Error() string {
	return e.Err.Error()
}

func (e *ErrAttemptFailed) Unwrap() error {
	return e.Err
}

func (e *ErrAttemptFailed) Is(target error) bool {
	_, ok := target.(*ErrAttemptFailed)
	return ok
}

func (e *ErrAttemptFailed) As(target interface{}) bool {
	tt, ok := target.(*ErrAttemptFailed)
	if ok {
		tt.Err = e.Err
		return true
	}
	return false
}

// AttemptLogin attempts a touch ID login.
// It returns ErrAttemptFailed if the attempt failed before user interaction.
// See Login.
func AttemptLogin(origin, user string, assertion *wanlib.CredentialAssertion) (*wanlib.CredentialAssertionResponse, string, error) {
	resp, actualUser, err := Login(origin, user, assertion)
	switch {
	case errors.Is(err, ErrNotAvailable), errors.Is(err, ErrCredentialNotFound):
		return nil, "", &ErrAttemptFailed{Err: err}
	case err != nil:
		return nil, "", trace.Wrap(err)
	}
	return resp, actualUser, nil
}
