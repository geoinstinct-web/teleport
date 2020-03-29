package auth

import (
	"crypto/subtle"

	"golang.org/x/crypto/bcrypt"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/trace"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

var fakePasswordHash = []byte(`$2a$10$Yy.e6BmS2SrGbBDsyDLVkOANZmvjjMR890nUGSXFJHBXWzxe7T44m`)

// Count of recovery tokens for 2FA
const RecoveryTokenCount = 10

// Length of recovery tokens for 2FA
const RecoveryTokenLength = 32

// ChangePassword changes user passsword
func (s *AuthServer) ChangePassword(req services.ChangePasswordReq) error {
	// validate new password
	err := services.VerifyPassword(req.NewPassword)
	if err != nil {
		return trace.Wrap(err)
	}

	authPreference, err := s.GetAuthPreference()
	if err != nil {
		return trace.Wrap(err)
	}

	userID := req.User
	fn := func() error {
		secondFactor := authPreference.GetSecondFactor()
		switch secondFactor {
		case teleport.OFF:
			return s.CheckPasswordWOToken(userID, req.OldPassword)
		case teleport.OTP:
			return s.CheckPassword(userID, req.OldPassword, req.SecondFactorToken)
		case teleport.U2F:
			if req.U2FSignResponse == nil {
				return trace.BadParameter("missing U2F sign response")
			}

			return s.CheckU2FSignResponse(userID, req.U2FSignResponse)
		}

		return trace.BadParameter("unsupported second factor method: %q", secondFactor)
	}

	err = s.WithUserLock(userID, fn)
	if err != nil {
		return trace.Wrap(err)
	}

	return trace.Wrap(s.UpsertPassword(userID, req.NewPassword))
}

// CheckPasswordWOToken checks just password without checking OTP tokens
// used in case of SSH authentication, when token has been validated.
func (s *AuthServer) CheckPasswordWOToken(user string, password []byte) error {
	const errMsg = "invalid username or password"

	err := services.VerifyPassword(password)
	if err != nil {
		return trace.BadParameter(errMsg)
	}

	hash, err := s.GetPasswordHash(user)
	if err != nil && !trace.IsNotFound(err) {
		return trace.Wrap(err)
	}
	if trace.IsNotFound(err) {
		log.Debugf("Username %q not found, using fake hash to mitigate timing attacks.", user)
		hash = fakePasswordHash
	}

	if err = bcrypt.CompareHashAndPassword(hash, password); err != nil {
		log.Debugf("Password for %q does not match", user)
		return trace.BadParameter(errMsg)
	}

	return nil
}

// CheckPassword checks the password and OTP token. Called by tsh or lib/web/*.
func (s *AuthServer) CheckPassword(user string, password []byte, otpToken string) error {
	err := s.CheckPasswordWOToken(user, password)
	if err != nil {
		return trace.Wrap(err)
	}

	err = s.CheckOTP(user, otpToken)
	return trace.Wrap(err)
}

// CheckOTP determines the type of OTP token used (for legacy HOTP and recovery support), fetches the
// appropriate type from the backend, and checks if the token is valid.
func (s *AuthServer) CheckOTP(user string, otpToken string) error {
	var err error

	if len(otpToken) == RecoveryTokenLength {
		tokens, err := s.GetRecoveryTokens(user)
		if err != nil {
			return trace.Wrap(err)
		}

		for _, token := range tokens {
			if token == otpToken {
				return nil
			}
		}

		return trace.BadParameter("invalid recovery token")
	}

	otpType, err := s.getOTPType(user)
	if err != nil {
		return trace.Wrap(err)
	}

	switch otpType {
	case teleport.HOTP:
		otp, err := s.GetHOTP(user)
		if err != nil {
			return trace.Wrap(err)
		}

		// look ahead n tokens to see if we can find a matching token
		if !otp.Scan(otpToken, defaults.HOTPFirstTokensRange) {
			return trace.BadParameter("bad one time token")
		}

		// we need to upsert the hotp state again because the
		// counter was incremented
		if err := s.UpsertHOTP(user, otp); err != nil {
			return trace.Wrap(err)
		}
	case teleport.TOTP:
		otpSecret, err := s.GetTOTP(user)
		if err != nil {
			return trace.Wrap(err)
		}

		// get the previously used token to mitigate token replay attacks
		usedToken, err := s.GetUsedTOTPToken(user)
		if err != nil {
			return trace.Wrap(err)
		}

		// we use a constant time compare function to mitigate timing attacks
		if subtle.ConstantTimeCompare([]byte(otpToken), []byte(usedToken)) == 1 {
			return trace.BadParameter("previously used totp token")
		}

		// we use totp.ValidateCustom over totp.Validate so we can use
		// a fake clock in tests to get reliable results
		valid, err := totp.ValidateCustom(otpToken, otpSecret, s.clock.Now(), totp.ValidateOpts{
			Period:    teleport.TOTPValidityPeriod,
			Skew:      teleport.TOTPSkew,
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		})
		if err != nil {
			log.Errorf("unable to validate token: %v", err)
			return trace.BadParameter("unable to validate token")
		}
		if !valid {
			return trace.BadParameter("invalid totp token")
		}

		// if we have a valid token, update the previously used token
		err = s.UpsertUsedTOTPToken(user, otpToken)
		if err != nil {
			return trace.Wrap(err)
		}
	}

	return nil
}

// getOTPType returns the type of OTP token used, HOTP or TOTP.
// Deprecated: Remove this method once HOTP support has been removed.
func (s *AuthServer) getOTPType(user string) (string, error) {
	_, err := s.GetHOTP(user)
	if err != nil {
		if trace.IsNotFound(err) {
			return teleport.TOTP, nil
		}
		return "", trace.Wrap(err)
	}
	return teleport.HOTP, nil
}

// GetOTPData returns the OTP Key, Key URL, and the QR code.
func (s *AuthServer) GetOTPData(user string) (string, []byte, error) {
	// get otp key from backend
	otpSecret, err := s.GetTOTP(user)
	if err != nil {
		return "", nil, trace.Wrap(err)
	}

	// create otp url
	params := map[string][]byte{"secret": []byte(otpSecret)}
	otpURL := utils.GenerateOTPURL("totp", user, params)

	// create the qr code
	otpQR, err := utils.GenerateQRCode(otpURL)
	if err != nil {
		return "", nil, trace.Wrap(err)
	}

	return otpURL, otpQR, nil
}
