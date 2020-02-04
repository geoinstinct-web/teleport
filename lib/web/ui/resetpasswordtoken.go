/*
Copyright 2020 Gravitational, Inc.

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

package ui

import "time"

// ResetPasswordToken describes ResetPasswordToken UI object
type ResetPasswordToken struct {
	// TokenID is token ID
	TokenID string `json:"tokenId"`
	// User is user name associated with this token
	User string `json:"user"`
	// QRCode is a QR code value
	QRCode []byte `json:"qrCode,omitempty"`
	// URL is token URL
	URL string `json:"url,omitempty"`
	// Expiry is token expiration time
	Expiry time.Time `json:"expiry,omitempty"`
}
