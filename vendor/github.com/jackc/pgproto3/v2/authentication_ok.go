package pgproto3

import (
	"encoding/binary"
	"errors"

	"github.com/jackc/pgio"
)

// AuthenticationOk is a message sent from the backend indicating that authentication was successful.
type AuthenticationOk struct {
}

// Backend identifies this message as sendable by the PostgreSQL backend.
func (*AuthenticationOk) Backend() {}

// Decode decodes src into dst. src must contain the complete message with the exception of the initial 1 byte message
// type identifier and 4 byte message length.
func (dst *AuthenticationOk) Decode(src []byte) error {
	if len(src) != 4 {
		return errors.New("bad authentication message size")
	}

	authType := binary.BigEndian.Uint32(src)

	if authType != AuthTypeOk {
		return errors.New("bad auth type")
	}

	return nil
}

// Encode encodes src into dst. dst will include the 1 byte message type identifier and the 4 byte message length.
func (src *AuthenticationOk) Encode(dst []byte) []byte {
	dst = append(dst, 'R')
	dst = pgio.AppendInt32(dst, 8)
	dst = pgio.AppendUint32(dst, AuthTypeOk)
	return dst
}
