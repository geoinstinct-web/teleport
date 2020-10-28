package pgproto3

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"

	"github.com/jackc/pgio"
)

type FunctionCallResponse struct {
	Result []byte
}

// Backend identifies this message as sendable by the PostgreSQL backend.
func (*FunctionCallResponse) Backend() {}

// Decode decodes src into dst. src must contain the complete message with the exception of the initial 1 byte message
// type identifier and 4 byte message length.
func (dst *FunctionCallResponse) Decode(src []byte) error {
	if len(src) < 4 {
		return &invalidMessageFormatErr{messageType: "FunctionCallResponse"}
	}
	rp := 0
	resultSize := int(binary.BigEndian.Uint32(src[rp:]))
	rp += 4

	if resultSize == -1 {
		dst.Result = nil
		return nil
	}

	if len(src[rp:]) != resultSize {
		return &invalidMessageFormatErr{messageType: "FunctionCallResponse"}
	}

	dst.Result = src[rp:]
	return nil
}

// Encode encodes src into dst. dst will include the 1 byte message type identifier and the 4 byte message length.
func (src *FunctionCallResponse) Encode(dst []byte) []byte {
	dst = append(dst, 'V')
	sp := len(dst)
	dst = pgio.AppendInt32(dst, -1)

	if src.Result == nil {
		dst = pgio.AppendInt32(dst, -1)
	} else {
		dst = pgio.AppendInt32(dst, int32(len(src.Result)))
		dst = append(dst, src.Result...)
	}

	pgio.SetInt32(dst[sp:], int32(len(dst[sp:])))

	return dst
}

// MarshalJSON implements encoding/json.Marshaler.
func (src FunctionCallResponse) MarshalJSON() ([]byte, error) {
	var formattedValue map[string]string
	var hasNonPrintable bool
	for _, b := range src.Result {
		if b < 32 {
			hasNonPrintable = true
			break
		}
	}

	if hasNonPrintable {
		formattedValue = map[string]string{"binary": hex.EncodeToString(src.Result)}
	} else {
		formattedValue = map[string]string{"text": string(src.Result)}
	}

	return json.Marshal(struct {
		Type   string
		Result map[string]string
	}{
		Type:   "FunctionCallResponse",
		Result: formattedValue,
	})
}
