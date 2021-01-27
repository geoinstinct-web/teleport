package pgproto3

import (
	"encoding/json"
)

type ReadyForQuery struct {
	TxStatus byte
}

// Backend identifies this message as sendable by the PostgreSQL backend.
func (*ReadyForQuery) Backend() {}

// Decode decodes src into dst. src must contain the complete message with the exception of the initial 1 byte message
// type identifier and 4 byte message length.
func (dst *ReadyForQuery) Decode(src []byte) error {
	if len(src) != 1 {
		return &invalidMessageLenErr{messageType: "ReadyForQuery", expectedLen: 1, actualLen: len(src)}
	}

	dst.TxStatus = src[0]

	return nil
}

// Encode encodes src into dst. dst will include the 1 byte message type identifier and the 4 byte message length.
func (src *ReadyForQuery) Encode(dst []byte) []byte {
	return append(dst, 'Z', 0, 0, 0, 5, src.TxStatus)
}

// MarshalJSON implements encoding/json.Marshaler.
func (src ReadyForQuery) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type     string
		TxStatus string
	}{
		Type:     "ReadyForQuery",
		TxStatus: string(src.TxStatus),
	})
}
