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

package protocol

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

// prefixLength adds the length to the bytes, used in the header for valid full message parsing
func prefixLength(bytes []byte) []byte {
	length := uint32(len(bytes)) + 4 // add 4 for the 32bit length itself
	prefix := make([]byte, 4)
	binary.LittleEndian.PutUint32(prefix, length)
	return append(prefix, bytes...)
}

// prefixId will add a random 4 byte id.  This is typically used for building the header which needs a request
// followed by response id.
func prefixId(bytes []byte) []byte {
	prefix := make([]byte, 4)
	_, err := rand.Read(prefix)
	if err != nil {
		panic(err)
	}
	return append(prefix, bytes...)
}

func FuzzMongoRead(f *testing.F) {
	// normal op msg single document
	f.Add(prefixLength(prefixId(prefixId([]byte{0xdd, 0x7, 0x0, 0x0, // (end header) op code
		0x30, 0x30, 0x30, 0x30, // msg flags
		0x0,                // section type
		0x5, 0x0, 0x0, 0x0, // msg size
		0x20})))) // msg
	// normal op query
	f.Add(prefixLength(prefixId(prefixId([]byte{0xd4, 0x7, 0x0, 0x0, // (end header) op code
		0x30, 0x30, 0x30, 0x30, // read flags
		0x0,                // collection name
		0x0, 0x0, 0x0, 0x0, // skip number
		0x1, 0x0, 0x0, 0x0, // return number
		0x5, 0x0, 0x0, 0x0, // msg size
		0x20})))) // msg
	// normal op get more
	f.Add(prefixLength(prefixId(prefixId([]byte{0xd5, 0x7, 0x0, 0x0, // (end header) op code
		0x30, 0x30, 0x30, 0x30, // zero
		0x0,                // collection name
		0x1, 0x0, 0x0, 0x0, // return number
		0x5, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0})))) // cursor id
	// normal op insert
	f.Add(prefixLength(prefixId(prefixId([]byte{0xd2, 0x7, 0x0, 0x0, // (end header) op code
		0x30, 0x30, 0x30, 0x30, // insert flags
		0x0,                // collection name
		0x5, 0x0, 0x0, 0x0, // document size
		0x20,               // document
		0x6, 0x0, 0x0, 0x0, // document size
		0x20, 0x20})))) // document
	// normal op update
	f.Add(prefixLength(prefixId(prefixId([]byte{0xd1, 0x7, 0x0, 0x0, // (end header) op code
		0x30, 0x30, 0x30, 0x30, // zero
		0x0,                    // collection name
		0x30, 0x30, 0x30, 0x30, // flags
		0x5, 0x0, 0x0, 0x0, // select document size
		0x20,               // select document
		0x6, 0x0, 0x0, 0x0, // update document size
		0x20, 0x20})))) // update document
	// normal op delete
	f.Add(prefixLength(prefixId(prefixId([]byte{0xd6, 0x7, 0x0, 0x0, // (end header) op code
		0x30, 0x30, 0x30, 0x30, // zero
		0x0,                    // collection name
		0x30, 0x30, 0x30, 0x30, // flags
		0x5, 0x0, 0x0, 0x0, // document size
		0x20})))) // document
	// normal op reply
	f.Add([]byte{0x30, 0x0, 0x0, 0x0, // (start header) length
		0x30, 0x30, 0x40, 0x30, // request id
		0x30, 0x30, 0x30, 0x30, // response to
		0x1, 0x0, 0x0, 0x0, // (end header) op code
		0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
		0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x1, 0x0, 0x0, 0x0, 0x0, 0x30,
		0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30})
	// normal op kill cursor
	f.Add(prefixLength(prefixId(prefixId([]byte{0xd7, 0x7, 0x0, 0x0, // (end header) op code
		0x30, 0x30, 0x30, 0x30, // zero
		0x2, 0x0, 0x0, 0x0, // cursor id count
		0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, // cursor id
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22})))) // cursor id
	// typical header start seed
	f.Add([]byte{0x1a, 0x0, 0x0, 0x0, // arbitrary length for fuzz to fill in suffix of
		0x30, 0x30, 0x11, 0x30, 0x30, 0x30, 0x30, 0x30})
	// large decompression test (Zstd mode but large size declared early)
	f.Add([]byte{0x1b, 0x0, 0x0, 0x0, 0x30, 0x30, 0x30, 0x30, 0x7f, 0x30, 0x30, 0x30,
		0xdc, 0x7, 0x0, 0x0, // op code
		0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x3, 0x30, 0x30})
	// large Snappy decompression (size declared small till Snappy size decoded)
	f.Add([]byte{0x20, 0x0, 0x0, 0x0, 0x30, 0x30, 0x30, 0x30, 0x50, 0x30, 0x30, 0x30,
		0xdc, 0x7, 0x0, 0x0, // op code
		0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x0, 0x1, 0xf5, 0xf5, 0xf6,
		0x80, 0xe, 0x30, 0x30, 0x30, 0x30, 0x30})
	// op msg with too small of msg
	f.Add([]byte{0x20, 0x0, 0x0, 0x0, // (start header) length
		0x30, 0x30, 0x11, 0x30, // request id
		0x30, 0x30, 0x30, 0x30, // response to
		0xdd, 0x7, 0x0, 0x0, // (end header) op code
		0x30, 0x30, 0x30, 0x30, 0x30, 0x1, 0xa, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0xF, // msg size
		0x20})
	// op msg sequence without body
	f.Add([]byte{0x20, 0x0, 0x0, 0x0, // (start header) length
		0x30, 0x30, 0x11, 0x30, // request id
		0x30, 0x30, 0x30, 0x30, // response to
		0xdd, 0x7, 0x0, 0x0, // (end header) op code
		0x30, 0x30, 0x30, 0x30, 0x30, 0x1, 0xa, 0x0, 0x0, 0x0, 0x0,
		0x5, 0x0, 0x0, 0x0, // msg size
		0x20})
	// compressed with invalid message size
	f.Add([]byte(" \x00\x00\x0000000000\xdc\a\x00\x000000000\xca\x010000000"))
	// op message document sequence with invalid size
	f.Add([]byte(" \x00\x00\x0000000000\xdd\a\x00\x000000\x01000\x8e0000000000000"))
	// op message document sequence with multiple document iteration ending in too short of document
	f.Add([]byte(" \x00\x00\x0000000000\xdd\a\x00\x00000000000000\x01000"))
	// op insert with zero length document
	f.Add([]byte(" \x00\x00\x0000000000\xd2\a\x00\x000000\x00\x00\x00\x00\x00\x00000000"))
	// invalid header
	f.Add([]byte("000\xa4000000000000"))
	// Header EOF due to large size defined
	f.Add([]byte{0x1d, 0x1d, 0x0, 0x0, // (start header) length
		0x0, 0x0, 0x2f, 0x0, // request id
		0x0, 0x30, 0x13, 0x0, // response to
		0x0, 0xdc, 0x7, 0x0, // (end header) op code
		0x0})

	f.Fuzz(func(t *testing.T, msgBytes []byte) {
		msg := bytes.NewReader(msgBytes)

		require.NotPanics(t, func() {
			_, _ = ReadMessage(msg)
		})
	})
}
