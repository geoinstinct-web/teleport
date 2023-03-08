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

package fixtures

import (
	"encoding/binary"
)

var (
	// PreLogin is an example Pre-Login request packet from the protocol spec:
	//
	// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/9420b4a3-eb9f-4f5e-90bd-3160444aa5a7
	PreLogin = []byte{
		0x12, 0x01, 0x00, 0x2F, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1A, 0x00, 0x06, 0x01, 0x00, 0x20,
		0x00, 0x01, 0x02, 0x00, 0x21, 0x00, 0x01, 0x03, 0x00, 0x22, 0x00, 0x04, 0x04, 0x00, 0x26, 0x00,
		0x01, 0xFF, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0xB8, 0x0D, 0x00, 0x00, 0x01,
	}

	// Login7 is an example Login7 request packet from the protocol spec:
	//
	// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/ce5ad23f-6bf8-4fa5-9426-6b0d36e14da2
	Login7 = []byte{
		0x10, 0x01, 0x00, 0x90, 0x00, 0x00, 0x01, 0x00, 0x88, 0x00, 0x00, 0x00, 0x02, 0x00, 0x09, 0x72,
		0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xE0, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x04, 0x00, 0x00, 0x5E, 0x00, 0x08, 0x00,
		0x6E, 0x00, 0x02, 0x00, 0x72, 0x00, 0x00, 0x00, 0x72, 0x00, 0x07, 0x00, 0x80, 0x00, 0x00, 0x00,
		0x80, 0x00, 0x00, 0x00, 0x80, 0x00, 0x04, 0x00, 0x88, 0x00, 0x00, 0x00, 0x88, 0x00, 0x00, 0x00,
		0x00, 0x50, 0x8B, 0xE2, 0xB7, 0x8F, 0x88, 0x00, 0x00, 0x00, 0x88, 0x00, 0x00, 0x00, 0x88, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x73, 0x00, 0x6B, 0x00, 0x6F, 0x00, 0x73, 0x00, 0x74, 0x00,
		0x6F, 0x00, 0x76, 0x00, 0x31, 0x00, 0x73, 0x00, 0x61, 0x00, 0x4F, 0x00, 0x53, 0x00, 0x51, 0x00,
		0x4C, 0x00, 0x2D, 0x00, 0x33, 0x00, 0x32, 0x00, 0x4F, 0x00, 0x44, 0x00, 0x42, 0x00, 0x43, 0x00,
	}

	// SQLBatch is an example of SQLBatchClientRequest client request packet from the protocol spec:
	//
	// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/b05b006b-3cbf-404b-bcaf-7ec584b54706
	SQLBatch = []byte{
		0x01, 0x01, 0x00, 0x5c, 0x00, 0x00, 0x01, 0x00, 0x16, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00,
		0x73, 0x00, 0x65, 0x00, 0x6c, 0x00, 0x65, 0x00, 0x63, 0x00, 0x74, 0x00, 0x20, 0x00, 0x27, 0x00,
		0x66, 0x00, 0x6f, 0x00, 0x6f, 0x00, 0x27, 0x00, 0x20, 0x00, 0x61, 0x00, 0x73, 0x00, 0x20, 0x00,
		0x27, 0x00, 0x62, 0x00, 0x61, 0x00, 0x72, 0x00, 0x27, 0x00, 0x0a, 0x00, 0x20, 0x00, 0x20, 0x00,
		0x20, 0x00, 0x20, 0x00, 0x20, 0x00, 0x20, 0x00, 0x20, 0x00, 0x20, 0x00,
	}

	// RPCClientRequest is an example of RPCClientRequest client request packet from the protocol spec:
	//
	// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/1469b2fa-6cab-42e9-91f9-044d358b306b
	RPCClientRequest = []byte{
		0x03, 0x01, 0x00, 0x2F, 0x00, 0x00, 0x01, 0x00, 0x16, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
		0x66, 0x00, 0x6F, 0x00, 0x6F, 0x00, 0x33, 0x00, 0x00, 0x00, 0x00, 0x02, 0x26, 0x02, 0x00,
	}

	// RPCClientRequestParam is a custom RPC Request with SQL param.
	RPCClientRequestParam = []byte{
		0x03, 0x01, 0x00, 0x50, 0x00, 0x00, 0x01, 0x00, 0x16, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff,
		0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe7, 0x40, 0x1f, 0x09, 0x04, 0xd0, 0x00, 0x34, 0x20, 0x00,
		0x73, 0x00, 0x65, 0x00, 0x6c, 0x00, 0x65, 0x00, 0x63, 0x00, 0x74, 0x00, 0x20, 0x00, 0x40, 0x00,
		0x40, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00, 0x73, 0x00, 0x69, 0x00, 0x6f, 0x00, 0x6e, 0x00,
	}

	// MalformedPacketTest is an RPC Request malformed packet.
	MalformedPacketTest = []byte{
		0x03, 0x01, 0x00, 0x90, 0x00, 0x00, 0x02, 0x00, 0x72, 0x00, 0x61, 0x00, 0x6d, 0x00, 0x5f, 0x00,
		0x31, 0x00, 0x20, 0x00, 0x6e, 0x00, 0x76, 0x00, 0x61, 0x00, 0x72, 0x00, 0x63, 0x00, 0x68, 0x00,
		0x61, 0x00, 0x72, 0x00, 0x28, 0x00, 0x34, 0x00, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x29, 0x00,
		0x0b, 0x40, 0x00, 0x5f, 0x00, 0x6d, 0x00, 0x73, 0x00, 0x70, 0x00, 0x61, 0x00, 0x72, 0x00, 0x61,
		0x00, 0x6d, 0x00, 0x5f, 0x00, 0x30, 0x00, 0x00, 0xe7, 0x40, 0x1f, 0x09, 0x04, 0xd0, 0x00, 0x34,
		0x16, 0x00, 0x73, 0x00, 0x70, 0x00, 0x74, 0x00, 0x5f, 0x00, 0x6d, 0x00, 0x6f, 0x00, 0x6e, 0x00,
		0x69, 0x00, 0x74, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x0b, 0x40, 0x00, 0x5f, 0x00, 0x6d, 0x00, 0x73,
		0x00, 0x70, 0x00, 0x61, 0x00, 0x72, 0x00, 0x61, 0x00, 0x6d, 0x00, 0x5f, 0x00, 0x31, 0x00, 0x00,
		0xe7, 0x40, 0x1f, 0x09, 0x04, 0xd0, 0x00, 0x34, 0x06, 0x00, 0x64, 0x00, 0x62, 0x00, 0x6f, 0x00,
	}
)

// RPCClientVariableLength returns a RPCCLientRequest packet containing a
// partially Length-prefixed Bytes request, as described here: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/3f983fde-0509-485a-8c40-a9fa6679a828
func RPCClientPartiallyLength(length uint64, chunks uint64) []byte {
	packet := []byte{
		0x03, 0x01, 0x00, 0x00, // Length placeholder
		0x00, 0x00, 0x01, 0x00, 0x16, 0x00, 0x00, 0x00,
		0x12, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x04, 0x00, 0x66, 0x00, 0x6F, 0x00,
		0x6F, 0x00, 0x33, 0x00, 0x00, 0x00, 0x00, 0x02,
		0xef,       // NVARCHARTYPE
		0xff, 0xff, // NULL length
		0x00, 0x00, 0x00, 0x00, 0x00, // NVARCHARTYPE flags
	}

	packet = binary.LittleEndian.AppendUint64(packet, length)

	if length > 0 && chunks > 1 {
		chunkSize := length / chunks
		rem := length
		for rem > 0 {
			packet = binary.LittleEndian.AppendUint32(packet, uint32(chunkSize))
			data := make([]byte, chunkSize)
			packet = append(packet, data...)
			rem -= chunkSize
		}
	}

	// PLP_TERMINATOR
	packet = append(packet, []byte{0x00, 0x00, 0x00, 0x00}...)

	packet[3] = byte(len(packet))
	return packet
}
