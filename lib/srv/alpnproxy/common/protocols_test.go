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

package common

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWithPingProtocols(t *testing.T) {
	require.Equal(t,
		[]Protocol{
			"teleport-tcp-ping",
			"teleport-redis-ping",
			"teleport-auth@",
			"teleport-tcp",
			"teleport-redis",
			"h2",
		},
		WithPingProtocols([]Protocol{
			ProtocolAuth,
			ProtocolTCP,
			ProtocolRedisDB,
			ProtocolAuth,
			ProtocolHTTP2,
		}),
	)
}

func TestIsDBTLSProtocol(t *testing.T) {
	require.True(t, IsDBTLSProtocol("teleport-redis"))
	require.True(t, IsDBTLSProtocol("teleport-redis-ping"))
	require.False(t, IsDBTLSProtocol("teleport-tcp"))
	require.False(t, IsDBTLSProtocol(""))
}

func BenchmarkNextProtosWithPing(b *testing.B) {
	b.Run("one with ping support", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			NextProtosWithPing(ProtocolReverseTunnel)
		}
	})
	b.Run("one without ping support", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			NextProtosWithPing(ProtocolHTTP)
		}
	})
	b.Run("five", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			NextProtosWithPing(ProtocolAuth, ProtocolTCP, ProtocolRedisDB, ProtocolAuth, ProtocolHTTP2)
		}
	})
}
