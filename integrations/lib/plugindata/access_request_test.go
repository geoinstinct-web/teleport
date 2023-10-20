// Copyright 2023 Gravitational, Inc
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

package plugindata

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var sampleAccessRequestData = AccessRequestData{
	User:             "user-foo",
	Roles:            []string{"role-foo", "role-bar"},
	Resources:        []string{"cluster/node/foo", "cluster/node/bar"},
	RequestReason:    "foo reason",
	ReviewsCount:     3,
	ResolutionTag:    ResolvedApproved,
	ResolutionReason: "foo ok",
}

func TestEncodeAccessRequestData(t *testing.T) {
	dataMap, err := EncodeAccessRequestData(sampleAccessRequestData)
	assert.Nil(t, err)
	assert.Len(t, dataMap, 7)
	assert.Equal(t, "user-foo", dataMap["user"])
	assert.Equal(t, "role-foo,role-bar", dataMap["roles"])
	assert.Equal(t, `["cluster/node/foo","cluster/node/bar"]`, dataMap["resources"])
	assert.Equal(t, "foo reason", dataMap["request_reason"])
	assert.Equal(t, "3", dataMap["reviews_count"])
	assert.Equal(t, "APPROVED", dataMap["resolution"])
	assert.Equal(t, "foo ok", dataMap["resolve_reason"])
}

func TestDecodeAccessRequestData(t *testing.T) {
	pluginData, err := DecodeAccessRequestData(map[string]string{
		"user":           "user-foo",
		"roles":          "role-foo,role-bar",
		"resources":      `["cluster/node/foo", "cluster/node/bar"]`,
		"request_reason": "foo reason",
		"reviews_count":  "3",
		"resolution":     "APPROVED",
		"resolve_reason": "foo ok",
	})
	assert.Nil(t, err)
	assert.Equal(t, sampleAccessRequestData, pluginData)
}

func TestEncodeEmptyAccessRequestData(t *testing.T) {
	dataMap, err := EncodeAccessRequestData(AccessRequestData{})
	assert.Nil(t, err)
	assert.Len(t, dataMap, 7)
	for key, value := range dataMap {
		assert.Emptyf(t, value, "value at key %q must be empty", key)
	}
}

func TestDecodeEmptyAccessRequestData(t *testing.T) {
	decoded, err := DecodeAccessRequestData(nil)
	assert.Nil(t, err)
	assert.Empty(t, decoded)
	decoded, err = DecodeAccessRequestData(make(map[string]string))
	assert.Nil(t, err)
	assert.Empty(t, decoded)
}
