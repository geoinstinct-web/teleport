/*
 * Copyright 2023 Gravitational, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package output

import "strings"

// Message represents a new message within a live conversation.
type Message struct {
	Content string
}

// StreamingMessage represents a new message that is being streamed from the LLM.
type StreamingMessage struct {
	Parts <-chan string
}

// String implements the Stringer interface. It waits until the message stream
// is over and returns the full message.
func (msg *StreamingMessage) String() string {
	sb := strings.Builder{}
	for part := range msg.Parts {
		sb.WriteString(part)
	}
	return sb.String()
}

// Label represents a label returned by OpenAI's completion API.
type Label struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// CompletionCommand represents a command suggestion returned by OpenAI's completion API.
type CompletionCommand struct {
	Command string   `json:"command,omitempty"`
	Nodes   []string `json:"nodes,omitempty"`
	Labels  []Label  `json:"labels,omitempty"`
}

// GeneratedCommand represents a Bash command generated by LLM.
type GeneratedCommand struct {
	Command string `json:"command"`
}

// AccessRequest represents an access request suggestion returned by OpenAI's completion API.
type AccessRequest struct {
	Roles              []string   `json:"roles"`
	Resources          []Resource `json:"resources"`
	Reason             string     `json:"reason"`
	SuggestedReviewers []string   `json:"suggested_reviewers"`
}

// Resource represents a resource suggestion returned by OpenAI's completion API.
type Resource struct {
	// The resource type.
	Type string `json:"type"`

	// The resource name.
	Name string `json:"id"`

	// Set if a display-friendly alternative name is available.
	FriendlyName string `json:"friendlyName,omitempty"`
}
