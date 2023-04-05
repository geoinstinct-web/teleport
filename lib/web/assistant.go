/*

 Copyright 2023 Gravitational, Inc.

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

package web

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
	"github.com/gravitational/trace"
	"github.com/julienschmidt/httprouter"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/llmchain"
)

const (
	kindChatUserMessage      = "CHAT_USER_MESSAGE"
	kindChatAssistantMessage = "CHAT_ASSISTANT_MESSAGE"
)

func (h *Handler) assistant(w http.ResponseWriter, r *http.Request, _ httprouter.Params, sctx *SessionContext) (any, error) {
	//authClient, err := sctx.GetClient()
	//if err != nil {
	//	return nil, trace.Wrap(err)
	//}

	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin:     func(r *http.Request) bool { return true },
	}

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		errMsg := "Error upgrading to websocket"
		h.log.WithError(err).Error(errMsg)
		http.Error(w, errMsg, http.StatusInternalServerError)
		return nil, nil
	}

	keepAliveInterval := time.Minute // TODO(jakule)
	err = ws.SetReadDeadline(deadlineForInterval(keepAliveInterval))
	if err != nil {
		h.log.WithError(err).Error("Error setting websocket readline")
		return nil, nil
	}
	defer ws.Close()

	prefs, err := h.cfg.ProxyClient.GetAuthPreference(r.Context())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	client := llmchain.NewClient(prefs.(*types.AuthPreferenceV2).Spec.Assist.ApiKey)
	chain := client.NewChain()

	//q := r.URL.Query()
	//conversationID := q.Get("conversation_id")
	// TODO(joel): impl persistance
	//conversationID := uuid.New().String()

	for {
		_, payload, err := ws.ReadMessage()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, trace.Wrap(err)
		}

		var wsIncoming wsMessage
		if err := json.Unmarshal(payload, &wsIncoming); err != nil {
			return nil, trace.Wrap(err)
		}

		chain.Insert(wsIncoming.Chat.Role, wsIncoming.Chat.Content)
		stream, err := chain.Complete(r.Context(), 500)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		for partial := range stream {
			out := wsMessage{
				Chat: &chatMessage{
					Role:    partial.Role,
					Content: partial.Content,
				},
				Idx: partial.Idx,
			}

			payload, err := json.Marshal(out)
			if err != nil {
				return nil, trace.Wrap(err)
			}

			if err := ws.WriteJSON(payload); err != nil {
				return nil, trace.Wrap(err)
			}
		}
	}

	return nil, nil
}

type wsMessage struct {
	Chat *chatMessage `json:"chat,omitempty"`
	Idx  int          `json:"idx,omitempty"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}
