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
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/gravitational/trace"
	"github.com/gravitational/trace/trail"
	"github.com/julienschmidt/httprouter"
	"github.com/sashabaranov/go-openai"

	"github.com/gravitational/teleport/api/client/proto"
	pluginsv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/plugins/v1"
	"github.com/gravitational/teleport/lib/ai"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/httplib"
	"github.com/gravitational/teleport/lib/reversetunnel"
)

const (
	messageKindCommand                  = "COMMAND"
	messageKindCommandResult            = "COMMAND_RESULT"
	messageKindUserMessage              = "CHAT_MESSAGE_USER"
	messageKindAssistantMessage         = "CHAT_MESSAGE_ASSISTANT"
	messageKindAssistantPartialMessage  = "CHAT_PARTIAL_MESSAGE_ASSISTANT"
	messageKindAssistantPartialFinalize = "CHAT_PARTIAL_MESSAGE_ASSISTANT_FINALIZE"
	messageKindSystemMessage            = "CHAT_MESSAGE_SYSTEM"
)

func (h *Handler) createAssistantConversation(w http.ResponseWriter, r *http.Request, _ httprouter.Params, sctx *SessionContext) (any, error) {
	authClient, err := sctx.GetClient()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	req := &proto.CreateAssistantConversationRequest{}

	resp, err := authClient.CreateAssistantConversation(r.Context(), req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (h *Handler) getAssistantConversationByID(_ http.ResponseWriter, r *http.Request, p httprouter.Params, sctx *SessionContext) (any, error) {
	authClient, err := sctx.GetClient()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	conversationID := p.ByName("conversation_id")

	resp, err := authClient.GetAssistantMessages(r.Context(), conversationID)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	type response struct {
		Messages []*proto.AssistantMessage
	}

	return &response{
		Messages: resp.Messages,
	}, err
}

func (h *Handler) getAssistantConversations(w http.ResponseWriter, r *http.Request, _ httprouter.Params, sctx *SessionContext) (any, error) {
	authClient, err := sctx.GetClient()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	resp, err := authClient.GetAssistantConversations(r.Context(), &proto.GetAssistantConversationsRequest{})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return resp, err
}

func (h *Handler) setAssistantTitle(_ http.ResponseWriter, r *http.Request, p httprouter.Params, sctx *SessionContext) (any, error) {
	req := struct {
		Message string `json:"message"`
	}{}

	if err := httplib.ReadJSON(r, &req); err != nil {
		return nil, trace.Wrap(err)
	}

	authClient, err := sctx.GetClient()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	conversationID := p.ByName("conversation_id")

	conversationInfo := &proto.ConversationInfo{
		Id:    conversationID,
		Title: req.Message,
	}

	if err := authClient.SetAssistantConversationTitle(r.Context(), conversationInfo); err != nil {
		return nil, trace.Wrap(err)
	}

	return OK(), nil
}

func (h *Handler) generateAssistantTitle(_ http.ResponseWriter, r *http.Request, p httprouter.Params, sctx *SessionContext) (any, error) {
	req := struct {
		Message string `json:"message"`
	}{}

	if err := httplib.ReadJSON(r, &req); err != nil {
		return nil, trace.Wrap(err)
	}

	conversationID := p.ByName("conversation_id")

	chat, err := getAssistantClient(r.Context(), h.cfg.ProxyClient, h.cfg.ProxySettings, sctx.cfg.User)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	titleSummary, err := chat.Summary(r.Context(), req.Message)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	conversationInfo := &proto.ConversationInfo{
		Id:    conversationID,
		Title: titleSummary,
	}

	return conversationInfo, nil
}

func (h *Handler) assistant(w http.ResponseWriter, r *http.Request, _ httprouter.Params, sctx *SessionContext, site reversetunnel.RemoteSite) (any, error) {
	// moved into a separate function for error management/debug purposes
	err := runAssistant(h, w, r, sctx, site)
	if err != nil {
		h.log.Warn(trace.DebugReport(err))
		return nil, trace.Wrap(err)
	}

	return nil, nil
}

type commandPayload struct {
	Command string     `json:"command,omitempty"`
	Nodes   []string   `json:"nodes,omitempty"`
	Labels  []ai.Label `json:"labels,omitempty"`
}

type partialMessagePayload struct {
	Content string `json:"content,omitempty"`
	Idx     int    `json:"idx,omitempty"`
}

type partialFinalizePayload struct {
	Idx int `json:"idx,omitempty"`
}

// runAssistant upgrades the HTTP connection to a websocket and starts a chat loop.
func runAssistant(h *Handler, w http.ResponseWriter, r *http.Request, sctx *SessionContext, site reversetunnel.RemoteSite,
) error {
	authClient, err := sctx.GetClient()
	if err != nil {
		return trace.Wrap(err)
	}

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
		return nil
	}

	// Use the default interval as this handler doesn't have access to network config.
	// Note: This time should be longer than OpenAI response time.
	keepAliveInterval := 15 * time.Second //defaults.KeepAliveInterval()
	err = ws.SetReadDeadline(deadlineForInterval(keepAliveInterval))
	if err != nil {
		h.log.WithError(err).Error("Error setting websocket readline")
		return nil
	}
	defer ws.Close()

	// Update the read deadline upon receiving a pong message.
	ws.SetPongHandler(func(_ string) error {
		h.log.Warnf("received PONG AAAAA")
		ws.SetReadDeadline(deadlineForInterval(keepAliveInterval))
		return nil
	})

	ws.SetCloseHandler(func(code int, text string) error {
		h.log.Warnf("closing assistant websocket: %v %v", code, text)
		return nil
	})

	ctx := context.Background() // r.Context()
	go startPingLoop(ctx, ws, keepAliveInterval/2, h.log, nil)

	chat, err := getAssistantClient(ctx, h.cfg.ProxyClient,
		h.cfg.ProxySettings, sctx.cfg.User)
	if err != nil {
		return trace.Wrap(err)
	}

	q := r.URL.Query()
	conversationID := q.Get("conversation_id")
	if conversationID == "" {
		return trace.BadParameter("conversation ID is required")
	}

	// existing conversation, retrieve old messages
	messages, err := authClient.GetAssistantMessages(ctx, conversationID)
	if err != nil {
		return trace.Wrap(err)
	}

	// restore conversation context.
	for _, msg := range messages.GetMessages() {
		role := kindToRole(msg.Type)
		if role != "" {
			chat.Insert(role, msg.Payload)
		}
	}

	if len(messages.GetMessages()) == 0 {
		// new conversation, generate hello message
		if err := processComplete(ctx, h, chat, conversationID, ws, authClient); err != nil {
			return trace.Wrap(err)
		}
	}

	for {
		_, payload, err := ws.ReadMessage()
		if err != nil {
			if err == io.EOF || websocket.IsCloseError(err, websocket.CloseAbnormalClosure, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				break
			}
			return trace.Wrap(err)
		}

		var wsIncoming proto.AssistantMessage
		if err := json.Unmarshal(payload, &wsIncoming); err != nil {
			return trace.Wrap(err)
		}

		// write user message to both in-memory chain and persistent storage
		chat.Insert(openai.ChatMessageRoleUser, wsIncoming.Payload)

		//TODO(jakule): Close authClient before reopening
		authClient, err = newRemoteClient(ctx, sctx, site)
		if err != nil {
			return trace.Wrap(err)
		}

		if _, err := authClient.InsertAssistantMessage(ctx, &proto.AssistantMessage{
			ConversationId: conversationID,
			Type:           messageKindUserMessage,
			Payload:        wsIncoming.Payload,
			CreatedTime:    h.clock.Now().UTC(),
		}); err != nil {
			return trace.Wrap(err)
		}

		if err := processComplete(ctx, h, chat, conversationID, ws, authClient); err != nil {
			return trace.Wrap(err)
		}
	}

	h.log.Debugf("end assistant conversation loop")

	return nil
}

func getOpenAITokenFromDefaultPlugin(ctx context.Context, proxyClient auth.ClientI) (string, error) {
	// Try retrieving credentials from the plugin resource first
	openaiPlugin, err := proxyClient.PluginsClient().GetPlugin(ctx, &pluginsv1.GetPluginRequest{
		Name:        "openai-default",
		WithSecrets: true,
	})
	if err != nil {
		return "", trail.FromGRPC(err)
	}

	creds := openaiPlugin.Credentials.GetBearerToken()
	if creds == nil {
		return "", trace.BadParameter("malformed credentials")
	}
	if creds.TokenFile != "" {
		tokenBytes, err := os.ReadFile(creds.TokenFile)
		if err != nil {
			return "", trace.Wrap(err)
		}
		return strings.TrimSpace(string(tokenBytes)), nil
	}

	return creds.Token, nil
}

func getAssistantClient(ctx context.Context, proxyClient auth.ClientI,
	proxySettings proxySettingsGetter, username string,
) (*ai.Chat, error) {
	token, err := getOpenAITokenFromDefaultPlugin(ctx, proxyClient)
	if err == nil {
		client := ai.NewClient(token)
		chat := client.NewChat(username)
		return chat, nil
	} else if !trace.IsNotFound(err) && !trace.IsNotImplemented(err) {
		// We ignore 2 types of errors here.
		// Unimplemented may be raised by the OSS server,
		// as PluginsService does not exist there yet.
		// NotFound means plugin does not exist,
		// in which case we should fall back on the static token configured in YAML.
		log.WithError(err).Error("Unexpected error fetching default OpenAI plugin")
	}

	keyGetter, found := proxySettings.(interface{ GetOpenAIAPIKey() string })
	if !found {
		return nil, trace.Errorf("GetOpenAIAPIKey is not implemented on %T", proxySettings)
	}

	apiKey := keyGetter.GetOpenAIAPIKey()
	if apiKey == "" {
		return nil, trace.Errorf("OpenAI API key is not set")
	}

	client := ai.NewClient(apiKey)
	chat := client.NewChat(username)

	return chat, nil
}

func processComplete(ctx context.Context, h *Handler, chat *ai.Chat, conversationID string,
	ws *websocket.Conn, authClient auth.ClientI,
) error {
	// query the assistant and fetch an answer
	message, err := chat.Complete(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	switch message := message.(type) {
	case *ai.StreamingMessage:
		// collection of the entire message, used for writing to conversation log
		content := ""

		// stream all chunks to client
	outer:
		for {
			select {
			case chunk, ok := <-message.Chunks:
				if !ok {
					break outer
				}

				if len(chunk) == 0 {
					continue outer
				}

				content += chunk
				payload := partialMessagePayload{
					Content: chunk,
					Idx:     message.Idx,
				}

				payloadJSON, err := json.Marshal(payload)
				if err != nil {
					return trace.Wrap(err)
				}

				protoMsg := &proto.AssistantMessage{
					ConversationId: conversationID,
					Type:           messageKindAssistantPartialMessage,
					Payload:        string(payloadJSON),
					CreatedTime:    h.clock.Now().UTC(),
				}

				if err := ws.WriteJSON(protoMsg); err != nil {
					return trace.Wrap(err)
				}
			case err = <-message.Error:
				return trace.Wrap(err)
			}
		}

		// tell the client that the message is complete
		finalizePayload := partialFinalizePayload{
			Idx: message.Idx,
		}

		finalizePayloadJSON, err := json.Marshal(finalizePayload)
		if err != nil {
			return trace.Wrap(err)
		}

		finalizeProtoMsg := &proto.AssistantMessage{
			ConversationId: conversationID,
			Type:           messageKindAssistantPartialFinalize,
			Payload:        string(finalizePayloadJSON),
			CreatedTime:    h.clock.Now().UTC(),
		}

		if err := ws.WriteJSON(finalizeProtoMsg); err != nil {
			return trace.Wrap(err)
		}

		// write the entire message to both in-memory chain and persistent storage
		chat.Insert(message.Role, content)
		protoMsg := &proto.AssistantMessage{
			ConversationId: conversationID,
			Type:           messageKindAssistantMessage,
			Payload:        content,
			CreatedTime:    h.clock.Now().UTC(),
		}

		if _, err := authClient.InsertAssistantMessage(ctx, protoMsg); err != nil {
			return trace.Wrap(err)
		}
	case *ai.Message:
		// write assistant message to both in-memory chain and persistent storage
		chat.Insert(message.Role, message.Content)
		protoMsg := &proto.AssistantMessage{
			ConversationId: conversationID,
			Type:           messageKindAssistantMessage,
			Payload:        message.Content,
			CreatedTime:    h.clock.Now().UTC(),
		}
		if _, err := authClient.InsertAssistantMessage(ctx, protoMsg); err != nil {
			return trace.Wrap(err)
		}

		if err := ws.WriteJSON(protoMsg); err != nil {
			return trace.Wrap(err)
		}
	case *ai.CompletionCommand:
		payload := commandPayload{
			Command: message.Command,
			Nodes:   message.Nodes,
			Labels:  message.Labels,
		}

		payloadJson, err := json.Marshal(payload)
		if err != nil {
			return trace.Wrap(err)
		}

		msg := &proto.AssistantMessage{
			Type:           messageKindCommand,
			ConversationId: conversationID,
			Payload:        string(payloadJson),
			CreatedTime:    h.clock.Now().UTC(),
		}

		if _, err := authClient.InsertAssistantMessage(ctx, msg); err != nil {
			return trace.Wrap(err)
		}

		if err := ws.WriteJSON(msg); err != nil {
			return trace.Wrap(err)
		}
	default:
		return trace.Errorf("unknown message type")
	}

	return nil
}

func kindToRole(kind string) string {
	switch kind {
	case messageKindUserMessage:
		return openai.ChatMessageRoleUser
	case messageKindAssistantMessage:
		return openai.ChatMessageRoleAssistant
	case messageKindSystemMessage:
		return openai.ChatMessageRoleSystem
	default:
		return ""
	}
}
