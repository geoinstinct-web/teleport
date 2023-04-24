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

import React, {
  createContext,
  PropsWithChildren,
  useCallback,
  useContext,
  useEffect,
  useState,
} from 'react';
import useWebSocket from 'react-use-websocket';

import { useParams } from 'react-router';

import api, { getAccessToken, getHostName } from 'teleport/services/api';

import NodeService from 'teleport/services/nodes';
import useStickyClusterId from 'teleport/useStickyClusterId';

import {
  Author,
  ExecuteRemoteCommandPayload,
  Message,
  Type,
} from '../services/messages';

interface MessageContextValue {
  send: (message: string) => Promise<void>;
  messages: Message[];
  loading: boolean;
  responding: boolean;
}

interface ServerMessage {
  conversation_id: string;
  type: string;
  payload: string;
  created_time: string;
}

interface ConversationHistoryResponse {
  Messages: ServerMessage[];
}

const MessagesContext = createContext<MessageContextValue>({
  messages: [],
  send: () => Promise.resolve(void 0),
  loading: true,
  responding: false,
});

interface MessagesContextProviderProps {
  conversationId: string;
}

async function convertServerMessage(
  message: ServerMessage,
  clusterId: string
): Promise<Message> {
  if (message.type === 'CHAT_MESSAGE_ASSISTANT') {
    return {
      author: Author.Teleport,
      content: {
        type: Type.Message,
        value: message.payload,
      },
    };
  }

  if (message.type === 'CHAT_MESSAGE_USER') {
    return {
      author: Author.User,
      content: {
        type: Type.Message,
        value: message.payload,
      },
    };
  }

  const convertToQuery = (cmd: ExecuteRemoteCommandPayload): string => {
    let query = '';

    if (cmd.nodes) {
      for (const node of cmd.nodes) {
        if (query) {
          query += ' || ';
        }
        query += `name == "${node}"`;
      }
    }

    if (cmd.labels) {
      for (const label of cmd.labels) {
        if (query) {
          query += ' || ';
        }
        query += `labels["${label.key}"] == "${label.value}"`;
      }
    }

    return query;
  };

  if (message.type === 'COMMAND') {
    const execCmd: ExecuteRemoteCommandPayload = JSON.parse(message.payload);
    const searchQuery = convertToQuery(execCmd);

    // fetch available users
    const ns = new NodeService();
    // TODO: fetch users after the query is edited in the UI.
    const nodes = await ns.fetchNodes(clusterId, {
      query: searchQuery,
      limit: 100, // TODO: What is there is mode nodes?
    });
    const availableLogins = findIntersection(
      nodes.agents.map(e => e.sshLogins)
    );

    return {
      author: Author.Teleport,
      isNew: true,
      content: {
        query: searchQuery,
        command: execCmd.command,
        type: Type.ExecuteRemoteCommand,
        selectedLogin: availableLogins ? availableLogins[0] : '',
        availableLogins: availableLogins,
      },
    };
  }
}

function findIntersection<T>(elems: T[][]): T[] {
  if (elems.length == 0) {
    return [];
  }

  if (elems.length == 1) {
    return elems[0];
  }

  const intersectSets = (a: Set<T>, b: Set<T>) => {
    const c = new Set<T>();
    a.forEach(v => b.has(v) && c.add(v));
    return c;
  };

  return [...elems.map(e => new Set(e)).reduce(intersectSets)];
}

export function MessagesContextProvider(
  props: PropsWithChildren<MessagesContextProviderProps>
) {
  const { conversationId } = useParams<{ conversationId: string }>();
  const { clusterId } = useStickyClusterId();

  const [loading, setLoading] = useState(true);
  const [responding, setResponding] = useState(false);
  const [messages, setMessages] = useState<Message[]>([]);

  const socketUrl = `wss://${getHostName()}/v1/webapi/assistant?access_token=${getAccessToken()}&conversation_id=${
    props.conversationId
  }`;

  const { sendMessage, lastMessage } = useWebSocket(socketUrl);

  const load = useCallback(async () => {
    setMessages([]);

    const res = (await api.get(
      `/v1/webapi/assistant/conversations/${props.conversationId}`
    )) as ConversationHistoryResponse;

    if (!res.Messages) {
      return;
    }

    setMessages(
      await Promise.all(
        res.Messages.map(async m => {
          return await convertServerMessage(m, clusterId);
        })
      )
    );
  }, [props.conversationId]);

  useEffect(() => {
    setLoading(true);

    load().then(() => setLoading(false));
  }, [props.conversationId]);

  useEffect(() => {
    if (lastMessage !== null) {
      const value = JSON.parse(lastMessage.data) as ServerMessage;

      convertServerMessage(value, clusterId).then(res => {
        setMessages(prev => prev.concat(res));
        setResponding(false);
      });
    }
  }, [lastMessage, setMessages, conversationId]);

  const send = useCallback(
    async (message: string) => {
      setResponding(true);

      const newMessages = [
        ...messages,
        {
          author: Author.User,
          isNew: true,
          content: { type: Type.Message, value: message } as const,
        },
      ];

      setMessages(newMessages);

      const data = JSON.stringify({ payload: message });
      console.log('data', data);
      sendMessage(data);
    },
    [messages]
  );

  return (
    <MessagesContext.Provider value={{ messages, send, loading, responding }}>
      {props.children}
    </MessagesContext.Provider>
  );
}

export function useMessages() {
  return useContext(MessagesContext);
}
