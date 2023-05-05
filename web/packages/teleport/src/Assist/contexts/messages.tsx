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

import cfg from 'teleport/config';

import { ApiError } from 'teleport/services/api/parseError';

import {
  Author,
  ExecuteRemoteCommandContent,
  ExecuteRemoteCommandPayload,
  Message,
  TextMessageContent,
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

type MessagesAction = (messages: Message[]) => void;

interface PartialMessagePayload {
  content: string;
  idx: number;
}

const convertToQuery = (cmd: ExecuteRemoteCommandPayload): string => {
  let query = '';

  if (cmd.nodes) {
    query += cmd.nodes.map(node => `name == "${node}"`).join(' || ');
  }

  if (cmd.labels) {
    query += cmd.labels
      .map(label => `labels["${label.key}"] == "${label.value}"`)
      .join(' || ');
  }

  return query;
};

export const remoteCommandToMessage = async (
  execCmd: ExecuteRemoteCommandContent,
  clusterId: string
): Promise<ExecuteRemoteCommandContent> => {
  try {
    const ns = new NodeService();
    // fetch available users
    const nodes = await ns.fetchNodes(clusterId, {
      query: execCmd.query,
      limit: 100, // TODO: What if there is more nodes?
    });

    if (nodes.agents.length == 0) {
      return {
        ...execCmd,
        selectedLogin: '',
        availableLogins: [],
        errorMsg: 'no nodes found',
      };
    }

    const availableLogins = findIntersection(
      nodes.agents.map(e => e.sshLogins)
    );

    let errorMsg = '';
    if (availableLogins.length == 0) {
      errorMsg = 'no users found';
    }

    return {
      ...execCmd,
      selectedLogin: availableLogins ? availableLogins[0] : '',
      availableLogins: availableLogins,
      errorMsg: errorMsg,
    };
  } catch (e) {
    return {
      ...execCmd,
      errorMsg: (e as ApiError).message,
    };
  }
};

async function convertServerMessage(
  message: ServerMessage,
  clusterId: string
): Promise<MessagesAction> {
  console.log(message);
  if (message.type === 'CHAT_MESSAGE_ASSISTANT') {
    const newMessage: Message = {
      author: Author.Teleport,
      content: {
        type: Type.Message,
        value: message.payload,
      },
    };

    return (messages: Message[]) => messages.push(newMessage);
  }

  if (message.type === 'CHAT_PARTIAL_MESSAGE_ASSISTANT') {
    return (messages: Message[]) => {
      const partial: PartialMessagePayload = JSON.parse(message.payload);
      const existing = messages.findIndex(m => m.idx === partial.idx);
      if (existing !== -1) {
        const copy = JSON.parse(JSON.stringify(messages[existing]));
        (copy.content as TextMessageContent).value += partial.content;
        messages[existing] = copy;
      } else {
        const newMessage: Message = {
          author: Author.Teleport,
          content: {
            type: Type.Message,
            value: partial.content,
          },
          idx: partial.idx,
        };

        messages.push(newMessage);
      }
    };
  }

  if (message.type === 'CHAT_PARTIAL_MESSAGE_ASSISTANT_FINALIZE') {
    return (/*_messages: Message[]*/) => {};
  }

  if (message.type == 'COMMAND_RESULT') {
    const payload = JSON.parse(message.payload) as {
      session_id: string;
      execution_id: string;
      node_id: string;
    };

    const sessionUrl = cfg.getSshPlaybackPrefixUrl({
      clusterId: clusterId,
      sid: payload.session_id,
    });

    // The offset here is set base on A/B test that was run between me, myself and I.
    const resp = await api
      .fetch(sessionUrl + '/stream?offset=0&bytes=4096', {
        Accept: 'text/plain',
        'Content-Type': 'text/plain; charset=utf-8',
      })
      .then(response => response.text());

    const newMessage: Message = {
      author: Author.Teleport,
      content: {
        type: Type.ExecuteCommandOutput,
        nodeId: payload.node_id,
        executionId: payload.execution_id,
        payload: resp,
      },
    };

    return (messages: Message[]) => messages.push(newMessage);
  }

  if (message.type === 'CHAT_MESSAGE_USER') {
    const newMessage: Message = {
      author: Author.User,
      content: {
        type: Type.Message,
        value: message.payload,
      },
    };

    return (messages: Message[]) => messages.push(newMessage);
  }

  if (message.type === 'COMMAND') {
    const execCmd: ExecuteRemoteCommandPayload = JSON.parse(message.payload);
    const searchQuery = convertToQuery(execCmd);
    const executionContent = await remoteCommandToMessage(
      {
        ...execCmd,
        type: Type.ExecuteRemoteCommand,
        query: searchQuery,
        selectedLogin: '',
        availableLogins: [],
        errorMsg: '',
      },
      clusterId
    );
    const newMessage = {
      author: Author.Teleport,
      isNew: true,
      content: executionContent,
    };

    return (messages: Message[]) => messages.push(newMessage);
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

  const socketUrl = `wss://${getHostName()}/v1/webapi/sites/${clusterId}/assistant?access_token=${getAccessToken()}&conversation_id=${
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

    let messages: Message[] = [];
    for (const m of res.Messages) {
      const action = await convertServerMessage(m, clusterId);
      action(messages);
    }

    setMessages(messages);
  }, [props.conversationId]);

  useEffect(() => {
    setLoading(true);

    load().then(() => setLoading(false));
  }, [props.conversationId]);

  useEffect(() => {
    if (lastMessage !== null) {
      const value = JSON.parse(lastMessage.data) as ServerMessage;
      convertServerMessage(value, clusterId).then(res => {
        setMessages(prev => {
          const curr = [...prev];
          res(curr);
          return curr;
        });
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
