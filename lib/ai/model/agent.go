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

package model

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/gravitational/trace"
	"github.com/sashabaranov/go-openai"
	log "github.com/sirupsen/logrus"
)

const (
	actionFinalAnswer = "Final Answer"
	actionException   = "_Exception"
	maxIterations     = 15
	maxElapsedTime    = 5 * time.Minute
)

var AssistAgent = &Agent{
	tools: []Tool{
		&commandExecutionTool{},
	},
}

type Agent struct {
	tools []Tool
}

type AgentAction struct {
	action string
	input  string
	log    string
}

type AgentFinish struct {
	// output must be Message or CompletionCommand
	output any
}

type executionState struct {
	llm               *openai.Client
	chatHistory       []openai.ChatCompletionMessage
	humanMessage      openai.ChatCompletionMessage
	intermediateSteps []AgentAction
	observations      []string
	tokensUsed        *TokensUsed
}

func (a *Agent) Think(ctx context.Context, llm *openai.Client, chatHistory []openai.ChatCompletionMessage, humanMessage openai.ChatCompletionMessage) (any, error) {
	log.Debug("entering agent think loop")
	iterations := 0
	start := time.Now()
	shouldExit := func() bool { return iterations > maxIterations || time.Since(start) > maxElapsedTime }
	tokensUsed := newTokensUsed_Cl100kBase()
	state := &executionState{
		llm:               llm,
		chatHistory:       chatHistory,
		humanMessage:      humanMessage,
		intermediateSteps: make([]AgentAction, 0),
		observations:      make([]string, 0),
		tokensUsed:        tokensUsed,
	}

	for {
		log.Debugf("performing iteration %v of loop, %v seconds elapsed", iterations, int(time.Since(start).Seconds()))

		// This is intentionally not context-based, as we want to finish the current step before exiting
		// and the concern is not that we're stuck but that we're taking too long over multiple iterations.
		if shouldExit() {
			return nil, trace.Errorf("timeout: agent took too long to finish")
		}

		output, err := a.takeNextStep(ctx, state)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		if output.finish != nil {
			log.Debugf("agent finished with output: %v", output.finish.output)
			switch v := output.finish.output.(type) {
			case *Message:
				v.TokensUsed = tokensUsed
				return v, nil
			case *CompletionCommand:
				v.TokensUsed = tokensUsed
				return v, nil
			default:
				return nil, trace.Errorf("invalid output type %T", v)
			}
		}

		if output.action != nil {
			state.intermediateSteps = append(state.intermediateSteps, *output.action)
			state.observations = append(state.observations, output.observation)
		}

		iterations++
	}
}

type stepOutput struct {
	finish      *AgentFinish
	action      *AgentAction
	observation string
	tokensUsed  int
}

func (a *Agent) takeNextStep(ctx context.Context, state *executionState) (stepOutput, error) {
	log.Debug("agent entering takeNextStep")
	defer log.Debug("agent exiting takeNextStep")

	action, finish, err := a.plan(ctx, state)
	if err, ok := trace.Unwrap(err).(*invalidOutputError); ok {
		log.Debugf("agent encountered an invalid output error: %v, attempting to recover", err)
		action := &AgentAction{
			action: actionException,
			input:  observationPrefix + "Invalid or incomplete response",
			log:    thoughtPrefix + err.Error(),
		}

		// The exception tool is currently a bit special, the observation is always equal to the input.
		// We can expand on this in the future to make it handle errors better.
		log.Debugf("agent decided on action %v and received observation %v", action.action, action.input)
		return stepOutput{action: action, observation: action.input}, nil
	}
	if err != nil {
		log.Debugf("agent encountered an error: %v", err)
		return stepOutput{}, trace.Wrap(err)
	}

	// If finish is set, the agent is done and did not call upon any tool.
	if finish != nil {
		log.Debug("agent picked finish, returning")
		return stepOutput{finish: finish}, nil
	}

	var tool Tool
	for _, candidate := range a.tools {
		if candidate.Name() == action.action {
			tool = candidate
			break
		}
	}

	if tool == nil {
		log.Debugf("agent picked an unknown tool %v", action.action)
		action := &AgentAction{
			action: actionException,
			input:  observationPrefix + "Unknown tool",
			log:    thoughtPrefix + "No tool with name " + action.action + " exists.",
		}

		return stepOutput{action: action, observation: action.input}, nil
	}

	if tool, ok := tool.(*commandExecutionTool); ok {
		input, err := tool.parseInput(action.input)
		if err != nil {
			action := &AgentAction{
				action: actionException,
				input:  observationPrefix + "Invalid or incomplete response",
				log:    thoughtPrefix + err.Error(),
			}

			return stepOutput{action: action, observation: action.input}, nil
		}

		completion := &CompletionCommand{
			Command: input.Command,
			Nodes:   input.Nodes,
			Labels:  input.Labels,
		}

		log.Debugf("agent decided on command execution, let's translate to an AgentFinish")
		return stepOutput{finish: &AgentFinish{output: completion}}, nil
	}

	return stepOutput{}, trace.NotImplemented("")
}

func (a *Agent) plan(ctx context.Context, state *executionState) (*AgentAction, *AgentFinish, error) {
	scratchpad := a.constructScratchpad(state.intermediateSteps, state.observations)
	prompt := a.createPrompt(state.chatHistory, scratchpad, state.humanMessage)
	resp, err := state.llm.CreateChatCompletion(
		ctx,
		openai.ChatCompletionRequest{
			Model:    openai.GPT4,
			Messages: prompt,
		},
	)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	llmOut := resp.Choices[0].Message.Content
	err = state.tokensUsed.AddTokens(prompt, llmOut)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	action, finish, err := parseConversationOutput(llmOut)
	return action, finish, trace.Wrap(err)
}

func (a *Agent) createPrompt(chatHistory, agentScratchpad []openai.ChatCompletionMessage, humanMessage openai.ChatCompletionMessage) []openai.ChatCompletionMessage {
	prompt := make([]openai.ChatCompletionMessage, 0)
	prompt = append(prompt, chatHistory...)
	toolList := strings.Builder{}
	toolNames := make([]string, 0, len(a.tools))
	for _, tool := range a.tools {
		toolNames = append(toolNames, tool.Name())
		toolList.WriteString("> ")
		toolList.WriteString(tool.Name())
		toolList.WriteString(": ")
		toolList.WriteString(tool.Description())
		toolList.WriteString("\n")
	}

	if len(a.tools) == 0 {
		toolList.WriteString("No tools available.")
	}

	formatInstructions := conversationParserFormatInstructionsPrompt(toolNames)
	newHumanMessage := conversationToolUsePrompt(toolList.String(), formatInstructions, humanMessage.Content)
	prompt = append(prompt, openai.ChatCompletionMessage{
		Role:    openai.ChatMessageRoleUser,
		Content: newHumanMessage,
	})

	prompt = append(prompt, agentScratchpad...)
	return prompt
}

func (a *Agent) constructScratchpad(intermediateSteps []AgentAction, observations []string) []openai.ChatCompletionMessage {
	var thoughts []openai.ChatCompletionMessage
	for i, action := range intermediateSteps {
		thoughts = append(thoughts, openai.ChatCompletionMessage{
			Role:    openai.ChatMessageRoleAssistant,
			Content: action.log,
		}, openai.ChatCompletionMessage{
			Role:    openai.ChatMessageRoleUser,
			Content: conversationToolResponse(observations[i]),
		})
	}

	return thoughts
}

func parseJSONFromModel[T any](text string) (T, *invalidOutputError) {
	cleaned := strings.TrimSpace(text)
	if strings.Contains(cleaned, "```json") {
		cleaned = strings.Split(cleaned, "```json")[1]
	}
	if strings.Contains(cleaned, "```") {
		cleaned = strings.Split(cleaned, "```")[0]
	}
	cleaned = strings.TrimPrefix(cleaned, "```json")
	cleaned = strings.TrimPrefix(cleaned, "```")
	strings.TrimSuffix(cleaned, "```")
	cleaned = strings.TrimSpace(cleaned)
	var output T
	err := json.Unmarshal([]byte(cleaned), &output)
	if err != nil {
		return output, newInvalidOutputErrorWithParseError(err)
	}

	return output, nil
}

type planOutput struct {
	Action       string `json:"action"`
	Action_input any    `json:"action_input"`
}

func parseConversationOutput(text string) (*AgentAction, *AgentFinish, error) {
	log.Debugf("received planning output: \"%v\"", text)
	response, err := parseJSONFromModel[planOutput](text)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	if response.Action == actionFinalAnswer {
		outputString, ok := response.Action_input.(string)
		if !ok {
			return nil, nil, trace.Errorf("invalid final answer type %T", response.Action_input)
		}

		return nil, &AgentFinish{output: &Message{Content: outputString}}, nil
	}

	if v, ok := response.Action_input.(string); ok {
		return &AgentAction{action: response.Action, input: v}, nil, nil
	} else {
		input, err := json.Marshal(response.Action_input)
		if err != nil {
			return nil, nil, trace.Wrap(err)
		}

		return &AgentAction{action: response.Action, input: string(input)}, nil, nil
	}
}
