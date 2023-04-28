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

package main

import (
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"golang.org/x/exp/maps"
)

type ghaWorkflow struct {
	name              string
	stepName          string
	srcRefVar         string
	ref               string
	timeout           time.Duration
	slackOnError      bool
	shouldTagWorkflow bool
	seriesRun         bool
	inputs            map[string]string
}

type ghaBuildType struct {
	buildType
	trigger
	pipelineName string
	checkoutPath string
	dependsOn    []string
	workflows    []ghaWorkflow
}

func ghaBuildPipeline(ghaBuild ghaBuildType) pipeline {
	return ghaMultiBuildPipeline(nil, ghaBuild)
}

// ghaMultiBuildPipeline returns a pipeline with multiple supported workflow call steps
func ghaMultiBuildPipeline(setupSteps []step, ghaBuild ghaBuildType) pipeline {
	p := newKubePipeline(ghaBuild.pipelineName)
	p.Trigger = ghaBuild.trigger
	p.Workspace = workspace{Path: "/go"}
	p.DependsOn = append(p.DependsOn, ghaBuild.dependsOn...)

	checkoutPath := ghaBuild.checkoutPath
	if checkoutPath == "" {
		checkoutPath = "/go/src/github.com/gravitational/teleport"
	}

	p.Steps = []step{
		{
			Name:  "Check out code",
			Image: "docker:git",
			Pull:  "if-not-exists",
			Environment: map[string]value{
				"GITHUB_PRIVATE_KEY": {fromSecret: "GITHUB_PRIVATE_KEY"},
			},
			Commands: pushCheckoutCommandsWithPath(ghaBuild.buildType, checkoutPath),
		},
	}

	p.Steps = append(p.Steps, setupSteps...)

	for _, workflow := range ghaBuild.workflows {
		p.Steps = append(p.Steps, buildGHAWorkflowCallStep(workflow, checkoutPath))

		if workflow.slackOnError {
			p.Steps = append(p.Steps, sendErrorToSlackStep())
		}
	}

	return p
}

func buildGHAWorkflowCallStep(workflow ghaWorkflow, checkoutPath string) step {
	var cmd strings.Builder
	cmd.WriteString(`go run ./cmd/gh-trigger-workflow `)
	cmd.WriteString(`-owner ${DRONE_REPO_OWNER} `)
	cmd.WriteString(`-repo teleport.e `)

	if workflow.shouldTagWorkflow {
		cmd.WriteString(`-tag-workflow `)
	}

	if workflow.seriesRun {
		cmd.WriteString(`-series-run `)
	}

	fmt.Fprintf(&cmd, `-timeout %s `, workflow.timeout.String())
	fmt.Fprintf(&cmd, `-workflow %s `, workflow.name)
	fmt.Fprintf(&cmd, `-workflow-ref=%s `, workflow.ref)

	// If we don't need to build teleport...
	if workflow.srcRefVar != "" {
		cmd.WriteString(`-input oss-teleport-repo=${DRONE_REPO} `)
		fmt.Fprintf(&cmd, `-input oss-teleport-ref=${%s} `, workflow.srcRefVar)
	}

	// Sort inputs so the are output in a consistent order to avoid
	// spurious changes in the generated drone config.
	keys := maps.Keys(workflow.inputs)
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&cmd, `-input "%s=%s" `, k, workflow.inputs[k])
	}

	stepName := workflow.stepName
	if stepName == "" {
		stepName = "Delegate build to GitHub"
	}

	return step{
		Name:  stepName,
		Image: fmt.Sprintf("golang:%s-alpine", GoVersion),
		Pull:  "if-not-exists",
		Environment: map[string]value{
			"GHA_APP_KEY": {fromSecret: "GITHUB_WORKFLOW_APP_PRIVATE_KEY"},
		},
		Commands: []string{
			fmt.Sprintf(`cd %q`, path.Join(checkoutPath, "build.assets", "tooling")),
			cmd.String(),
		},
	}
}
