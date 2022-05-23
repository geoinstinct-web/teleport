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

package main

import (
	"flag"
	"path/filepath"

	"github.com/gravitational/trace"
)

type commandlineArgs struct {
	workspace     string
	targetBranch  string
	commitSHA     string
	skipChown     bool
	githubKeySrc  string
	skipUnshallow bool
}

// validate ensures the suplied arguments are valid & internally consistent.
func (args *commandlineArgs) validate() error {
	if args.workspace == "" {
		return trace.Errorf("workspace path must be set")
	}

	var err error
	args.workspace, err = filepath.Abs(args.workspace)
	if err != nil {
		return trace.Wrap(err, "Unable to resole absolute path to workspace")
	}

	if args.targetBranch == "" {
		return trace.Errorf("target branch must be set")
	}

	if args.commitSHA == "" {
		return trace.Errorf("commit must be set")
	}
	return nil
}

func parseCommandLine() (*commandlineArgs, error) {
	args := &commandlineArgs{}

	flag.StringVar(&args.workspace, "workspace", "/workspace", "Fully-qualified path to the build workspace")
	flag.StringVar(&args.targetBranch, "target", "", "The PR's target branch")
	flag.StringVar(&args.commitSHA, "commit", "HEAD", "The PR's latest commit SHA")
	flag.BoolVar(&args.skipChown, "skip-chown", false, "Skip reconfiguring the workspace for a nonroot user.")
	flag.StringVar(&args.githubKeySrc, "key-secret", "", "Location of github deploy token, as a Google Cloud Secret")
	flag.BoolVar(&args.skipUnshallow, "skip-unshallow", false, "Skip unshallowing the repository.")

	flag.Parse()

	err := args.validate()
	if err != nil {
		return nil, err
	}

	return args, nil
}
