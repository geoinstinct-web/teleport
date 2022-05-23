/*
Copyright 2021 Gravitational, Inc.

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
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"time"

	"github.com/gravitational/teleport/.cloudbuild/scripts/internal/changes"
	"github.com/gravitational/teleport/.cloudbuild/scripts/internal/etcd"
	"github.com/gravitational/teleport/.cloudbuild/scripts/internal/git"
	"github.com/gravitational/teleport/.cloudbuild/scripts/internal/secrets"
	"github.com/gravitational/trace"
	log "github.com/sirupsen/logrus"
)

const (
	gomodcacheDir = ".gomodcache-ci"
)

// main is just a stub that prints out an error message and sets a nonzero exit
// code on failure. All of the work happens in `innerMain()`.
func main() {
	if err := innerMain(); err != nil {
		log.Fatalf("FAILED: %s", err.Error())
	}
}

type commandlineArgs struct {
	workspace     string
	targetBranch  string
	commitSHA     string
	githubKeySrc  string
	skipUnshallow bool
}

func parseCommandLine() (commandlineArgs, error) {
	args := commandlineArgs{}

	flag.StringVar(&args.workspace, "workspace", "/workspace", "Fully-qualified path to the build workspace")
	flag.StringVar(&args.targetBranch, "target", "", "The PR's target branch")
	flag.StringVar(&args.commitSHA, "commit", "HEAD", "The PR's latest commit SHA")
	flag.StringVar(&args.githubKeySrc, "key-secret", "", "Location of github deploy token, as a Google Cloud Secret")

	flag.Parse()

	if args.workspace == "" {
		return args, trace.Errorf("workspace path must be set")
	}

	var err error
	args.workspace, err = filepath.Abs(args.workspace)
	if err != nil {
		return args, trace.Wrap(err, "Unable to resolve absolute path to workspace")
	}

	if args.targetBranch == "" {
		return args, trace.Errorf("target branch must be set")
	}

	if args.commitSHA == "" {
		return args, trace.Errorf("commit must be set")
	}

	return args, nil
}

// innerMain parses the command line, performs the highlevel docs change check
// and creates the marker file if necessary
func innerMain() error {
	args, err := parseCommandLine()
	if err != nil {
		return trace.Wrap(err)
	}

	// If a github deploy key location was supplied...
	var deployKey []byte
	if args.githubKeySrc != "" {
		// fetch the deployment key from the GCB secret manager
		log.Infof("Fetching deploy key from %s", args.githubKeySrc)
		deployKey, err = secrets.Fetch(context.Background(), args.githubKeySrc)
		if err != nil {
			return trace.Wrap(err, "failed fetching deploy key")
		}
	}

	if !args.skipUnshallow {
		unshallowCtx, unshallowCancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer unshallowCancel()
		err = git.UnshallowRepository(unshallowCtx, args.workspace, deployKey)
		if err != nil {
			return trace.Wrap(err, "unshallow failed")
		}
	}

	log.Println("Analysing code changes")
	ch, err := changes.Analyze(args.workspace, args.targetBranch, args.commitSHA)
	if err != nil {
		return trace.Wrap(err, "Failed analyzing code")
	}

	hasOnlyDocChanges := ch.Docs && (!ch.Code)
	if hasOnlyDocChanges {
		log.Println("No non-docs changes detected. Skipping tests.")
		return nil
	}

	log.Printf("Starting etcd...")
	cancelCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err = etcd.Start(cancelCtx, args.workspace, 0, 0)
	if err != nil {
		return trace.Wrap(err, "failed starting etcd")
	}

	log.Printf("Running unit tests...")
	err = runUnitTests(args.workspace)
	if err != nil {
		return trace.Wrap(err, "unit tests failed")
	}

	log.Printf("PASS")

	return nil
}

func runUnitTests(workspace string) error {
	gomodcache := fmt.Sprintf("GOMODCACHE=%s", path.Join(workspace, gomodcacheDir))

	cmd := exec.Command("make", "test")
	cmd.Dir = workspace
	cmd.Env = append(os.Environ(), gomodcache, "TELEPORT_ETCD_TEST=yes")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}
