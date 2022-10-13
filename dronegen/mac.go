package main

import (
	"fmt"
	"path"
	"path/filepath"
)

// escapedPreformatted returns expr wrapped in escaped backticks,
// resulting in Slack "preformatted" string, but safe to use in bash
// without triggering the command expansion.
// This is useful for use in Go backtick literals,
// where backticks can not be escaped in any way.
func escapedPreformatted(expr string) string {
	return fmt.Sprintf("\\`%s\\`", expr)
}

func newDarwinPipeline(name string) pipeline {
	p := newExecPipeline(name)
	p.Workspace.Path = path.Join("/tmp", name)
	p.Concurrency.Limit = 1
	p.Platform = platform{OS: "darwin", Arch: "amd64"}
	return p
}

func darwinPushPipeline() pipeline {
	p := newDarwinPipeline("push-build-darwin-amd64")
	p.Trigger = triggerPush
	p.Steps = []step{
		setUpExecStorageStep(p.Workspace.Path),
		{
			Name: "Check out code",
			Environment: map[string]value{
				"WORKSPACE_DIR":      {raw: p.Workspace.Path},
				"GITHUB_PRIVATE_KEY": {fromSecret: "GITHUB_PRIVATE_KEY"},
			},
			Commands: pushCheckoutCommandsDarwin(),
		},
		{
			Name: "Build Mac artifacts",
			Environment: map[string]value{
				"GOPATH":        {raw: path.Join(p.Workspace.Path, "/go")},
				"GOCACHE":       {raw: path.Join(p.Workspace.Path, "/go/cache")},
				"OS":            {raw: "darwin"},
				"ARCH":          {raw: "amd64"},
				"WORKSPACE_DIR": {raw: p.Workspace.Path},
			},
			Commands: darwinTagBuildCommands(),
		},
		cleanUpExecStorageStep(p.Workspace.Path),
		{
			Name:        "Send Slack notification (exec)",
			Environment: map[string]value{"SLACK_WEBHOOK_DEV_TELEPORT": {fromSecret: "SLACK_WEBHOOK_DEV_TELEPORT"}},
			Commands: []string{
				`
export DRONE_BUILD_LINK="${DRONE_SYSTEM_PROTO}://${DRONE_SYSTEM_HOSTNAME}/${DRONE_REPO_OWNER}/${DRONE_REPO_NAME}/${DRONE_BUILD_NUMBER}"
export GOOS=$(go env GOOS)
export GOARCH=$(go env GOARCH)
`,
				fmt.Sprintf(`
curl -sL -X POST -H 'Content-type: application/json' --data "{\"text\":\"Warning: %s artifact build failed for [%s] - please investigate immediately!\nBranch: %s\nCommit: %s\nLink: $DRONE_BUILD_LINK\"}" $SLACK_WEBHOOK_DEV_TELEPORT`,
					escapedPreformatted("${GOOS}-${GOARCH}"),
					escapedPreformatted("${DRONE_REPO_NAME}"),
					escapedPreformatted("${DRONE_BRANCH}"),
					escapedPreformatted("${DRONE_COMMIT_SHA}")),
			},
			When: &condition{Status: []string{"failure"}},
		},
	}
	return p
}

func darwinTagPipeline() pipeline {
	b := buildType{
		arch: "amd64",
		os:   "darwin",
	}
	p := newDarwinPipeline("build-darwin-amd64")
	p.Trigger = triggerTag
	awsConfigPath := filepath.Join(p.Workspace.Path, "credentials")
	p.DependsOn = []string{tagCleanupPipelineName}
	p.Steps = []step{
		setUpExecStorageStep(p.Workspace.Path),
		{
			Name: "Check out code",
			Environment: map[string]value{
				"WORKSPACE_DIR":      {raw: p.Workspace.Path},
				"GITHUB_PRIVATE_KEY": {fromSecret: "GITHUB_PRIVATE_KEY"},
			},
			Commands: darwinTagCheckoutCommands(),
		},
		{
			Name: "Build Mac release artifacts",
			Environment: map[string]value{
				"GOPATH":        {raw: path.Join(p.Workspace.Path, "/go")},
				"GOCACHE":       {raw: path.Join(p.Workspace.Path, "/go/cache")},
				"OS":            {raw: b.os},
				"ARCH":          {raw: b.arch},
				"WORKSPACE_DIR": {raw: p.Workspace.Path},
			},
			Commands: darwinTagBuildCommands(),
		},
		{
			Name: "Copy Mac artifacts",
			Environment: map[string]value{
				"WORKSPACE_DIR": {raw: p.Workspace.Path},
			},
			Commands: darwinTagCopyPackageArtifactCommands(),
		},
		macAssumeAwsRoleStep(macRoleSettings{
			awsRoleSettings: awsRoleSettings{
				awsAccessKeyId:     value{fromSecret: "AWS_ACCESS_KEY_ID"},
				awsSecretAccessKey: value{fromSecret: "AWS_SECRET_ACCESS_KEY"},
				role:               value{fromSecret: "AWS_ROLE"},
			},
			configPath: awsConfigPath,
		}),
		{
			Name: "Upload to S3",
			Environment: map[string]value{
				"AWS_S3_BUCKET":               {fromSecret: "AWS_S3_BUCKET"},
				"AWS_REGION":                  {raw: "us-west-2"},
				"AWS_SHARED_CREDENTIALS_FILE": {raw: awsConfigPath},
				"WORKSPACE_DIR":               {raw: p.Workspace.Path},
			},
			Commands: darwinUploadToS3Commands(),
		},
		{
			Name:     "Register artifacts",
			Commands: tagCreateReleaseAssetCommands(b, "", nil),
			Environment: map[string]value{
				"WORKSPACE_DIR": {raw: p.Workspace.Path},
				"RELEASES_CERT": {fromSecret: "RELEASES_CERT"},
				"RELEASES_KEY":  {fromSecret: "RELEASES_KEY"},
			},
		},
		cleanUpExecStorageStep(p.Workspace.Path),
	}
	return p
}

func pushCheckoutCommandsDarwin() []string {
	return []string{
		`set -u`,
		`mkdir -p $WORKSPACE_DIR/go/src/github.com/gravitational/teleport`,
		`cd $WORKSPACE_DIR/go/src/github.com/gravitational/teleport`,
		`git clone https://github.com/gravitational/${DRONE_REPO_NAME}.git .`,
		`git checkout ${DRONE_TAG:-$DRONE_COMMIT}`,
		// fetch enterprise submodules
		// suppressing the newline on the end of the private key makes git operations fail on MacOS
		// with an error like 'Load key "/path/.ssh/id_rsa": invalid format'
		`mkdir -m 0700 $WORKSPACE_DIR/.ssh && echo "$GITHUB_PRIVATE_KEY" > $WORKSPACE_DIR/.ssh/id_rsa && chmod 600 $WORKSPACE_DIR/.ssh/id_rsa`,
		`ssh-keyscan -H github.com > $WORKSPACE_DIR/.ssh/known_hosts 2>/dev/null`,
		`chmod 600 $WORKSPACE_DIR/.ssh/known_hosts`,
		`GIT_SSH_COMMAND='ssh -i $WORKSPACE_DIR/.ssh/id_rsa -o UserKnownHostsFile=$WORKSPACE_DIR/.ssh/known_hosts -F /dev/null' git submodule update --init e`,
		// this is allowed to fail because pre-4.3 Teleport versions don't use the webassets submodule
		`GIT_SSH_COMMAND='ssh -i $WORKSPACE_DIR/.ssh/id_rsa -o UserKnownHostsFile=$WORKSPACE_DIR/.ssh/known_hosts -F /dev/null' git submodule update --init --recursive webassets || true`,
		`rm -rf $WORKSPACE_DIR/.ssh`,
		`mkdir -p $WORKSPACE_DIR/go/cache`,
	}
}

func setUpExecStorageStep(path string) step {
	return step{
		Name:        "Set up exec runner storage",
		Environment: map[string]value{"WORKSPACE_DIR": {raw: path}},
		Commands: []string{
			"set -u",
			"mkdir -p $WORKSPACE_DIR",
			"chmod -R u+rw $WORKSPACE_DIR",
			"rm -rf $WORKSPACE_DIR/go $WORKSPACE_DIR/.ssh",
		},
	}
}

func cleanUpExecStorageStep(path string) step {
	return step{
		Name:        "Clean up exec runner storage (post)",
		Environment: map[string]value{"WORKSPACE_DIR": {raw: path}},
		Commands: []string{
			`set -u`,
			`chmod -R u+rw $WORKSPACE_DIR`,
			`rm -rf $WORKSPACE_DIR/go $WORKSPACE_DIR/.ssh`,
		},
	}
}

func darwinTagCheckoutCommands() []string {
	return append(pushCheckoutCommandsDarwin(),
		`mkdir -p $WORKSPACE_DIR/go/artifacts`,
		`echo "${DRONE_TAG##v}" > $WORKSPACE_DIR/go/.version.txt`,
		`cat $WORKSPACE_DIR/go/.version.txt`,
	)
}

func darwinTagBuildCommands() []string {
	return []string{
		`set -u`,
		`cd $WORKSPACE_DIR/go/src/github.com/gravitational/teleport`,
		`make clean release OS=$OS ARCH=$ARCH`,
	}
}

func darwinTagCopyPackageArtifactCommands() []string {
	return []string{
		`set -u`,
		`cd $WORKSPACE_DIR/go/src/github.com/gravitational/teleport`,
		// copy release archives to artifact directory
		`cp teleport*.tar.gz $WORKSPACE_DIR/go/artifacts`,
		`cp e/teleport-ent*.tar.gz $WORKSPACE_DIR/go/artifacts`,
		// generate checksums (for mac)
		`cd $WORKSPACE_DIR/go/artifacts && for FILE in teleport*.tar.gz; do shasum -a 256 $FILE > $FILE.sha256; done && ls -l`,
	}
}

func darwinUploadToS3Commands() []string {
	return []string{
		`set -u`,
		`cd $WORKSPACE_DIR/go/artifacts`,
		`aws s3 sync . s3://$AWS_S3_BUCKET/teleport/tag/${DRONE_TAG##v}`,
	}
}
