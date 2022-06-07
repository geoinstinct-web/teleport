//go:build linux
// +build linux

/*
Copyright 2015-2018 Gravitational, Inc.

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

package srv

import (
	"fmt"
	"os"
	os_exec "os/exec"
	"os/user"
	"strconv"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/gravitational/teleport"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/lib/sshutils"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/stretchr/testify/require"
)

// TestMain will re-execute Teleport to run a command if "exec" is passed to
// it as an argument. Otherwise it will run tests as normal.
func TestMain(m *testing.M) {
	utils.InitLoggerForTests()
	// If the test is re-executing itself, execute the command that comes over
	// the pipe.
	if IsReexec() {
		RunAndExit(os.Args[1])
		return
	}

	// Otherwise run tests as normal.
	code := m.Run()
	os.Exit(code)
}

func TestLoginDefsParser(t *testing.T) {
	expectedEnvSuPath := "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/bar"
	expectedSuPath := "PATH=/usr/local/bin:/usr/bin:/bin:/foo"

	require.Equal(t, expectedEnvSuPath, getDefaultEnvPath("0", "../../fixtures/login.defs"))
	require.Equal(t, expectedSuPath, getDefaultEnvPath("1000", "../../fixtures/login.defs"))
	require.Equal(t, defaultEnvPath, getDefaultEnvPath("1000", "bad/file"))
}

func TestOSCommandPrep(t *testing.T) {
	srv := newMockServer(t)
	scx := newExecServerContext(t, srv)

	usr, err := user.Current()
	require.NoError(t, err)

	expectedEnv := []string{
		"LANG=en_US.UTF-8",
		getDefaultEnvPath(strconv.Itoa(os.Geteuid()), defaultLoginDefsPath),
		fmt.Sprintf("HOME=%s", usr.HomeDir),
		fmt.Sprintf("USER=%s", usr.Username),
		"SHELL=/bin/sh",
		"SSH_CLIENT=10.0.0.5 4817 3022",
		"SSH_CONNECTION=10.0.0.5 4817 127.0.0.1 3022",
		"TERM=xterm",
		fmt.Sprintf("SSH_TTY=%v", scx.session.term.TTY().Name()),
		"SSH_SESSION_ID=xxx",
		"SSH_SESSION_WEBPROXY_ADDR=<proxyhost>:3080",
		"SSH_TELEPORT_HOST_UUID=test",
		"SSH_TELEPORT_CLUSTER_NAME=localhost",
		"SSH_TELEPORT_USER=teleportUser",
	}

	// Empty command (simple shell).
	execCmd, err := scx.ExecCommand()
	require.NoError(t, err)

	cmd, err := buildCommand(execCmd, usr, nil, nil, nil)
	require.NoError(t, err)

	require.NotNil(t, cmd)
	require.Equal(t, "/bin/sh", cmd.Path)
	require.Equal(t, []string{"-sh"}, cmd.Args)
	require.Equal(t, usr.HomeDir, cmd.Dir)
	require.Equal(t, expectedEnv, cmd.Env)
	require.Equal(t, syscall.SIGKILL, cmd.SysProcAttr.Pdeathsig)

	// Non-empty command (exec a prog).
	scx.ExecRequest.SetCommand("ls -lh /etc")
	execCmd, err = scx.ExecCommand()
	require.NoError(t, err)

	cmd, err = buildCommand(execCmd, usr, nil, nil, nil)
	require.NoError(t, err)

	require.NotNil(t, cmd)
	require.Equal(t, "/bin/sh", cmd.Path)
	require.Equal(t, []string{"/bin/sh", "-c", "ls -lh /etc"}, cmd.Args)
	require.Equal(t, usr.HomeDir, cmd.Dir)
	require.Equal(t, expectedEnv, cmd.Env)
	require.Equal(t, syscall.SIGKILL, cmd.SysProcAttr.Pdeathsig)

	// Command without args.
	scx.ExecRequest.SetCommand("top")
	execCmd, err = scx.ExecCommand()
	require.NoError(t, err)

	cmd, err = buildCommand(execCmd, usr, nil, nil, nil)
	require.NoError(t, err)

	require.Equal(t, "/bin/sh", cmd.Path)
	require.Equal(t, []string{"/bin/sh", "-c", "top"}, cmd.Args)
	require.Equal(t, syscall.SIGKILL, cmd.SysProcAttr.Pdeathsig)

	if os.Geteuid() != 0 {
		t.Skip("skipping portion of test which must run as root")
	}

	// Missing home directory - HOME should still be set to the given
	// home dir, but the command should set it's CWD to root instead.
	usr.HomeDir = "/wrong/place"
	root := string(os.PathSeparator)
	expectedEnv[2] = "HOME=/wrong/place"
	cmd, err = buildCommand(execCmd, usr, nil, nil, nil)
	require.NoError(t, err)

	require.Equal(t, root, cmd.Dir)
	require.Equal(t, expectedEnv, cmd.Env)
}

// TestEmitExecAuditEvent make sure the full command and exit code for a
// command is always recorded.
func TestEmitExecAuditEvent(t *testing.T) {
	srv := newMockServer(t)
	scx := newExecServerContext(t, srv)

	var tests = []struct {
		inCommand  string
		inError    error
		outCommand string
		outCode    string
	}{
		// Successful execution.
		{
			inCommand:  "exit 0",
			inError:    nil,
			outCommand: "exit 0",
			outCode:    strconv.Itoa(teleport.RemoteCommandSuccess),
		},
		// Exited with error.
		{
			inCommand:  "exit 255",
			inError:    fmt.Errorf("unknown error"),
			outCommand: "exit 255",
			outCode:    strconv.Itoa(teleport.RemoteCommandFailure),
		},
		// Command injection.
		{
			inCommand:  "/bin/teleport scp --remote-addr=127.0.0.1:50862 --local-addr=127.0.0.1:54895 -f ~/file.txt && touch /tmp/new.txt",
			inError:    fmt.Errorf("unknown error"),
			outCommand: "/bin/teleport scp --remote-addr=127.0.0.1:50862 --local-addr=127.0.0.1:54895 -f ~/file.txt && touch /tmp/new.txt",
			outCode:    strconv.Itoa(teleport.RemoteCommandFailure),
		},
	}
	for _, tt := range tests {
		emitExecAuditEvent(scx, tt.inCommand, tt.inError)
		execEvent := srv.MockEmitter.LastEvent().(*apievents.Exec)
		require.Equal(t, tt.outCommand, execEvent.Command)
		require.Equal(t, tt.outCode, execEvent.ExitCode)
	}
}

// TestContinue tests if the process hangs if a continue signal is not sent
// and makes sure the process continues once it has been sent.
func TestContinue(t *testing.T) {
	srv := newMockServer(t)
	scx := newExecServerContext(t, srv)

	// Configure Session Context to re-exec "ls".
	var err error
	lsPath, err := os_exec.LookPath("ls")
	require.NoError(t, err)
	scx.ExecRequest.SetCommand(lsPath)

	// Create an exec.Cmd to execute through Teleport.
	cmd, err := ConfigureCommand(scx)
	require.NoError(t, err)

	// Create a channel that will be used to signal that execution is complete.
	cmdDone := make(chan error, 1)

	// Re-execute Teleport and run "ls". Signal over the context when execution
	// is complete.
	go func() {
		cmdDone <- cmd.Run()
	}()

	// Wait for the process. Since the continue pipe has not been closed, the
	// process should not have exited yet.
	select {
	case err := <-cmdDone:
		t.Fatalf("Process exited before continue with error %v", err)
	case <-time.After(5 * time.Second):
	}

	// Close the continue pipe to signal to Teleport to now execute the
	// requested program.
	err = scx.contw.Close()
	require.NoError(t, err)

	// Program should have executed now. If the complete signal has not come
	// over the context, something failed.
	select {
	case <-time.After(5 * time.Second):
		t.Fatalf("Timed out waiting for process to finish.")
	case err := <-cmdDone:
		require.NoError(t, err)
	}
}

func newExecServerContext(t *testing.T, srv Server) *ServerContext {
	scx := newTestServerContext(t, srv, nil)

	term, err := newLocalTerminal(scx)
	require.NoError(t, err)
	term.SetTermType("xterm")

	scx.session = &session{id: "xxx"}
	scx.session.term = term
	scx.request = &ssh.Request{Type: sshutils.ExecRequest}

	t.Cleanup(func() { require.NoError(t, scx.session.term.Close()) })

	return scx
}
