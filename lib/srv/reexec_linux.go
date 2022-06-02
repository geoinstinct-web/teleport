// +build linux

package srv

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

func init() {
	// errors in open/openat are signaled by returning -1, we don't really care
	// about the specifics anyway so we can just ignore the error value
	//
	// we're opening with O_PATH rather than O_RDONLY because the binary might
	// not actually be readable (but only executable)
	fd1, _ := syscall.Open("/proc/self/exe", unix.O_PATH|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	fd2, _ := syscall.Open("/proc/self/exe", unix.O_PATH|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)

	// this can happen if both calls failed (returning -1) or if we're
	// running in a version of qemu-user that's affected by this bug:
	// https://gitlab.com/qemu-project/qemu/-/issues/927
	// (hopefully they'll also add special handling for execve on /proc/self/exe
	// if they ever fix that bug)
	if fd1 == fd2 {
		return
	}

	// closing -1 is harmless, no need to check here
	syscall.Close(fd1)
	syscall.Close(fd2)

	// if one Open has failed but not the other we can't really
	// trust the availability of "/proc/self/exe"
	if fd1 == -1 || fd2 == -1 {
		return
	}

	reexecPath = "/proc/self/exe"
}

// reexecPath specifies a path to execute on reexec, overriding Path in the cmd
// passed to reexecCommandOSTweaks, if not empty.
var reexecPath string

func reexecCommandOSTweaks(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = new(syscall.SysProcAttr)
	}
	// Linux only: when parent process (node) dies unexpectedly without
	// cleaning up child processes, send a signal for graceful shutdown
	// to children.
	cmd.SysProcAttr.Pdeathsig = syscall.SIGQUIT

	// replace the path on disk (which might not exist, or refer to an
	// upgraded version of teleport) with reexecPath, which contains
	// some path that refers to the specific binary we're running
	if reexecPath != "" {
		cmd.Path = reexecPath
	}
}

func userCommandOSTweaks(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = new(syscall.SysProcAttr)
	}
	// Linux only: when parent process (this process) dies unexpectedly, kill
	// the child process instead of orphaning it.
	// SIGKILL because we don't control the child process and it could choose
	// to ignore other signals.
	cmd.SysProcAttr.Pdeathsig = syscall.SIGKILL
}
