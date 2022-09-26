package regular

import (
	"context"
	"io"
	"os"
	"os/user"
	"strings"

	"github.com/gravitational/teleport/lib/srv"

	"github.com/gravitational/trace"
	"golang.org/x/crypto/ssh"
)

type homeDirSubsys struct {
	done chan struct{}
}

func newHomeDirSubsys() *homeDirSubsys {
	return &homeDirSubsys{
		done: make(chan struct{}),
	}
}

func (h *homeDirSubsys) Start(_ context.Context, serverConn *ssh.ServerConn, ch ssh.Channel, _ *ssh.Request, _ *srv.ServerContext) error {
	defer close(h.done)

	connUser := serverConn.User()
	localUser, err := user.Lookup(connUser)
	if err != nil {
		return trace.Wrap(err)
	}

	exists, err := srv.CheckHomeDir(localUser)
	if err != nil {
		return trace.Wrap(err)
	}
	homeDir := localUser.HomeDir
	if !exists {
		homeDir = string(os.PathSeparator)
	}
	_, err = io.Copy(ch, strings.NewReader(homeDir))

	return trace.Wrap(err)
}

func (h *homeDirSubsys) Wait() error {
	<-h.done
	return nil
}
