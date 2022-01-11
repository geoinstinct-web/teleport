package x11

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strings"

	"github.com/gravitational/trace"
)

const (
	// mitMagicCookieProto is the default xauth protocol used for x11 forwarding.
	mitMagicCookieProto = "MIT-MAGIC-COOKIE-1"
	// mitMagicCookieSize is the number of bytes in an mit magic cookie.
	mitMagicCookieSize = 16
)

// XAuthEntry is an entry in an XAuthority database which can be used to authenticate
// and authorize requests from an XServer to the associated X display.
type XAuthEntry struct {
	// Display is an X display in the format - [hostname]:[display_number].[screen_number]
	Display string `json:"display"`
	// Proto is an XAuthority protocol, generally "MIT-MAGIC-COOKIE-1"
	Proto string `json:"proto"`
	// Cookie is a hex encoded XAuthority cookie
	Cookie string `json:"cookie"`
}

// NewXauthEntry generates a new trusted xauth entry.
func NewXauthEntry(display string) (*XAuthEntry, error) {
	// the client's local XAuthority will treat this
	// random cookie the same as one generated with
	// `xauth generate trusted <display> MIT-MAGIC-COOKIE-1`
	cookie, err := newFakeCookie(mitMagicCookieSize)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &XAuthEntry{
		Display: display,
		Proto:   mitMagicCookieProto,
		Cookie:  cookie,
	}, nil
}

func newFakeCookie(byteLength int) (string, error) {
	cookieBytes := make([]byte, byteLength)
	if _, err := rand.Read(cookieBytes); err != nil {
		return "", trace.Wrap(err)
	}
	return hex.EncodeToString(cookieBytes), nil
}

// SpoofCookie creates a new random cookie with the same length as the entry's cookie.
// This is used to create a believable spoof of the client's xauth data to send to the server.
func (e *XAuthEntry) SpoofCookie() (string, error) {
	spoof, err := newFakeCookie(hex.DecodedLen(len(e.Cookie)))
	if err != nil {
		return "", trace.Wrap(err)
	}
	return spoof, nil
}

// XAuthCommand is a os/exec.Cmd wrapper for running xauth commands.
type XAuthCommand struct {
	*exec.Cmd
}

// NewXAuthCommand reate a new "xauth" command. xauthFile can be
// optionally provided to run the xauth command against a specific xauth file.
func NewXAuthCommand(ctx context.Context, xauthFile string) *XAuthCommand {
	var args []string
	if xauthFile != "" {
		args = []string{"-f", xauthFile}
	}
	return &XAuthCommand{exec.CommandContext(ctx, "xauth", args...)}
}

// ReadEntry runs "xauth list" to read the first xauth entry for the given display.
func (x *XAuthCommand) ReadEntry(display string) (*XAuthEntry, error) {
	x.Cmd.Args = append(x.Cmd.Args, "list", display)
	out, err := x.CombinedOutput()
	if err != nil {
		return nil, trace.Wrap(err, string(out))
	} else if len(out) == 0 {
		return nil, trace.NotFound("no xauth entry found")
	}

	// Ignore entries beyond the first listed.
	entry := strings.Split(string(out), "\n")[0]

	splitEntry := strings.Split(entry, "  ")
	if len(splitEntry) != 3 {
		return nil, trace.Errorf("invalid xAuthEntry, expected entry to have three parts")
	}
	_, proto, cookie := splitEntry[0], splitEntry[1], splitEntry[2]

	return &XAuthEntry{
		Display: display,
		Proto:   proto,
		Cookie:  cookie,
	}, nil
}

// RemoveEntries runs "xauth remove" to remove any xauth entries for the given display.
func (x *XAuthCommand) RemoveEntries(display string) error {
	x.Cmd.Args = append(x.Cmd.Args, "remove", display)
	return trace.Wrap(x.Run())
}

// AddEntry runs "xauth add" to add the given xauth entry.
func (x *XAuthCommand) AddEntry(entry *XAuthEntry) error {
	x.Cmd.Args = append(x.Cmd.Args, "add", entry.Display, entry.Proto, entry.Cookie)
	return trace.Wrap(x.Run())
}

// GenerateUntrustedCookie runs "xauth generate untrusted" to create a new untrusted xauth
// entry for the given display. A timeout can optionally be set for the xauth entry. This
// untrusted cookie will provide fewer X privileges than a trusted cookie to prevent
// attackers from using the cookie to perform actions like keystroke monitoring.
func (x *XAuthCommand) GenerateUntrustedCookie(display, proto string, timeout uint) error {
	x.Cmd.Args = append(x.Cmd.Args, "generate", "untrusted", display, proto)
	if timeout != 0 {
		// Add some slack to the ttl to avoid XServer from denying
		// access to the ssh session during its lifetime.
		var timeoutSlack uint = 60
		x.Cmd.Args = append(x.Cmd.Args, "timeout", fmt.Sprint(timeout+timeoutSlack))
	}
	return trace.Wrap(x.Run())
}
