---
authors: Andrew LeFevre (andrew.lefevre@goteleport.com)
state: draft
---

# RFD 74 - SFTP Support

## What

Add SFTP support to `tsh` and Teleport Node and Proxy services. This will
not replace scp, both will be supported.

## Why

[OpenSSH 9.0](https://www.openssh.com/txt/release-9.0) changed `scp` to
use the [SFTP](atatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02)
protocol by default instead of scp/rcp protocol. This is to
combat many security issues present in the legacy scp/rcp protocol. Users
running the latest OpenSSH version will currently find that `scp` and various
tools that use it under the hood, such as Ansible and various JetBrain IDEs
will not work through Teleport anymore. This can be fixed temporarily by passing
a flag to `scp`, but that can be difficult when `scp` is being invoked indirectly
by other tools.

## Details

[github.com/pkg/sftp](https://pkg.go.dev/github.com/pkg/sftp) will be leveraged 
heavily to provide both an SFTP client and server.

SFTP support will be added in two stages. Adding SFTP subsystem support to
Teleport's SSH server will be the first step. When an SFTP request is
first received on an SSH connection, the Teleport daemon will be re-executed as the
logon user of the SSH connection. This will require
adding a hidden `sftp` sub command to the `teleport` binary. The parent process will
create 2 anonymous pipes and pass them to the child (`teleport sftp`) so the child
can access the SFTP connection.

The second stage will be adding the `sftp` sub command to `tsh`, and ensuring
SFTP trasfers work on the web UI.

### Security

SFTP uses the SSH protocol to provide confidentiality and integrity, as it is
used inside an existing SSH connection. It also has the benefit of not starting
processes with attacker-controlled arguments like the scp/rcp protocol does.

As mentioned above, Teleport Node services will re-execute themselves as the
SSH login user to handle SFTP connections. This will ensure users can only
access and modify files they are allowed to.

Two role options will be added to control whether users can use scp and/or
SFTP.

### UX

The UX of `tsh sftp` will be very similar to that of `tsh scp`, but there
will be some differences of behavior between the two. SFTP does not natively
support expanding home directories, so absolute paths will have to be used
for remote paths. Likewise passing quoted commands to be remotely executed
(ex. ``tsh scp my_file 'user@host:/tmp/`whoami`.txt'``) will not work as
`teleport sftp` is run without any other arguments.

The web UI for trasferring files will need to have a method of allowing the
user to choose between scp and SFTP. A knob could be added for this purpose,
and it would be grayed out if the user is not allowed to use either scp or
SFTP due to role constraints.

Examples of `tsh sftp`:

```bash
tsh sftp ~/Downloads/notes.txt user@cluster.host:/home/user/Documents
tsh sftp user@cluster.host:/home/user/Documents/notes.txt ~/Downloads/notes.txt
```
