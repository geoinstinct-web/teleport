/*
Copyright 2016 Gravitational, Inc.

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
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/session"
	"github.com/gravitational/teleport/lib/teleagent"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/buger/goterm"
	"github.com/pborman/uuid"
)

func main() {
	run(os.Args[1:], false)
}

// CLIConf stores command line arguments and flags:
type CLIConf struct {
	// UserHost contains "[login]@hostname" argument to SSH command
	UserHost string
	// Commands to execute on a remote host
	RemoteCommand []string
	// Login is the Teleport user login
	Login string
	// Proxy keeps the hostname:port of the SSH proxy to use
	Proxy string
	// TTL defines how long a session must be active (in minutes)
	MinsToLive int32
	// SSH Port on a remote SSH host
	NodePort int16
	// Login on a remote SSH host
	NodeLogin string
	// InsecureSkipVerify bypasses verification of HTTPS certificate when talking to web proxy
	InsecureSkipVerify bool
	// IsUnderTest is set to true for unit testing
	IsUnderTest bool
	// AgentSocketAddr is address for agent listeing socket
	AgentSocketAddr utils.NetAddrVal
	// Remote SSH session to join
	SessionID session.ID
	// Src:dest parameter for SCP
	CopySpec []string
	// -r flag for scp
	RecursiveCopy bool
	// -L flag for ssh. Local port forwarding like 'ssh -L 80:remote.host:80 -L 443:remote.host:443'
	LocalForwardPorts []string
	// --local flag for ssh
	LocalExec bool
	// ExternalAuth is used to authenticate using external OIDC method
	ExternalAuth string
	// SiteName specifies remote site go login to
	SiteName string
}

// run executes TSH client. same as main() but easier to test
func run(args []string, underTest bool) {
	var (
		cf CLIConf
	)
	cf.IsUnderTest = underTest
	utils.InitLoggerCLI()

	// configure CLI argument parser:
	app := utils.InitCLIParser("tsh", "TSH: Teleport SSH client").Interspersed(false)
	app.Flag("user", fmt.Sprintf("SSH proxy user [%s]", client.Username())).StringVar(&cf.Login)
	app.Flag("auth", "[EXPERIMENTAL] Use external authentication, e.g. 'google'").Hidden().StringVar(&cf.ExternalAuth)
	app.Flag("site", "[EXPERIMENTAL] Specify site to connect to via proxy").Hidden().StringVar(&cf.SiteName)
	app.Flag("proxy", "SSH proxy host or IP address").StringVar(&cf.Proxy)
	app.Flag("ttl", "Minutes to live for a SSH session").Int32Var(&cf.MinsToLive)
	app.Flag("insecure", "Do not verify server's certificate and host name. Use only in test environments").Default("false").BoolVar(&cf.InsecureSkipVerify)
	debugMode := app.Flag("debug", "Verbose logging to stdout").Short('d').Bool()
	app.HelpFlag.Short('h')
	ver := app.Command("version", "Print the version")
	// ssh
	ssh := app.Command("ssh", "Run shell or execute a command on a remote SSH node")
	ssh.Arg("[user@]host", "Remote hostname and the login to use").Required().StringVar(&cf.UserHost)
	ssh.Arg("command", "Command to execute on a remote host").StringsVar(&cf.RemoteCommand)
	ssh.Flag("port", "SSH port on a remote host").Short('p').Int16Var(&cf.NodePort)
	ssh.Flag("login", "Remote host login").Short('l').StringVar(&cf.NodeLogin)
	ssh.Flag("forward", "Forward localhost connections to remote server").Short('L').StringsVar(&cf.LocalForwardPorts)
	ssh.Flag("local", "Execute command on localhost after connecting to SSH node").Default("false").BoolVar(&cf.LocalExec)
	// join
	join := app.Command("join", "Join the active SSH session")
	join.Arg("session-id", "ID of the session to join").Required().SetValue(&cf.SessionID)
	// scp
	scp := app.Command("scp", "Secure file copy")
	scp.Arg("from, to", "Source and destination to copy").Required().StringsVar(&cf.CopySpec)
	scp.Flag("recursive", "Recursive copy of subdirectories").Short('r').BoolVar(&cf.RecursiveCopy)
	scp.Flag("port", "Port to connect to on the remote host").Short('P').Int16Var(&cf.NodePort)
	// ls
	ls := app.Command("ls", "List remote SSH nodes")
	ls.Arg("labels", "List of labels to filter node list").StringVar(&cf.UserHost)
	// sites
	sites := app.Command("sites", "[EXPERIMENTAL] List sites connected to the proxy").Hidden()
	// agent (SSH agent listening on unix socket)
	agent := app.Command("agent", "Start SSH agent on unix socket")
	agent.Flag("socket", "SSH agent listening socket address, e.g. unix:///tmp/teleport.agent.sock").SetValue(&cf.AgentSocketAddr)

	// login logs in with remote proxy and obtains certificate
	login := app.Command("login", "Log in with remote proxy and get signed certificate")

	// parse CLI commands+flags:
	command, err := app.Parse(args)
	if err != nil {
		utils.FatalError(err)
	}

	// apply -d flag:
	if *debugMode {
		utils.InitLoggerDebug()
	}

	switch command {
	case ver.FullCommand():
		onVersion()
	case ssh.FullCommand():
		onSSH(&cf)
	case join.FullCommand():
		onJoin(&cf)
	case scp.FullCommand():
		onSCP(&cf)
	case ls.FullCommand():
		onListNodes(&cf)
	case sites.FullCommand():
		onListSites(&cf)
	case agent.FullCommand():
		onAgentStart(&cf)
	case login.FullCommand():
		onLogin(&cf)
	}
}

// onAgentStart start ssh agent on a socket
func onAgentStart(cf *CLIConf) {
	tc, err := makeClient(cf)
	if err != nil {
		utils.FatalError(err)
	}
	socketAddr := utils.NetAddr(cf.AgentSocketAddr)
	if socketAddr.IsEmpty() {
		socketAddr = utils.NetAddr{AddrNetwork: "unix", Addr: filepath.Join(os.TempDir(), fmt.Sprintf("%v.socket", uuid.New()))}
	}
	// This makes teleport agent behave exactly like ssh-agent command,
	// the output and behavior matches the openssh behavior,
	// so users can do 'eval $(tsh agent --proxy=<addr>&)
	pid := os.Getpid()
	fmt.Printf(`
SSH_AUTH_SOCK=%v; export SSH_AUTH_SOCK;
SSH_AGENT_PID=%v; export SSH_AGENT_PID;
echo Agent pid %v;
`, socketAddr.Addr, pid, pid)
	agentServer := teleagent.NewServer()
	agentKeys, err := tc.LocalAgent().GetKeys()
	if err != nil {
		utils.FatalError(err)
	}
	// add existing keys to the running agent for ux purposes
	for _, key := range agentKeys {
		err := agentServer.Add(key)
		if err != nil {
			utils.FatalError(err)
		}
	}
	if err := agentServer.ListenAndServe(socketAddr); err != nil {
		utils.FatalError(err)
	}
}

// onLogin logs in with remote proxy and gets signed certificates
func onLogin(cf *CLIConf) {
	tc, err := makeClient(cf)
	if err != nil {
		utils.FatalError(err)
	}
	if err := tc.Login(); err != nil {
		utils.FatalError(err)
	}
	fmt.Println("\nlogged in successfully")
}

// onListNodes executes 'tsh ls' command
func onListNodes(cf *CLIConf) {
	tc, err := makeClient(cf)
	if err != nil {
		utils.FatalError(err)
	}
	servers, err := tc.ListNodes()
	if err != nil {
		utils.FatalError(err)
	}
	nodesView := func(nodes []services.Server) string {
		t := goterm.NewTable(0, 10, 5, ' ', 0)
		printHeader(t, []string{"Node Name", "Node ID", "Address", "Labels"})
		if len(nodes) == 0 {
			return t.String()
		}
		for _, n := range nodes {
			fmt.Fprintf(t, "%v\t%v\t%v\t%v\n", n.Hostname, n.ID, n.Addr, n.LabelsString())
		}
		return t.String()
	}
	fmt.Printf(nodesView(servers))
}

// onListSites executes 'tsh sites' command
func onListSites(cf *CLIConf) {
	tc, err := makeClient(cf)
	if err != nil {
		utils.FatalError(err)
	}
	proxyClient, err := tc.ConnectToProxy()
	if err != nil {
		utils.FatalError(err)
	}
	defer proxyClient.Close()
	sites, err := proxyClient.GetSites()
	if err != nil {
		utils.FatalError(err)
	}
	sitesView := func() string {
		t := goterm.NewTable(0, 10, 5, ' ', 0)
		printHeader(t, []string{"Site Name", "Status", "Last Connected"})
		if len(sites) == 0 {
			return t.String()
		}
		for _, site := range sites {
			fmt.Fprintf(t, "%v\t%v\t%v\n", site.Name, site.Status, site.LastConnected)
		}
		return t.String()
	}
	fmt.Printf(sitesView())
}

// onSSH executes 'tsh ssh' command
func onSSH(cf *CLIConf) {
	tc, err := makeClient(cf)
	if err != nil {
		utils.FatalError(err)
	}

	if err = tc.SSH(cf.RemoteCommand, cf.LocalExec, nil); err != nil {
		utils.FatalError(err)
	}
}

// onJoin executes 'ssh join' command
func onJoin(cf *CLIConf) {
	tc, err := makeClient(cf)
	if err != nil {
		utils.FatalError(err)
	}
	if err = tc.Join(string(cf.SessionID), nil); err != nil {
		utils.FatalError(err)
	}
}

// onSCP executes 'tsh scp' command
func onSCP(cf *CLIConf) {
	tc, err := makeClient(cf)
	if err != nil {
		utils.FatalError(err)
	}
	if err := tc.SCP(cf.CopySpec, int(cf.NodePort), cf.RecursiveCopy); err != nil {
		utils.FatalError(err)
	}
}

// makeClient takes the command-line configuration and constructs & returns
// a fully configured TeleportClient object
func makeClient(cf *CLIConf) (tc *client.TeleportClient, err error) {
	// apply defults
	if cf.NodePort == 0 {
		cf.NodePort = defaults.SSHServerListenPort
	}
	if cf.MinsToLive == 0 {
		cf.MinsToLive = int32(defaults.CertDuration / time.Minute)
	}

	// split login & host
	hostLogin := cf.Login
	var labels map[string]string
	if cf.UserHost != "" {
		parts := strings.Split(cf.UserHost, "@")
		if len(parts) > 1 {
			hostLogin = parts[0]
			cf.UserHost = parts[1]
		}
		// see if remote host is specified as a set of labels
		if strings.Contains(cf.UserHost, "=") {
			labels, err = client.ParseLabelSpec(cf.UserHost)
			if err != nil {
				return nil, err
			}
		}
	}
	fPorts, err := parsePortForwardSpec(cf.LocalForwardPorts)
	if err != nil {
		return nil, err
	}

	// prep client config:
	c := &client.Config{
		Output:             os.Stdout,
		Login:              cf.Login,
		ProxyHost:          cf.Proxy,
		Host:               cf.UserHost,
		HostPort:           int(cf.NodePort),
		HostLogin:          hostLogin,
		Labels:             labels,
		KeyTTL:             time.Minute * time.Duration(cf.MinsToLive),
		InsecureSkipVerify: cf.InsecureSkipVerify,
		LocalForwardPorts:  fPorts,
		ConnectorID:        cf.ExternalAuth,
		SiteName:           cf.SiteName,
	}
	return client.NewClient(c)
}

func onVersion() {
	utils.PrintVersion()
}

func printHeader(t *goterm.Table, cols []string) {
	dots := make([]string, len(cols))
	for i := range dots {
		dots[i] = strings.Repeat("-", len(cols[i]))
	}
	fmt.Fprint(t, strings.Join(cols, "\t")+"\n")
	fmt.Fprint(t, strings.Join(dots, "\t")+"\n")
}

// parsePortForwardSpec parses parameter to -L flag, i.e. strings like "[ip]:80:remote.host:3000"
func parsePortForwardSpec(spec []string) (ports []client.ForwardedPort, err error) {
	if len(spec) == 0 {
		return ports, nil
	}
	const errTemplate = "Invalid port forwarding spec: '%s'. Sould be like `80:remote.host:80`"
	ports = make([]client.ForwardedPort, len(spec), len(spec))

	for i, str := range spec {
		parts := strings.Split(str, ":")
		if len(parts) < 3 || len(parts) > 4 {
			return nil, fmt.Errorf(errTemplate, str)
		}
		if len(parts) == 3 {
			parts = append([]string{"127.0.0.1"}, parts...)
		}
		p := &ports[i]
		p.SrcIP = parts[0]
		p.SrcPort, err = strconv.Atoi(parts[1])
		if err != nil {
			return nil, fmt.Errorf(errTemplate, str)
		}
		p.DestHost = parts[2]
		p.DestPort, err = strconv.Atoi(parts[3])
		if err != nil {
			return nil, fmt.Errorf(errTemplate, str)
		}
	}
	return ports, nil
}
