/*
Copyright 2020-2021 Gravitational, Inc.

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
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gravitational/kingpin"
	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/api/profile"
	"github.com/gravitational/teleport/api/types"
	apiutils "github.com/gravitational/teleport/api/utils"
	"github.com/gravitational/teleport/api/utils/keypaths"
	"github.com/gravitational/teleport/lib/asciitable"
	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/kube/kubeconfig"
	kubeutils "github.com/gravitational/teleport/lib/kube/utils"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/cli-runtime/pkg/resource"
	coreclient "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/pkg/apis/clientauthentication"
	clientauthv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	"k8s.io/kubectl/pkg/cmd/util/podcmd"
	"k8s.io/kubectl/pkg/polymorphichelpers"
	"k8s.io/kubectl/pkg/scheme"
	"k8s.io/kubectl/pkg/util/term"
)

type kubeCommands struct {
	credentials *kubeCredentialsCommand
	ls          *kubeLSCommand
	login       *kubeLoginCommand
	sessions    *kubeSessionsCommand
	exec        *kubeExecCommand
	join        *kubeJoinCommand
}

func newKubeCommand(app *kingpin.Application) kubeCommands {
	kube := app.Command("kube", "Manage available kubernetes clusters")
	cmds := kubeCommands{
		credentials: newKubeCredentialsCommand(kube),
		ls:          newKubeLSCommand(kube),
		login:       newKubeLoginCommand(kube),
		sessions:    newKubeSessionsCommand(kube),
		exec:        newKubeExecCommand(kube),
		join:        newKubeJoinCommand(kube),
	}
	return cmds
}

type kubeJoinCommand struct {
	*kingpin.CmdClause
	session  string
	mode     string
	siteName string
}

func newKubeJoinCommand(parent *kingpin.CmdClause) *kubeJoinCommand {
	c := &kubeJoinCommand{
		CmdClause: parent.Command("join", "Join an active Kubernetes session."),
	}

	c.Flag("mode", "Mode of joining the session, valid modes are observer and moderator").Short('m').Default("moderator").StringVar(&c.mode)
	c.Flag("cluster", clusterHelp).Short('c').StringVar(&c.siteName)
	c.Arg("session", "The ID of the target session.").Required().StringVar(&c.session)
	return c
}

func (c *kubeJoinCommand) getSessionMeta(ctx context.Context, tc *client.TeleportClient) (types.SessionTracker, error) {
	sessions, err := tc.GetActiveSessions(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	for _, session := range sessions {
		if session.GetSessionID() == c.session {
			return session, nil
		}
	}

	return nil, trace.NotFound("session %q not found", c.session)
}

func (c *kubeJoinCommand) run(cf *CLIConf) error {
	if err := validateParticipantMode(types.SessionParticipantMode(c.mode)); err != nil {
		return trace.Wrap(err)
	}

	cf.SiteName = c.siteName
	tc, err := makeClient(cf, true)
	if err != nil {
		return trace.Wrap(err)
	}

	meta, err := c.getSessionMeta(cf.Context, tc)
	if err != nil {
		return trace.Wrap(err)
	}

	cluster := meta.GetClustername()
	kubeCluster := meta.GetKubeCluster()
	var k *client.Key

	// Try loading existing keys.
	k, err = tc.LocalAgent().GetKey(cluster, client.WithKubeCerts{})
	if err != nil && !trace.IsNotFound(err) {
		return trace.Wrap(err)
	}

	// Loaded existing credentials and have a cert for this cluster? Return it
	// right away.
	if err == nil {
		crt, err := k.KubeTLSCertificate(kubeCluster)
		if err != nil && !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}
		if crt != nil && time.Until(crt.NotAfter) > time.Minute {
			log.Debugf("Re-using existing TLS cert for kubernetes cluster %q", kubeCluster)
		} else {
			err = client.RetryWithRelogin(cf.Context, tc, func() error {
				var err error
				k, err = tc.IssueUserCertsWithMFA(cf.Context, client.ReissueParams{
					RouteToCluster:    cluster,
					KubernetesCluster: kubeCluster,
				})

				return trace.Wrap(err)
			})

			if err != nil {
				return trace.Wrap(err)
			}

			// Cache the new cert on disk for reuse.
			if _, err := tc.LocalAgent().AddKey(k); err != nil {
				return trace.Wrap(err)
			}
		}
		// Otherwise, cert for this k8s cluster is missing or expired. Request
		// a new one.
	}

	if _, err := tc.Ping(cf.Context); err != nil {
		return trace.Wrap(err)
	}

	if tc.KubeProxyAddr == "" {
		// Kubernetes support disabled, don't touch kubeconfig.
		return trace.AccessDenied("this cluster does not support kubernetes")
	}

	kubeStatus, err := fetchKubeStatus(cf.Context, tc)
	if err != nil {
		return trace.Wrap(err)
	}

	session, err := client.NewKubeSession(cf.Context, tc, meta, k, tc.KubeProxyAddr, kubeStatus.tlsServerName, types.SessionParticipantMode(c.mode))
	if err != nil {
		return trace.Wrap(err)
	}

	session.Wait()
	return nil
}

// RemoteExecutor defines the interface accepted by the Exec command - provided for test stubbing
type RemoteExecutor interface {
	Execute(method string, url *url.URL, config *restclient.Config, stdin io.Reader, stdout, stderr io.Writer, tty bool, terminalSizeQueue remotecommand.TerminalSizeQueue) error
}

// DefaultRemoteExecutor is the standard implementation of remote command execution
type DefaultRemoteExecutor struct{}

func (*DefaultRemoteExecutor) Execute(method string, url *url.URL, config *restclient.Config, stdin io.Reader, stdout, stderr io.Writer, tty bool, terminalSizeQueue remotecommand.TerminalSizeQueue) error {
	exec, err := remotecommand.NewSPDYExecutor(config, method, url)
	if err != nil {
		return err
	}
	return exec.Stream(remotecommand.StreamOptions{
		Stdin:             stdin,
		Stdout:            stdout,
		Stderr:            stderr,
		Tty:               tty,
		TerminalSizeQueue: terminalSizeQueue,
	})
}

type StreamOptions struct {
	Namespace     string
	PodName       string
	ContainerName string
	Stdin         bool
	TTY           bool
	// minimize unnecessary output
	Quiet bool

	genericclioptions.IOStreams

	overrideStreams func() (io.ReadCloser, io.Writer, io.Writer)
	isTerminalIn    func(t term.TTY) bool
}

func (o *StreamOptions) SetupTTY() term.TTY {
	t := term.TTY{
		Out: o.Out,
	}

	if !o.Stdin {
		// need to nil out o.In to make sure we don't create a stream for stdin
		o.In = nil
		o.TTY = false
		return t
	}

	t.In = o.In
	if !o.TTY {
		return t
	}

	if o.isTerminalIn == nil {
		o.isTerminalIn = func(tty term.TTY) bool {
			return tty.IsTerminalIn()
		}
	}
	if !o.isTerminalIn(t) {
		o.TTY = false

		if !o.Quiet && o.ErrOut != nil {
			fmt.Fprintln(o.ErrOut, "Unable to use a TTY - input is not a terminal or the right kind of file")
		}

		return t
	}

	// if we get to here, the user wants to attach stdin, wants a TTY, and o.In is a terminal, so we
	// can safely set t.Raw to true
	t.Raw = true

	stdin, stdout, _ := o.overrideStreams()
	o.In = stdin
	t.In = stdin
	if o.Out != nil {
		o.Out = stdout
		t.Out = stdout
	}

	return t
}

type ExecOptions struct {
	StreamOptions
	resource.FilenameOptions

	ResourceName     string
	Command          []string
	EnforceNamespace bool

	Builder          func() *resource.Builder
	ExecutablePodFn  polymorphichelpers.AttachablePodForObjectFunc
	restClientGetter genericclioptions.RESTClientGetter

	Pod                            *corev1.Pod
	Executor                       RemoteExecutor
	PodClient                      coreclient.PodsGetter
	GetPodTimeout                  time.Duration
	Config                         *restclient.Config
	displayParticipantRequirements bool
}

// Run executes a validated remote execution against a pod.
func (p *ExecOptions) Run() error {
	var err error
	if len(p.PodName) != 0 {
		p.Pod, err = p.PodClient.Pods(p.Namespace).Get(context.TODO(), p.PodName, metav1.GetOptions{})
		if err != nil {
			return err
		}
	} else {
		builder := p.Builder().
			WithScheme(scheme.Scheme, scheme.Scheme.PrioritizedVersionsAllGroups()...).
			FilenameParam(p.EnforceNamespace, &p.FilenameOptions).
			NamespaceParam(p.Namespace).DefaultNamespace()
		if len(p.ResourceName) > 0 {
			builder = builder.ResourceNames("pods", p.ResourceName)
		}

		obj, err := builder.Do().Object()
		if err != nil {
			return err
		}

		p.Pod, err = p.ExecutablePodFn(p.restClientGetter, obj, p.GetPodTimeout)
		if err != nil {
			return err
		}
	}

	pod := p.Pod

	if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
		return fmt.Errorf("cannot exec into a container in a completed pod; current phase is %s", pod.Status.Phase)
	}

	containerName := p.ContainerName
	if len(containerName) == 0 {
		container, err := podcmd.FindOrDefaultContainerByName(pod, containerName, p.Quiet, p.ErrOut)
		if err != nil {
			return err
		}
		containerName = container.Name
	}

	// ensure we can recover the terminal while attached
	t := p.SetupTTY()

	var sizeQueue remotecommand.TerminalSizeQueue
	if t.Raw {
		// this call spawns a goroutine to monitor/update the terminal size
		sizeQueue = t.MonitorSize(t.GetSize())

		// unset p.Err if it was previously set because both stdout and stderr go over p.Out when tty is
		// true
		p.ErrOut = nil
	}

	fn := func() error {
		restClient, err := restclient.RESTClientFor(p.Config)
		if err != nil {
			return err
		}

		req := restClient.Post().
			Resource("pods").
			Name(pod.Name).
			Namespace(pod.Namespace).
			SubResource("exec").
			Param("displayParticipantRequirements", strconv.FormatBool(p.displayParticipantRequirements))
		req.VersionedParams(&corev1.PodExecOptions{
			Container: containerName,
			Command:   p.Command,
			Stdin:     p.Stdin,
			Stdout:    p.Out != nil,
			Stderr:    p.ErrOut != nil,
			TTY:       t.Raw,
		}, scheme.ParameterCodec)

		return p.Executor.Execute("POST", req.URL(), p.Config, p.In, p.Out, p.ErrOut, t.Raw, sizeQueue)
	}

	return trace.Wrap(t.Safe(fn))
}

type kubeExecCommand struct {
	*kingpin.CmdClause
	target                         string
	container                      string
	filename                       string
	quiet                          bool
	stdin                          bool
	tty                            bool
	reason                         string
	invited                        string
	command                        []string
	displayParticipantRequirements bool
}

func newKubeExecCommand(parent *kingpin.CmdClause) *kubeExecCommand {
	c := &kubeExecCommand{
		CmdClause: parent.Command("exec", "Execute a command in a kubernetes pod"),
	}

	c.Flag("container", "Container name. If omitted, use the kubectl.kubernetes.io/default-container annotation for selecting the container to be attached or the first container in the pod will be chosen").Short('c').StringVar(&c.container)
	c.Flag("filename", "to use to exec into the resource").Short('f').StringVar(&c.filename)
	c.Flag("quiet", "Only print output from the remote session").Short('q').BoolVar(&c.quiet)
	c.Flag("stdin", "Pass stdin to the container").Short('s').BoolVar(&c.stdin)
	c.Flag("tty", "Stdin is a TTY").Short('t').BoolVar(&c.tty)
	c.Flag("reason", "The purpose of the session.").StringVar(&c.reason)
	c.Flag("invite", "A comma separated list of people to mark as invited for the session.").StringVar(&c.invited)
	c.Flag("participant-req", "Displays a verbose list of required participants in a moderated session.").BoolVar(&c.displayParticipantRequirements)
	c.Arg("target", "Pod or deployment name").Required().StringVar(&c.target)
	c.Arg("command", "Command to execute in the container").Required().StringsVar(&c.command)
	return c
}

func (c *kubeExecCommand) run(cf *CLIConf) error {
	var p ExecOptions
	var err error

	p.IOStreams = genericclioptions.IOStreams{
		In:     os.Stdin,
		Out:    os.Stdout,
		ErrOut: os.Stderr,
	}
	kubeConfigFlags := genericclioptions.NewConfigFlags(true).WithDeprecatedPasswordFlag()
	matchVersionKubeConfigFlags := cmdutil.NewMatchVersionFlags(kubeConfigFlags)
	f := cmdutil.NewFactory(matchVersionKubeConfigFlags)
	p.ResourceName = c.target
	p.ContainerName = c.container
	p.Quiet = c.quiet
	p.Stdin = c.stdin
	p.TTY = c.tty
	p.Command = c.command
	p.ExecutablePodFn = polymorphichelpers.AttachablePodForObjectFn
	p.GetPodTimeout = time.Second * 5
	p.Builder = f.NewBuilder
	p.restClientGetter = f
	p.Executor = &DefaultRemoteExecutor{}
	p.displayParticipantRequirements = c.displayParticipantRequirements
	p.Namespace, p.EnforceNamespace, err = f.ToRawKubeConfigLoader().Namespace()
	if err != nil {
		return trace.Wrap(err)
	}

	p.Config, err = f.ToRESTConfig()
	if err != nil {
		return trace.Wrap(err)
	}

	clientset, err := f.KubernetesClientSet()
	if err != nil {
		return trace.Wrap(err)
	}

	p.PodClient = clientset.CoreV1()
	return trace.Wrap(p.Run())
}

type kubeSessionsCommand struct {
	*kingpin.CmdClause
}

func newKubeSessionsCommand(parent *kingpin.CmdClause) *kubeSessionsCommand {
	c := &kubeSessionsCommand{
		CmdClause: parent.Command("sessions", "Get a list of active kubernetes sessions."),
	}

	return c
}

func (c *kubeSessionsCommand) run(cf *CLIConf) error {
	tc, err := makeClient(cf, true)
	if err != nil {
		return trace.Wrap(err)
	}

	sessions, err := tc.GetActiveSessions(cf.Context)
	if err != nil {
		return trace.Wrap(err)
	}

	filteredSessions := make([]types.SessionTracker, 0)
	for _, session := range sessions {
		if session.GetSessionKind() == types.KubernetesSessionKind {
			filteredSessions = append(filteredSessions, session)
		}
	}

	sort.Slice(filteredSessions, func(i, j int) bool {
		return filteredSessions[i].GetCreated().Before(filteredSessions[j].GetCreated())
	})

	printSessions(filteredSessions)
	return nil
}

func printSessions(sessions []types.SessionTracker) {
	table := asciitable.MakeTable([]string{"ID", "State", "Created", "Hostname", "Address", "Login", "Reason"})
	for _, s := range sessions {
		table.AddRow([]string{s.GetSessionID(), s.GetState().String(), s.GetCreated().Format(time.RFC3339), s.GetHostname(), s.GetAddress(), s.GetLogin(), s.GetReason()})
	}

	output := table.AsBuffer().String()
	print(output)
}

type kubeCredentialsCommand struct {
	*kingpin.CmdClause
	kubeCluster     string
	teleportCluster string
}

func newKubeCredentialsCommand(parent *kingpin.CmdClause) *kubeCredentialsCommand {
	c := &kubeCredentialsCommand{
		// This command is always hidden. It's called from the kubeconfig that
		// tsh generates and never by users directly.
		CmdClause: parent.Command("credentials", "Get credentials for kubectl access").Hidden(),
	}
	c.Flag("teleport-cluster", "Name of the teleport cluster to get credentials for.").Required().StringVar(&c.teleportCluster)
	c.Flag("kube-cluster", "Name of the kubernetes cluster to get credentials for.").Required().StringVar(&c.kubeCluster)
	return c
}

func (c *kubeCredentialsCommand) run(cf *CLIConf) error {
	tc, err := makeClient(cf, true)
	if err != nil {
		return trace.Wrap(err)
	}

	// Try loading existing keys.
	k, err := tc.LocalAgent().GetKey(c.teleportCluster, client.WithKubeCerts{})
	if err != nil && !trace.IsNotFound(err) {
		return trace.Wrap(err)
	}
	// Loaded existing credentials and have a cert for this cluster? Return it
	// right away.
	if err == nil {
		crt, err := k.KubeTLSCertificate(c.kubeCluster)
		if err != nil && !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}
		if crt != nil && time.Until(crt.NotAfter) > time.Minute {
			log.Debugf("Re-using existing TLS cert for kubernetes cluster %q", c.kubeCluster)
			return c.writeResponse(k, c.kubeCluster)
		}
		// Otherwise, cert for this k8s cluster is missing or expired. Request
		// a new one.
	}

	log.Debugf("Requesting TLS cert for kubernetes cluster %q", c.kubeCluster)
	err = client.RetryWithRelogin(cf.Context, tc, func() error {
		var err error
		k, err = tc.IssueUserCertsWithMFA(cf.Context, client.ReissueParams{
			RouteToCluster:    c.teleportCluster,
			KubernetesCluster: c.kubeCluster,
		})
		return err
	})
	if err != nil {
		return trace.Wrap(err)
	}

	// Cache the new cert on disk for reuse.
	if _, err := tc.LocalAgent().AddKey(k); err != nil {
		return trace.Wrap(err)
	}

	return c.writeResponse(k, c.kubeCluster)
}

func (c *kubeCredentialsCommand) writeResponse(key *client.Key, kubeClusterName string) error {
	crt, err := key.KubeTLSCertificate(kubeClusterName)
	if err != nil {
		return trace.Wrap(err)
	}
	expiry := crt.NotAfter
	// Indicate slightly earlier expiration to avoid the cert expiring
	// mid-request, if possible.
	if time.Until(expiry) > time.Minute {
		expiry = expiry.Add(-1 * time.Minute)
	}
	resp := &clientauthentication.ExecCredential{
		Status: &clientauthentication.ExecCredentialStatus{
			ExpirationTimestamp:   &metav1.Time{Time: expiry},
			ClientCertificateData: string(key.KubeTLSCerts[kubeClusterName]),
			ClientKeyData:         string(key.Priv),
		},
	}
	data, err := runtime.Encode(kubeCodecs.LegacyCodec(kubeGroupVersion), resp)
	if err != nil {
		return trace.Wrap(err)
	}
	fmt.Println(string(data))
	return nil
}

type kubeLSCommand struct {
	*kingpin.CmdClause
	labels         string
	predicateExpr  string
	searchKeywords string
}

func newKubeLSCommand(parent *kingpin.CmdClause) *kubeLSCommand {
	c := &kubeLSCommand{
		CmdClause: parent.Command("ls", "Get a list of kubernetes clusters"),
	}
	c.Flag("search", searchHelp).StringVar(&c.searchKeywords)
	c.Flag("query", queryHelp).StringVar(&c.predicateExpr)
	c.Arg("labels", labelHelp).StringVar(&c.labels)
	return c
}

func (c *kubeLSCommand) run(cf *CLIConf) error {
	cf.SearchKeywords = c.searchKeywords
	cf.UserHost = c.labels
	cf.PredicateExpression = c.predicateExpr

	tc, err := makeClient(cf, true)
	if err != nil {
		return trace.Wrap(err)
	}
	currentTeleportCluster, kubeClusters, err := fetchKubeClusters(cf.Context, tc)
	if err != nil {
		return trace.Wrap(err)
	}

	selectedCluster := selectedKubeCluster(currentTeleportCluster)

	var t asciitable.Table
	if cf.Quiet {
		t = asciitable.MakeHeadlessTable(2)
	} else {
		t = asciitable.MakeTable([]string{"Kube Cluster Name", "Selected"})
	}
	for _, cluster := range kubeClusters {
		var selectedMark string
		if cluster == selectedCluster {
			selectedMark = "*"
		}
		t.AddRow([]string{cluster, selectedMark})
	}
	fmt.Println(t.AsBuffer().String())

	return nil
}

func selectedKubeCluster(currentTeleportCluster string) string {
	kc, err := kubeconfig.Load("")
	if err != nil {
		log.WithError(err).Warning("Failed parsing existing kubeconfig")
		return ""
	}
	return kubeconfig.KubeClusterFromContext(kc.CurrentContext, currentTeleportCluster)
}

type kubeLoginCommand struct {
	*kingpin.CmdClause
	kubeCluster string
}

func newKubeLoginCommand(parent *kingpin.CmdClause) *kubeLoginCommand {
	c := &kubeLoginCommand{
		CmdClause: parent.Command("login", "Login to a kubernetes cluster"),
	}
	c.Arg("kube-cluster", "Name of the kubernetes cluster to login to. Check 'tsh kube ls' for a list of available clusters.").Required().StringVar(&c.kubeCluster)
	return c
}

func (c *kubeLoginCommand) run(cf *CLIConf) error {
	// Set CLIConf.KubernetesCluster so that the kube cluster's context is automatically selected.
	cf.KubernetesCluster = c.kubeCluster

	tc, err := makeClient(cf, true)
	if err != nil {
		return trace.Wrap(err)
	}
	// Check that this kube cluster exists.
	currentTeleportCluster, kubeClusters, err := fetchKubeClusters(cf.Context, tc)
	if err != nil {
		return trace.Wrap(err)
	}
	if !apiutils.SliceContainsStr(kubeClusters, c.kubeCluster) {
		return trace.NotFound("kubernetes cluster %q not found, check 'tsh kube ls' for a list of known clusters", c.kubeCluster)
	}

	// Try updating the active kubeconfig context.
	if err := kubeconfig.SelectContext(currentTeleportCluster, c.kubeCluster); err != nil {
		if !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}
		// We know that this kube cluster exists from the API, but there isn't
		// a context for it in the current kubeconfig. This is probably a new
		// cluster, added after the last 'tsh login'.
		//
		// Re-generate kubeconfig contexts and try selecting this kube cluster
		// again.
		if err := updateKubeConfig(cf, tc, ""); err != nil {
			return trace.Wrap(err)
		}
	}

	// Generate a profile specific kubeconfig which can be used
	// by setting the kubeconfig environment variable (with `tsh env`)
	profileKubeconfigPath := keypaths.KubeConfigPath(
		profile.FullProfilePath(cf.HomePath), tc.WebProxyHost(), tc.Username, currentTeleportCluster, c.kubeCluster,
	)
	if err := updateKubeConfig(cf, tc, profileKubeconfigPath); err != nil {
		return trace.Wrap(err)
	}

	fmt.Printf("Logged into kubernetes cluster %q\n", c.kubeCluster)
	return nil
}

func fetchKubeClusters(ctx context.Context, tc *client.TeleportClient) (teleportCluster string, kubeClusters []string, err error) {
	err = client.RetryWithRelogin(ctx, tc, func() error {
		pc, err := tc.ConnectToProxy(ctx)
		if err != nil {
			return trace.Wrap(err)
		}
		defer pc.Close()
		ac, err := pc.ConnectToCurrentCluster(ctx, true)
		if err != nil {
			return trace.Wrap(err)
		}
		defer ac.Close()

		cn, err := ac.GetClusterName()
		if err != nil {
			return trace.Wrap(err)
		}
		teleportCluster = cn.GetClusterName()

		kubeClusters, err = kubeutils.ListKubeClusterNamesWithFilters(ctx, ac, proto.ListResourcesRequest{
			SearchKeywords:      tc.SearchKeywords,
			PredicateExpression: tc.PredicateExpression,
			Labels:              tc.Labels,
		})
		if err != nil {
			// ListResources for kube service not available, provide fallback.
			// Fallback does not support filters, so if users
			// provide them, it does nothing.
			//
			// DELETE IN 11.0.0
			if trace.IsNotImplemented(err) {
				kubeClusters, err = kubeutils.KubeClusterNames(ctx, ac)
				if err != nil {
					return trace.Wrap(err)
				}
				return nil
			}
			return trace.Wrap(err)
		}

		return nil
	})
	if err != nil {
		return "", nil, trace.Wrap(err)
	}
	return teleportCluster, kubeClusters, nil
}

// kubernetesStatus holds teleport client information necessary to populate the user's kubeconfig.
type kubernetesStatus struct {
	clusterAddr         string
	teleportClusterName string
	kubeClusters        []string
	credentials         *client.Key
	tlsServerName       string
}

// fetchKubeStatus returns a kubernetesStatus populated from the given TeleportClient.
func fetchKubeStatus(ctx context.Context, tc *client.TeleportClient) (*kubernetesStatus, error) {
	var err error
	kubeStatus := &kubernetesStatus{
		clusterAddr: tc.KubeClusterAddr(),
	}
	kubeStatus.credentials, err = tc.LocalAgent().GetCoreKey()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	kubeStatus.teleportClusterName, kubeStatus.kubeClusters, err = fetchKubeClusters(ctx, tc)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if tc.TLSRoutingEnabled {
		kubeStatus.tlsServerName = getKubeTLSServerName(tc)
	}

	return kubeStatus, nil
}

// getKubeTLSServerName returns k8s server name used in KUBECONFIG to leverage TLS Routing.
func getKubeTLSServerName(tc *client.TeleportClient) string {
	k8host, _ := tc.KubeProxyHostPort()

	isIPFormat := net.ParseIP(k8host) != nil
	if k8host == "" || isIPFormat {
		// If proxy is configured without public_addr set the ServerName to the 'kube.teleport.cluster.local' value.
		// The k8s server name needs to be a valid hostname but when public_addr is missing from proxy settings
		// the web_listen_addr is used thus webHost will contain local proxy IP address like: 0.0.0.0 or 127.0.0.1
		// TODO(smallinsky) UPGRADE IN 10.0. Switch to KubeTeleportProxyALPNPrefix instead.
		return addSubdomainPrefix(constants.APIDomain, constants.KubeSNIPrefix)
	}
	// TODO(smallinsky) UPGRADE IN 10.0. Switch to KubeTeleportProxyALPNPrefix instead.
	return addSubdomainPrefix(k8host, constants.KubeSNIPrefix)
}

func addSubdomainPrefix(domain, prefix string) string {
	return fmt.Sprintf("%s%s", prefix, domain)
}

// buildKubeConfigUpdate returns a kubeconfig.Values suitable for updating the user's kubeconfig
// based on the CLI parameters and the given kubernetesStatus.
func buildKubeConfigUpdate(cf *CLIConf, kubeStatus *kubernetesStatus) (*kubeconfig.Values, error) {
	v := &kubeconfig.Values{
		ClusterAddr:         kubeStatus.clusterAddr,
		TeleportClusterName: kubeStatus.teleportClusterName,
		Credentials:         kubeStatus.credentials,
		ProxyAddr:           cf.Proxy,
		TLSServerName:       kubeStatus.tlsServerName,
	}

	if cf.executablePath == "" {
		// Don't know tsh path.
		// Fall back to the old kubeconfig, with static credentials from v.Credentials.
		return v, nil
	}

	if len(kubeStatus.kubeClusters) == 0 {
		// If there are no registered k8s clusters, we may have an older teleport cluster.
		// Fall back to the old kubeconfig, with static credentials from v.Credentials.
		log.Debug("Disabling exec plugin mode for kubeconfig because this Teleport cluster has no Kubernetes clusters.")
		return v, nil
	}

	v.Exec = &kubeconfig.ExecValues{
		TshBinaryPath:     cf.executablePath,
		TshBinaryInsecure: cf.InsecureSkipVerify,
		KubeClusters:      kubeStatus.kubeClusters,
		Env:               make(map[string]string),
	}

	if cf.HomePath != "" {
		v.Exec.Env[types.HomeEnvVar] = cf.HomePath
	}

	// Only switch the current context if kube-cluster is explicitly set on the command line.
	if cf.KubernetesCluster != "" {
		if !apiutils.SliceContainsStr(kubeStatus.kubeClusters, cf.KubernetesCluster) {
			return nil, trace.BadParameter("Kubernetes cluster %q is not registered in this Teleport cluster; you can list registered Kubernetes clusters using 'tsh kube ls'.", cf.KubernetesCluster)
		}
		v.Exec.SelectCluster = cf.KubernetesCluster
	}
	return v, nil
}

// updateKubeConfig adds Teleport configuration to the users's kubeconfig based on the CLI
// parameters and the kubernetes services in the current Teleport cluster. If no path for
// the kubeconfig is given, it will use environment values or known defaults to get a path.
func updateKubeConfig(cf *CLIConf, tc *client.TeleportClient, path string) error {
	// Fetch proxy's advertised ports to check for k8s support.
	if _, err := tc.Ping(cf.Context); err != nil {
		return trace.Wrap(err)
	}
	if tc.KubeProxyAddr == "" {
		// Kubernetes support disabled, don't touch kubeconfig.
		return nil
	}

	kubeStatus, err := fetchKubeStatus(cf.Context, tc)
	if err != nil {
		return trace.Wrap(err)
	}

	values, err := buildKubeConfigUpdate(cf, kubeStatus)
	if err != nil {
		return trace.Wrap(err)
	}

	if path == "" {
		path = kubeconfig.PathFromEnv()
	}

	// If this is a profile specific kubeconfig, we only need
	// to put the selected kube cluster into the kubeconfig.
	isKubeConfig, err := keypaths.IsProfileKubeConfigPath(path)
	if err != nil {
		return trace.Wrap(err)
	}
	if isKubeConfig {
		if !strings.Contains(path, cf.KubernetesCluster) {
			return trace.BadParameter("profile specific kubeconfig is in use, run 'eval $(tsh env --unset)' to switch contexts to another kube cluster")
		}
		values.Exec.KubeClusters = []string{cf.KubernetesCluster}
	}

	return trace.Wrap(kubeconfig.Update(path, *values))
}

// Required magic boilerplate to use the k8s encoder.

var (
	kubeScheme       = runtime.NewScheme()
	kubeCodecs       = serializer.NewCodecFactory(kubeScheme)
	kubeGroupVersion = schema.GroupVersion{
		Group:   "client.authentication.k8s.io",
		Version: "v1beta1",
	}
)

func init() {
	metav1.AddToGroupVersion(kubeScheme, schema.GroupVersion{Version: "v1"})
	clientauthv1beta1.AddToScheme(kubeScheme)
	clientauthentication.AddToScheme(kubeScheme)
}
