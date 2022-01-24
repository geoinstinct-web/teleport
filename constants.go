/*
Copyright 2018-2019 Gravitational, Inc.

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

package teleport

import (
	"fmt"
	"strings"
	"time"

	"github.com/coreos/go-semver/semver"
)

// WebAPIVersion is a current webapi version
const WebAPIVersion = "v1"

// ForeverTTL means that object TTL will not expire unless deleted
const ForeverTTL time.Duration = 0

const (
	// SSHAuthSock is the environment variable pointing to the
	// Unix socket the SSH agent is running on.
	SSHAuthSock = "SSH_AUTH_SOCK"
	// SSHAgentPID is the environment variable pointing to the agent
	// process ID
	SSHAgentPID = "SSH_AGENT_PID"

	// SSHTeleportUser is the current Teleport user that is logged in.
	SSHTeleportUser = "SSH_TELEPORT_USER"

	// SSHSessionWebproxyAddr is the address the web proxy.
	SSHSessionWebproxyAddr = "SSH_SESSION_WEBPROXY_ADDR"

	// SSHTeleportClusterName is the name of the cluster this node belongs to.
	SSHTeleportClusterName = "SSH_TELEPORT_CLUSTER_NAME"

	// SSHTeleportHostUUID is the UUID of the host.
	SSHTeleportHostUUID = "SSH_TELEPORT_HOST_UUID"

	// SSHSessionID is the UUID of the current session.
	SSHSessionID = "SSH_SESSION_ID"
)

const (
	// HTTPNextProtoTLS is the NPN/ALPN protocol negotiated during
	// HTTP/1.1.'s TLS setup.
	// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
	HTTPNextProtoTLS = "http/1.1"
)

const (
	// HTTPSProxy is an environment variable pointing to a HTTPS proxy.
	HTTPSProxy = "HTTPS_PROXY"

	// HTTPProxy is an environment variable pointing to a HTTP proxy.
	HTTPProxy = "HTTP_PROXY"

	// NoProxy is an environment variable matching the cases
	// when HTTPS_PROXY or HTTP_PROXY is ignored
	NoProxy = "NO_PROXY"
)

const (
	// TOTPValidityPeriod is the number of seconds a TOTP token is valid.
	TOTPValidityPeriod uint = 30

	// TOTPSkew adds that many periods before and after to the validity window.
	TOTPSkew uint = 1
)

const (
	// ComponentMemory is a memory backend
	ComponentMemory = "memory"

	// ComponentAuthority is a TLS and an SSH certificate authority
	ComponentAuthority = "ca"

	// ComponentProcess is a main control process
	ComponentProcess = "proc"

	// ComponentServer is a server subcomponent of some services
	ComponentServer = "server"

	// ComponentACME is ACME protocol controller
	ComponentACME = "acme"

	// ComponentReverseTunnelServer is reverse tunnel server
	// that together with agent establish a bi-directional SSH revers tunnel
	// to bypass firewall restrictions
	ComponentReverseTunnelServer = "proxy:server"

	// ComponentReverseTunnelAgent is reverse tunnel agent
	// that together with server establish a bi-directional SSH revers tunnel
	// to bypass firewall restrictions
	ComponentReverseTunnelAgent = "proxy:agent"

	// ComponentLabel is a component label name used in reporting
	ComponentLabel = "component"

	// ComponentProxyKube is a kubernetes proxy
	ComponentProxyKube = "proxy:kube"

	// ComponentAuth is the cluster CA node (auth server API)
	ComponentAuth = "auth"

	// ComponentGRPC is grpc server
	ComponentGRPC = "grpc"

	// ComponentMigrate is responsible for data migrations
	ComponentMigrate = "migrate"

	// ComponentNode is SSH node (SSH server serving requests)
	ComponentNode = "node"

	// ComponentForwardingNode is SSH node (SSH server serving requests)
	ComponentForwardingNode = "node:forward"

	// ComponentProxy is SSH proxy (SSH server forwarding connections)
	ComponentProxy = "proxy"

	// ComponentApp is the application proxy service.
	ComponentApp = "app:service"

	// ComponentDatabase is the database proxy service.
	ComponentDatabase = "db:service"

	// ComponentAppProxy is the application handler within the web proxy service.
	ComponentAppProxy = "app:web"

	// ComponentWebProxy is the web handler within the web proxy service.
	ComponentWebProxy = "web"

	// ComponentDiagnostic is a diagnostic service
	ComponentDiagnostic = "diag"

	// ComponentClient is a client
	ComponentClient = "client"

	// ComponentTunClient is a tunnel client
	ComponentTunClient = "client:tunnel"

	// ComponentCache is a cache component
	ComponentCache = "cache"

	// ComponentBackend is a backend component
	ComponentBackend = "backend"

	// ComponentCachingClient is a caching auth client
	ComponentCachingClient = "client:cache"

	// ComponentSubsystemProxy is the proxy subsystem.
	ComponentSubsystemProxy = "subsystem:proxy"

	// ComponentLocalTerm is a terminal on a regular SSH node.
	ComponentLocalTerm = "term:local"

	// ComponentRemoteTerm is a terminal on a forwarding SSH node.
	ComponentRemoteTerm = "term:remote"

	// ComponentRemoteSubsystem is subsystem on a forwarding SSH node.
	ComponentRemoteSubsystem = "subsystem:remote"

	// ComponentAuditLog is audit log component
	ComponentAuditLog = "audit"

	// ComponentKeyAgent is an agent that has loaded the sessions keys and
	// certificates for a user connected to a proxy.
	ComponentKeyAgent = "keyagent"

	// ComponentKeyStore is all sessions keys and certificates a user has on disk
	// for all proxies.
	ComponentKeyStore = "keystore"

	// ComponentConnectProxy is the HTTP CONNECT proxy used to tunnel connection.
	ComponentConnectProxy = "http:proxy"

	// ComponentSOCKS is a SOCKS5 proxy.
	ComponentSOCKS = "socks"

	// ComponentKeyGen is the public/private keypair generator.
	ComponentKeyGen = "keygen"

	// ComponentFirestore represents firestore clients
	ComponentFirestore = "firestore"

	// ComponentSession is an active session.
	ComponentSession = "session"

	// ComponentDynamoDB represents dynamodb clients
	ComponentDynamoDB = "dynamodb"

	// Component pluggable authentication module (PAM)
	ComponentPAM = "pam"

	// ComponentUpload is a session recording upload server
	ComponentUpload = "upload"

	// ComponentWeb is a web server
	ComponentWeb = "web"

	// ComponentWebsocket is websocket server that the web client connects to.
	ComponentWebsocket = "websocket"

	// ComponentRBAC is role-based access control.
	ComponentRBAC = "rbac"

	// ComponentKeepAlive is keep-alive messages sent from clients to servers
	// and vice versa.
	ComponentKeepAlive = "keepalive"

	// ComponentTSH is the "tsh" binary.
	ComponentTSH = "tsh"

	// ComponentKubeClient is the Kubernetes client.
	ComponentKubeClient = "client:kube"

	// ComponentBuffer is in-memory event circular buffer
	// used to broadcast events to subscribers.
	ComponentBuffer = "buffer"

	// ComponentBPF is the eBPF packagae.
	ComponentBPF = "bpf"

	// ComponentRestrictedSession is restriction of user access to kernel objects
	ComponentRestrictedSession = "restrictedsess"

	// ComponentCgroup is the cgroup package.
	ComponentCgroup = "cgroups"

	// ComponentKube is an Kubernetes API gateway.
	ComponentKube = "kubernetes"

	// ComponentSAML is a SAML service provider.
	ComponentSAML = "saml"

	// ComponentMetrics is a metrics server
	ComponentMetrics = "metrics"

	// ComponentWindowsDesktop is a Windows desktop access server.
	ComponentWindowsDesktop = "windows_desktop"

	// DebugEnvVar tells tests to use verbose debug output
	DebugEnvVar = "DEBUG"

	// DebugAssetsPath allows users to set the path of the webassets if debug
	// mode is enabled.
	// For example,
	// `DEBUG=1 DEBUG_ASSETS_PATH=/path/to/webassets/ teleport start`.
	DebugAssetsPath = "DEBUG_ASSETS_PATH"

	// VerboseLogEnvVar forces all logs to be verbose (down to DEBUG level)
	VerboseLogsEnvVar = "TELEPORT_DEBUG"

	// IterationsEnvVar sets tests iterations to run
	IterationsEnvVar = "ITERATIONS"

	// DefaultTerminalWidth defines the default width of a server-side allocated
	// pseudo TTY
	DefaultTerminalWidth = 80

	// DefaultTerminalHeight defines the default height of a server-side allocated
	// pseudo TTY
	DefaultTerminalHeight = 25

	// SafeTerminalType is the fall-back TTY type to fall back to (when $TERM
	// is not defined)
	SafeTerminalType = "xterm"

	// DataDirParameterName is the name of the data dir configuration parameter passed
	// to all backends during initialization
	DataDirParameterName = "data_dir"

	// SSH request type to keep the connection alive. A client and a server keep
	// pining each other with it:
	KeepAliveReqType = "keepalive@openssh.com"

	// RecordingProxyReqType is the name of a global request which returns if
	// the proxy is recording sessions or not.
	RecordingProxyReqType = "recording-proxy@teleport.com"

	// JSON means JSON serialization format
	JSON = "json"

	// YAML means YAML serialization format
	YAML = "yaml"

	// Text means text serialization format
	Text = "text"

	// PTY is a raw pty session capture format
	PTY = "pty"

	// Names is for formatting node names in plain text
	Names = "names"

	// LinuxAdminGID is the ID of the standard adm group on linux
	LinuxAdminGID = 4

	// DirMaskSharedGroup is the mask for a directory accessible
	// by the owner and group
	DirMaskSharedGroup = 0770

	// FileMaskOwnerOnly is the file mask that allows read write access
	// to owers only
	FileMaskOwnerOnly = 0600

	// On means mode is on
	On = "on"

	// Off means mode is off
	Off = "off"

	// SchemeS3 is S3 file scheme, means upload or download to S3 like object
	// storage
	SchemeS3 = "s3"

	// SchemeGCS is GCS file scheme, means upload or download to GCS like object
	// storage
	SchemeGCS = "gs"

	// GCSTestURI turns on GCS tests
	GCSTestURI = "TEST_GCS_URI"

	// AWSRunTests turns on tests executed against AWS directly
	AWSRunTests = "TEST_AWS"

	// Region is AWS region parameter
	Region = "region"

	// Endpoint is an optional Host for non-AWS S3
	Endpoint = "endpoint"

	// Insecure is an optional switch to use HTTP instead of HTTPS
	Insecure = "insecure"

	// DisableServerSideEncryption is an optional switch to opt out of SSE in case the provider does not support it
	DisableServerSideEncryption = "disablesse"

	// ACL is the canned ACL to send to S3
	ACL = "acl"

	// SSEKMSKey is an optional switch to use an KMS CMK key for S3 SSE.
	SSEKMSKey = "sse_kms_key"

	// SchemeFile is a local disk file storage
	SchemeFile = "file"

	// SchemeStdout outputs audit log entries to stdout
	SchemeStdout = "stdout"

	// LogsDir is a log subdirectory for events and logs
	LogsDir = "log"

	// Syslog is a mode for syslog logging
	Syslog = "syslog"

	// HumanDateFormat is a human readable date formatting
	HumanDateFormat = "Jan _2 15:04 UTC"

	// HumanDateFormatMilli is a human readable date formatting with milliseconds
	HumanDateFormatMilli = "Jan _2 15:04:05.000 UTC"

	// DebugLevel is a debug logging level name
	DebugLevel = "debug"

	// MinimumEtcdVersion is the minimum version of etcd supported by Teleport
	MinimumEtcdVersion = "3.3.0"
)

// OTPType is the type of the One-time Password Algorithm.
type OTPType string

const (
	// TOTP means Time-based One-time Password Algorithm (for Two-Factor Authentication)
	TOTP = OTPType("totp")
	// HOTP means HMAC-based One-time Password Algorithm (for Two-Factor Authentication)
	HOTP = OTPType("hotp")
)

const (
	// These values are from https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest

	// OIDCPromptSelectAccount instructs the Authorization Server to
	// prompt the End-User to select a user account.
	OIDCPromptSelectAccount = "select_account"

	// OIDCAccessTypeOnline indicates that OIDC flow should be performed
	// with Authorization server and user connected online
	OIDCAccessTypeOnline = "online"
)

// Component generates "component:subcomponent1:subcomponent2" strings used
// in debugging
func Component(components ...string) string {
	return strings.Join(components, ":")
}

const (
	// AuthorizedKeys are public keys that check against User CAs.
	AuthorizedKeys = "authorized_keys"
	// KnownHosts are public keys that check against Host CAs.
	KnownHosts = "known_hosts"
)

const (
	// CertExtensionPermitX11Forwarding allows X11 forwarding for certificate
	CertExtensionPermitX11Forwarding = "permit-X11-forwarding"
	// CertExtensionPermitAgentForwarding allows agent forwarding for certificate
	CertExtensionPermitAgentForwarding = "permit-agent-forwarding"
	// CertExtensionPermitPTY allows user to request PTY
	CertExtensionPermitPTY = "permit-pty"
	// CertExtensionPermitPortForwarding allows user to request port forwarding
	CertExtensionPermitPortForwarding = "permit-port-forwarding"
	// CertExtensionTeleportRoles is used to propagate teleport roles
	CertExtensionTeleportRoles = "teleport-roles"
	// CertExtensionTeleportRouteToCluster is used to encode
	// the target cluster to route to in the certificate
	CertExtensionTeleportRouteToCluster = "teleport-route-to-cluster"
	// CertExtensionTeleportTraits is used to propagate traits about the user.
	CertExtensionTeleportTraits = "teleport-traits"
	// CertExtensionTeleportActiveRequests is used to track which privilege
	// escalation requests were used to construct the certificate.
	CertExtensionTeleportActiveRequests = "teleport-active-requests"
	// CertExtensionMFAVerified is used to mark certificates issued after an MFA
	// check.
	CertExtensionMFAVerified = "mfa-verified"
	// CertExtensionClientIP is used to embed the IP of the client that created
	// the certificate.
	CertExtensionClientIP = "client-ip"
	// CertExtensionImpersonator is set when one user has requested certificates
	// for another user
	CertExtensionImpersonator = "impersonator"
	// CertExtensionDisallowReissue is set when a certificate should not be allowed
	// to request future certificates.
	CertExtensionDisallowReissue = "disallow-reissue"
)

const (
	// NetIQ is an identity provider.
	NetIQ = "netiq"
	// ADFS is Microsoft Active Directory Federation Services
	ADFS = "adfs"
	// Ping is the common backend for all Ping Identity-branded identity
	// providers (including PingOne, PingFederate, etc).
	Ping = "ping"
)

const (
	// RemoteCommandSuccess is returned when a command has successfully executed.
	RemoteCommandSuccess = 0
	// RemoteCommandFailure is returned when a command has failed to execute and
	// we don't have another status code for it.
	RemoteCommandFailure = 255
)

// MaxEnvironmentFileLines is the maximum number of lines in a environment file.
const MaxEnvironmentFileLines = 1000

// MaxResourceSize is the maximum size (in bytes) of a serialized resource.  This limit is
// typically only enforced against resources that are likely to arbitrarily grow (e.g. PluginData).
const MaxResourceSize = 1000000

// MaxHTTPRequestSize is the maximum accepted size (in bytes) of the body of
// a received HTTP request.  This limit is meant to be used with utils.ReadAtMost
// to prevent resource exhaustion attacks.
const MaxHTTPRequestSize = 10 * 1024 * 1024

// MaxHTTPResponseSize is the maximum accepted size (in bytes) of the body of
// a received HTTP response.  This limit is meant to be used with utils.ReadAtMost
// to prevent resource exhaustion attacks.
const MaxHTTPResponseSize = 10 * 1024 * 1024

const (
	// CertificateFormatOldSSH is used to make Teleport interoperate with older
	// versions of OpenSSH.
	CertificateFormatOldSSH = "oldssh"

	// CertificateFormatUnspecified is used to check if the format was specified
	// or not.
	CertificateFormatUnspecified = ""
)

const (
	// TraitInternalPrefix is the role variable prefix that indicates it's for
	// local accounts.
	TraitInternalPrefix = "internal"

	// TraitExternalPrefix is the role variable prefix that indicates the data comes from an external identity provider.
	TraitExternalPrefix = "external"

	// TraitLogins is the name of the role variable used to store
	// allowed logins.
	TraitLogins = "logins"

	// TraitWindowsLogins is the name of the role variable used
	// to store allowed Windows logins.
	TraitWindowsLogins = "windows_logins"

	// TraitKubeGroups is the name the role variable used to store
	// allowed kubernetes groups
	TraitKubeGroups = "kubernetes_groups"

	// TraitKubeUsers is the name the role variable used to store
	// allowed kubernetes users
	TraitKubeUsers = "kubernetes_users"

	// TraitDBNames is the name of the role variable used to store
	// allowed database names.
	TraitDBNames = "db_names"

	// TraitDBUsers is the name of the role variable used to store
	// allowed database users.
	TraitDBUsers = "db_users"

	// TraitInternalLoginsVariable is the variable used to store allowed
	// logins for local accounts.
	TraitInternalLoginsVariable = "{{internal.logins}}"

	// TraitInternalWindowsLoginsVariable is the variable used to store
	// allowed Windows Desktop logins for local accounts.
	TraitInternalWindowsLoginsVariable = "{{internal.windows_logins}}"

	// TraitInternalKubeGroupsVariable is the variable used to store allowed
	// kubernetes groups for local accounts.
	TraitInternalKubeGroupsVariable = "{{internal.kubernetes_groups}}"

	// TraitInternalKubeUsersVariable is the variable used to store allowed
	// kubernetes users for local accounts.
	TraitInternalKubeUsersVariable = "{{internal.kubernetes_users}}"

	// TraitInternalDBNamesVariable is the variable used to store allowed
	// database names for local accounts.
	TraitInternalDBNamesVariable = "{{internal.db_names}}"

	// TraitInternalDBUsersVariable is the variable used to store allowed
	// database users for local accounts.
	TraitInternalDBUsersVariable = "{{internal.db_users}}"
)

// SCP is Secure Copy.
const SCP = "scp"

// Root is *nix system administrator account name.
const Root = "root"

// Administrator is the Windows system administrator account name.
const Administrator = "Administrator"

// AdminRoleName is the name of the default admin role for all local users if
// another role is not explicitly assigned
const AdminRoleName = "admin"

const (
	// PresetEditorRoleName is a name of a preset role that allows
	// editing cluster configuration.
	PresetEditorRoleName = "editor"

	// PresetAccessRoleName is a name of a preset role that allows
	// accessing cluster resources.
	PresetAccessRoleName = "access"

	// PresetAuditorRoleName is a name of a preset role that allows
	// reading cluster events and playing back session records.
	PresetAuditorRoleName = "auditor"
)

// MinClientVersion is the minimum client version required by the server.
var MinClientVersion string

func init() {
	// Per https://github.com/gravitational/teleport/blob/master/rfd/0012-teleport-versioning.md,
	// only one major version backwards is supported for clients.
	ver := semver.New(Version)
	MinClientVersion = fmt.Sprintf("%d.0.0", ver.Major-1)
}

const (
	// RemoteClusterStatusOffline indicates that cluster is considered as
	// offline, since it has missed a series of heartbeats
	RemoteClusterStatusOffline = "offline"
	// RemoteClusterStatusOnline indicates that cluster is sending heartbeats
	// at expected interval
	RemoteClusterStatusOnline = "online"
)

const (
	// SharedDirMode is a mode for a directory shared with group
	SharedDirMode = 0750

	// PrivateDirMode is a mode for private directories
	PrivateDirMode = 0700
)

const (
	// SessionEvent is sent by servers to clients when an audit event occurs on
	// the session.
	SessionEvent = "x-teleport-event"

	// VersionRequest is sent by clients to server requesting the Teleport
	// version they are running.
	VersionRequest = "x-teleport-version"
)

const (
	// EnvKubeConfig is environment variable for kubeconfig
	EnvKubeConfig = "KUBECONFIG"

	// KubeConfigDir is a default directory where k8s stores its user local config
	KubeConfigDir = ".kube"

	// KubeConfigFile is a default filename where k8s stores its user local config
	KubeConfigFile = "config"

	// EnvHome is home environment variable
	EnvHome = "HOME"

	// EnvUserProfile is the home directory environment variable on Windows.
	EnvUserProfile = "USERPROFILE"

	// KubeCAPath is a hardcode of mounted CA inside every pod of K8s
	KubeCAPath = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

	// KubeRunTests turns on kubernetes tests
	KubeRunTests = "TEST_KUBE"

	// KubeSystemAuthenticated is a builtin group that allows
	// any user to access common API methods, e.g. discovery methods
	// required for initial client usage
	KubeSystemAuthenticated = "system:authenticated"

	// UsageKubeOnly specifies certificate usage metadata
	// that limits certificate to be only used for kubernetes proxying
	UsageKubeOnly = "usage:kube"

	// UsageAppOnly specifies a certificate metadata that only allows it to be
	// used for proxying applications.
	UsageAppsOnly = "usage:apps"

	// UsageDatabaseOnly specifies certificate usage metadata that only allows
	// it to be used for proxying database connections.
	UsageDatabaseOnly = "usage:db"

	// UsageWindowsDesktopOnly specifies certificate usage metadata that limits
	// certificate to be only used for Windows desktop access
	UsageWindowsDesktopOnly = "usage:windows_desktop"
)

const (
	// NodeIsAmbiguous serves as an identifying error string indicating that
	// the proxy subsystem found multiple nodes matching the specified hostname.
	NodeIsAmbiguous = "err-node-is-ambiguous"

	// MaxLeases serves as an identifying error string indicating that the
	// semaphore system is rejecting an acquisition attempt due to max
	// leases having already been reached.
	MaxLeases = "err-max-leases"
)

const (
	// OpenBrowserLinux is the command used to open a web browser on Linux.
	OpenBrowserLinux = "xdg-open"

	// OpenBrowserDarwin is the command used to open a web browser on macOS/Darwin.
	OpenBrowserDarwin = "open"

	// OpenBrowserWindows is the command used to open a web browser on Windows.
	OpenBrowserWindows = "rundll32.exe"

	// BrowserNone is the string used to suppress the opening of a browser in
	// response to 'tsh login' commands.
	BrowserNone = "none"
)

const (
	// ExecSubCommand is the sub-command Teleport uses to re-exec itself for
	// command execution (exec and shells).
	ExecSubCommand = "exec"

	// ForwardSubCommand is the sub-command Teleport uses to re-exec itself
	// for port forwarding.
	ForwardSubCommand = "forward"
)

const (
	// ChanDirectTCPIP is a SSH channel of type "direct-tcpip".
	ChanDirectTCPIP = "direct-tcpip"

	// ChanSession is a SSH channel of type "session".
	ChanSession = "session"
)

// A principal name for use in SSH certificates.
type Principal string

const (
	// The localhost domain, for talking to a proxy or node on the same
	// machine.
	PrincipalLocalhost Principal = "localhost"
	// The IPv4 loopback address, for talking to a proxy or node on the same
	// machine.
	PrincipalLoopbackV4 Principal = "127.0.0.1"
	// The IPv6 loopback address, for talking to a proxy or node on the same
	// machine.
	PrincipalLoopbackV6 Principal = "::1"
)

// UserSystem defines a user as system.
const UserSystem = "system"

const (
	// internal application being proxied.
	AppJWTHeader = "teleport-jwt-assertion"

	// AppCFHeader is a compatibility header.
	AppCFHeader = "cf-access-token"

	// HostHeader is the name of the Host header.
	HostHeader = "Host"
)

// UserSingleUseCertTTL is a TTL for per-connection user certificates.
const UserSingleUseCertTTL = time.Minute

// StandardHTTPSPort is the default port used for the https URI scheme,
// cf. RFC 7230 § 2.7.2.
const StandardHTTPSPort = 443

// StandardRDPPort is the default port used for RDP.
const StandardRDPPort = 3389
