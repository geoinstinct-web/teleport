---
title: Kubernetes Access Guide
description: How to set up and configure Teleport for Kubernetes access with SSO and RBAC
h1: Teleport Kubernetes Access Guide
---

Teleport has the ability to act as a compliance gateway for managing privileged
access to Kubernetes clusters. This enables the following capabilities:

* A Teleport Proxy can act as a single authentication endpoint for both SSH and
  Kubernetes. Users can authenticate against a Teleport proxy using Teleport's
  [`tsh login`](cli-docs.md#tsh-login) command
  and retrieve credentials for both SSH and Kubernetes API.
* Users RBAC roles are always synchronized between SSH and Kubernetes, making
  it easier to implement policies like _developers must not access production
  data_.
* Teleport's session recording and audit log extend to Kubernetes, as well.
  Regular `kubectl exec` commands are logged into the audit log and the interactive
  commands are recorded as regular sessions that can be stored and replayed in the
  future.

## Teleport Proxy Service
By default, the Kubernetes integration is turned off in Teleport. The configuration
setting to enable the integration in the proxy service section in the `/etc/teleport.yaml`
config file, as shown below:

```yaml
# snippet from /etc/teleport.yaml on the Teleport proxy service:
proxy_service:
    # create the 'kubernetes' section and set 'enabled' to 'yes':
    kubernetes:
        enabled: yes
        public_addr: [teleport.example.com:3026]
        listen_addr: 0.0.0.0:3026
```
Let's take a closer look at the available Kubernetes settings:

- `public_addr` defines the publicly accessible address which Kubernetes API clients
  like `kubectl` will connect to. This address will be placed inside of kubeconfig on
  a client's machine when a client executes tsh login command to retrieve its certificate.
  If you intend to run multiple Teleport proxies behind a load balancer, this must
  be the load balancer's public address.

- `listen_addr` defines which network interface and port the Teleport proxy server
  should bind to. It defaults to port 3026 on all NICs.

### Connecting the Teleport proxy to Kubernetes

There are two options for setting up Teleport to access Kubernetes:

## Option 1: Deploy Inside Kubernetes as a pod

Deploy Teleport Proxy service as a Kubernetes pod inside the Kubernetes cluster
you want the proxy to have access to.

```yaml
# snippet from /etc/teleport.yaml on the Teleport proxy service:
proxy_service:
    # create the 'kubernetes' section and set 'enabled' to 'yes':
    kubernetes:
        enabled: yes
```

If you're using Helm, we've a chart that you can use. Run these commands:

```bash
$ helm repo add teleport https://charts.releases.teleport.dev
$ helm install teleport teleport/teleport
```

You will still need a correctly configured `values.yaml` file for this to work. See
our [Helm Docs](https://github.com/gravitational/teleport/tree/master/examples/chart/teleport#introduction) for more information.

![teleport-kubernetes-inside](../img/teleport-k8s-pod.svg)

## Option 2: Deploy Outside of Kubernetes

Deploy the Teleport proxy service outside of Kubernetes and update the Teleport
Proxy configuration with Kubernetes credentials. Update the Teleport Proxy
configuration with Kubernetes credentials.

In this case, we need to update `/etc/teleport.yaml` for the proxy service as shown
below:

```yaml
# snippet from /etc/teleport.yaml on the Teleport proxy service:
proxy_service:
  # create the 'kubernetes' section and set 'enabled' to 'yes':
  kubernetes:
    enabled: yes
    # The address for the proxy process to accept k8s requests.
    listen_addr: 0.0.0.0:3026
    # The address used by the clients after tsh login. If you run a load balancer
    # in front of this proxy, use the address of that balancer here. Otherwise,
    # use the address of the host running this proxy.
    public_addr: [teleport.example.com:3026]
    kubeconfig_file: /path/to/.kube/config
```

![teleport-ssh-kubernetes-integration](../img/teleport-kubernetes-outside.svg)

To generate the `kubeconfig_file` for the Teleport proxy service:

1. Configure your `kubectl` to point at the Kubernetes cluster and have admin-level access.
2. Use [this
   script](https://github.com/gravitational/teleport/blob/master/examples/k8s-auth/get-kubeconfig.sh)
   to generate `kubeconfig`:

```bash
# Download the script.
$ curl -o get-kubeconfig.sh https://raw.githubusercontent.com/gravitational/teleport/master/examples/k8s-auth/get-kubeconfig.sh

# Make it executable.
$ chmod +x get-kubeconfig.sh

# Run the script, it will write the generated kubeconfig to the current
# directory.
$ ./get-kubeconfig.sh

# Check that the generated kubeconfig has the right permissions.
# The output should look similar to this.
$ kubectl --kubeconfig kubeconfig auth can-i --list
Resources                                       Non-Resource URLs   Resource Names   Verbs
selfsubjectaccessreviews.authorization.k8s.io   []                  []               [create create]
selfsubjectrulesreviews.authorization.k8s.io    []                  []               [create create]
                                                [/api/*]            []               [get]
                                                ...                 []               [...]
groups                                          []                  []               [impersonate]
serviceaccounts                                 []                  []               [impersonate]
users                                           []                  []               [impersonate]
```

3. Copy the generated `kubeconfig` file to the host running the Teleport proxy
   service.
4. Update `kubeconfig_file` path in `teleport.yaml` to where you copied the
   `kubeconfig`.

Alternatively, you can use your existing local config from `~/.kube/config`.
However, it will result in Teleport proxy using your personal Kubernetes
credentials. This is risky: your credentials can expire or get revoked (such as
when leaving your company).



## Impersonation

!!! note

    If you used [the script from Option
    2](https://github.com/gravitational/teleport/blob/master/examples/k8s-auth/get-kubeconfig.sh)
    above, you can skip this step. The script already configured impersonation permissions.

The next step is to configure the Teleport Proxy to be able to impersonate Kubernetes principals within a given group
using [Kubernetes Impersonation Headers](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#user-impersonation).

If Teleport is running inside the cluster using a Kubernetes `ServiceAccount`,
here's an example of the permissions that the `ServiceAccount` will need to be able
to use impersonation (change `teleport-serviceaccount` to the name of the `ServiceAccount`
that's being used):

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: teleport-impersonation
rules:
- apiGroups:
  - ""
  resources:
  - users
  - groups
  - serviceaccounts
  verbs:
  - impersonate
- apiGroups:
  - "authorization.k8s.io"
  resources:
  - selfsubjectaccessreviews
  verbs:
  - create
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: teleport
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: teleport-impersonation
subjects:
- kind: ServiceAccount
  # this should be changed to the name of the Kubernetes ServiceAccount being used
  name: teleport-serviceaccount
  namespace: default
```

There is also an [example of this usage](https://github.com/gravitational/teleport/blob/master/examples/chart/teleport/templates/clusterrole.yaml)
within the [example Teleport Helm chart](https://github.com/gravitational/teleport/blob/master/examples/chart/teleport/).

If Teleport is running outside of the Kubernetes cluster, you will need to ensure
that the principal used to connect to Kubernetes via the `kubeconfig` file has the
same impersonation permissions as are described in the `ClusterRole` above.

## Kubernetes RBAC

Once you perform the steps above, your Teleport instance should become a fully
functional Kubernetes API proxy. The next step is to configure Teleport to assign
the correct Kubernetes groups to Teleport users.

Mapping Kubernetes groups to Teleport users depends on how Teleport is
configured. In this guide we'll look at two common configurations:

* **Open source, Teleport Community edition** configured to authenticate users via [Github](admin-guide.md#github-oauth-20).
  In this case, we'll need to map Github teams to Kubernetes groups.

* **Commercial, Teleport Enterprise edition** configured to authenticate users via [Okta SSO](enterprise/sso/ssh-okta.md).
  In this case, we'll need to map users' groups that come from Okta to Kubernetes
  groups.

## Kubernetes Groups and Users

Teleport provides support for

* Kubernetes Groups, using `kubernetes_groups: ["system:masters"]`.
* Kubernetes Users, using `kubernetes_users: ['barent', 'jane']`. If a Kubernetes
user isn't set the user will impersonate themselves.

When adding new local users you have to specify which Kubernetes groups they
belong to:

``` bash
# Adding a Teleport local user to map to a Kubernetes group.
$ tctl users add joe --k8s-groups="system:masters"
# Adding a Teleport local user to map to a Kubernetes user.
$ tctl users add jenkins --k8s-users="jenkins"
# Enterprise users should manage k8s-users and k8s-groups via RBAC, see Okta Auth
# example below
```

### Github Auth

When configuring Teleport to authenticate against Github, you have to create a
Teleport connector for Github, like the one shown below. Notice the `kubernetes_groups`
setting which assigns Kubernetes groups to a given Github team:

```yaml
kind: github
version: v3
metadata:
  # connector name that will be used with `tsh --auth=github login`
  name: github
spec:
  # client ID of Github OAuth app
  client_id: <client-id>
  # client secret of Github OAuth app
  client_secret: <client-secret>
  # connector display name that will be shown on web UI login screen
  display: Github
  # callback URL that will be called after successful authentication
  redirect_url: https://teleport.example.com:3080/v1/webapi/github/callback
  # mapping of org/team memberships onto allowed logins and roles
  teams_to_logins:
    - organization: octocats # Github organization name
      team: admin           # Github team name within that organization
      # allowed UNIX logins for team octocats/admin:
      logins:
        - root
      # list of Kubernetes groups this Github team is allowed to connect to
      kubernetes_groups: ["system:masters"]
      # Optional: If not set, users will impersonate themselves.
      # kubernetes_users: ['barent']
```

To obtain client ID and client secret from Github, please follow [Github documentation](https://developer.github.com/apps/building-oauth-apps/creating-an-oauth-app/) on how to create and register an OAuth
app. Be sure to set the "Authorization callback URL" to the same value as `redirect_url`
in the resource spec.

Finally, create the Github connector with the command: `tctl create -f github.yaml`.
Now, when Teleport users execute the Teleport's `tsh login` command, they will be
prompted to login through the Github SSO and upon successful authentication, they
have access to Kubernetes.

```bsh
# Login via Github SSO and retrieve SSH+Kubernetes certificates:
$ tsh login --proxy=teleport.example.com --auth=github login

# Use Kubernetes API!
$ kubectl exec -ti <pod-name>
```

The `kubectl exec` request will be routed through the Teleport proxy and
Teleport will log the audit record and record the session.

!!! note

    For more information on integrating Teleport with Github SSO, please see the
    [Github section in the Admin Manual](admin-guide.md#github-oauth-20).

### Okta Auth

With Okta (or any other SAML/OIDC/Active Directory provider), you must update
Teleport's roles to include the mapping to Kubernetes groups.

Let's assume you have the Teleport role called "admin". Add `kubernetes_groups`
setting to it as shown below:

```yaml
# NOTE: the role definition is edited to remove the unnecessary fields
kind: role
version: v3
metadata:
  name: admin
spec:
  allow:
    # if kubernetes integration is enabled, this setting configures which
    # kubernetes groups the users of this role will be assigned to.
    # note that you can refer to a SAML/OIDC trait via the "external" property bag,
    # this allows you to specify Kubernetes group membership in an identity manager:
    kubernetes_groups: ["system:masters", "{% raw %}{{external.trait_name}}{% endraw %}"]]
```

To add `kubernetes_groups` setting to an existing Teleport role, you can either
use the Web UI or `tctl`:

```bsh
# Dump the "admin" role into a file:
$ tctl get roles/admin > admin.yaml
# Edit the file, add kubernetes_groups setting
# and then execute:
$ tctl create -f admin.yaml
```

!!! tip "Advanced Usage"

    `{% raw %}{{ external.trait_name }}{% endraw %}` example is shown to demonstrate how to fetch
    the Kubernetes groups dynamically from Okta during login. In this case, you
    need to define Kubernetes group membership in Okta (as a trait) and use
    that trait name in the Teleport role.

    Teleport 4.3 has an option to extract the local part from an email claim. This can be helpful
    since some operating systems don't support the @ symbol. This means by using `logins: ['{% raw %}{{email.local(external.email)}}{% endraw %}']` the resulting output will be `dave.smith` if the email was dave.smith@acme.com.

Once setup is complete, when users execute `tsh login` and go through the usual Okta login
sequence, their `kubeconfig` will be updated with their Kubernetes credentials.

!!! note

    For more information on integrating Teleport with Okta, please see the
    [Okta integration guide](enterprise/sso/ssh-okta.md).

## Using Teleport Kubernetes with Automation

Teleport can integrate with CI/CD tooling for greater visibility and auditability of
these tools. For this we recommend creating a local Teleport user, then exporting
a kubeconfig using [`tctl auth sign`](cli-docs.md#tctl-auth-sign)

An example setup is below.

```bash
# Create a new local user for Jenkins
$ tctl users add jenkins
# Option 1: Creates a token for 1 year
$ tctl auth sign --user=jenkins --format=kubernetes --out=kubeconfig --ttl=8760h
# Recommended Option 2: Creates a token for 25hrs
$ tctl auth sign --user=jenkins --format=kubernetes --out=kubeconfig --ttl=25h

  The credentials have been written to kubeconfig

$ cat kubeconfig
  apiVersion: v1
  clusters:
  - cluster:
      certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZ....
# This kubeconfig can now be exported and will provide access to the automation tooling.

# Uses kubectl to get pods, using the provided kubeconfig.
$ kubectl --kubeconfig /path/to/kubeconfig get pods
```

!!! tip "How long should TTL be?"

    In the above example we've provided two options. One with 1yr (8760h) time to live
    and one for just 25hrs. As proponents of short lived SSH certificates we recommend
    the same for automation.

    Handling secrets is out of scope of our docs, but at a high level we recommend
    using providers secrets managers. Such as [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/),
    [GCP Secrets Manager](https://cloud.google.com/secret-manager), or on prem using
    a project like [Vault](https://www.vaultproject.io/).  Then running a nightly
    job on the auth server to sign and publish a new kubeconfig. In our example, we've
    added 1hr, and during this time both kubeconfigs will be valid.

    Taking this a step further you could build a system to request a very short lived
    token for each CI run. We plan to make this easier for operators to integrate in
    the future by exposing and documenting more of our API.

## AWS EKS

We've a complete guide on setting up Teleport with EKS. Please see the [Using Teleport with EKS Guide](aws-oss-guide.md#using-teleport-with-eks).

## Multiple Kubernetes Clusters

You can take advantage of the [Trusted Clusters](trustedclusters.md) feature of
Teleport to federate trust across multiple Kubernetes clusters.

When multiple trusted clusters are present behind a Teleport proxy, the
`kubeconfig` generated by [ `tsh login` ](cli-docs.md#tsh-login) will contain the
Kubernetes API endpoint determined by the `<cluster>` argument to [`tsh
login`](cli-docs.md#tsh-login) .

For example, consider the following setup:

* There are three Teleport/Kubernetes clusters: "main", "east" and "west". These
  are the names set in `cluster_name` setting in their configuration files.
* The clusters "east" and "west" are trusted clusters for "main".
* Users always authenticate against "main" but use their certificates to access
  SSH nodes and Kubernetes API in all three clusters.
* The DNS name of the main proxy server is "main.example.com"

In this scenario, users usually login using this command:

``` bash
# Using login without arguments
$ tsh --proxy=main.example.com login

# user's `kubeconfig` now contains one entry for the main Kubernetes
# endpoint, i.e. `proxy.example.com` .

# Receive a certificate for "east":
$ tsh --proxy=main.example.com login east

# user's `kubeconfig` now contains the entry for the "east" Kubernetes
# endpoint, i.e. `east.proxy.example.com` .
```
