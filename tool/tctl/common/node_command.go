/*
Copyright 2015 Gravitational, Inc.

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

package common

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gravitational/kingpin"
	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/service"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/trace"
)

// NodeCommand implements `tctl nodes` group of commands
type NodeCommand struct {
	config *service.Config
	// format is the output format, e.g. text or json
	format string
	// list of roles for the new node to assume
	roles string
	// TTL: duration of time during which a generated node token will
	// be valid.
	ttl time.Duration
	// namespace is node namespace
	namespace string
	// token is an optional custom token supplied by client,
	// if not specified, is autogenerated
	token string

	// CLI subcommands (clauses)
	nodeAdd  *kingpin.CmdClause
	nodeList *kingpin.CmdClause
}

// Initialize allows NodeCommand to plug itself into the CLI parser
func (c *NodeCommand) Initialize(app *kingpin.Application, config *service.Config) {
	c.config = config

	// add node command
	nodes := app.Command("nodes", "Issue invites for other nodes to join the cluster")
	c.nodeAdd = nodes.Command("add", "Generate a node invitation token")
	c.nodeAdd.Flag("roles", "Comma-separated list of roles for the new node to assume [node]").Default("node").StringVar(&c.roles)
	c.nodeAdd.Flag("ttl", "Time to live for a generated token").Default(defaults.ProvisioningTokenTTL.String()).DurationVar(&c.ttl)
	c.nodeAdd.Flag("token", "Custom token to use, autogenerated if not provided").StringVar(&c.token)
	c.nodeAdd.Flag("format", "Output format, 'text' or 'json'").Hidden().Default("text").StringVar(&c.format)
	c.nodeAdd.Alias(AddNodeHelp)

	c.nodeList = nodes.Command("ls", "List all active SSH nodes within the cluster")
	c.nodeList.Flag("namespace", "Namespace of the nodes").Default(defaults.Namespace).StringVar(&c.namespace)
	c.nodeList.Alias(ListNodesHelp)
}

// TryRun takes the CLI command as an argument (like "nodes ls") and executes it.
func (c *NodeCommand) TryRun(cmd string, client auth.ClientI) (match bool, err error) {
	switch cmd {
	case c.nodeAdd.FullCommand():
		err = c.Invite(client)
	case c.nodeList.FullCommand():
		err = c.ListActive(client)

	default:
		return false, nil
	}
	return true, trace.Wrap(err)
}

const trustedClusterMessage = `The cluster invite token: %v
This token will expire in %d minutes

Use this token when defining a trusted cluster resource on a remote cluster.
`

const nodeMessage = `The invite token: %v
This token will expire in %d minutes

Run this on the new node to join the cluster:

> teleport start \
   --roles=%s \
   --token=%v \
   --ca-pin=%v \
   --auth-server=%v

Please note:

  - This invitation token will expire in %d minutes
  - %v must be reachable from the new node
`

// Invite generates a token which can be used to add another SSH node
// to a cluster
func (c *NodeCommand) Invite(client auth.ClientI) error {
	// parse --roles flag
	roles, err := teleport.ParseRoles(c.roles)
	if err != nil {
		return trace.Wrap(err)
	}
	token, err := client.GenerateToken(context.TODO(), auth.GenerateTokenRequest{Roles: roles, TTL: c.ttl, Token: c.token})
	if err != nil {
		return trace.Wrap(err)
	}

	// Calculate the CA pin for this cluster. The CA pin is used by the client
	// to verify the identity of the Auth Server.
	caPin, err := calculateCAPin(client)
	if err != nil {
		return trace.Wrap(err)
	}

	authServers, err := client.GetAuthServers()
	if err != nil {
		return trace.Wrap(err)
	}
	if len(authServers) == 0 {
		return trace.Errorf("This cluster does not have any auth servers running.")
	}

	// output format swtich:
	if c.format == "text" {
		if roles.Include(teleport.RoleTrustedCluster) || roles.Include(teleport.LegacyClusterTokenType) {
			fmt.Printf(trustedClusterMessage, token, int(c.ttl.Minutes()))
		} else {
			fmt.Printf(nodeMessage,
				token,
				int(c.ttl.Minutes()),
				strings.ToLower(roles.String()),
				token,
				caPin,
				authServers[0].GetAddr(),
				int(c.ttl.Minutes()),
				authServers[0].GetAddr(),
			)
		}
	} else {
		// Always return a list, otherwise we'll break users tooling. See #1846 for
		// more details.
		tokens := []string{token}
		out, err := json.Marshal(tokens)
		if err != nil {
			return trace.Wrap(err, "failed to marshal token")
		}
		fmt.Print(string(out))
	}
	return nil
}

// ListActive retreives the list of nodes who recently sent heartbeats to
// to a cluster and prints it to stdout
func (c *NodeCommand) ListActive(client auth.ClientI) error {
	ctx := context.TODO()
	nodes, err := client.GetNodes(ctx, c.namespace, services.SkipValidation())
	if err != nil {
		return trace.Wrap(err)
	}
	coll := &serverCollection{servers: nodes}
	if err := coll.writeText(os.Stdout); err != nil {
		return trace.Wrap(err)
	}
	return nil
}
