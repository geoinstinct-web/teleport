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
	"text/template"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/gravitational/trace"
	log "github.com/sirupsen/logrus"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/client/proto"
	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth"
	libclient "github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/service/servicecfg"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"
)

// NodeCommand implements `tctl nodes` group of commands
type NodeCommand struct {
	config *servicecfg.Config
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

	searchKeywords string
	predicateExpr  string
	labels         string

	// ls output format -- text or json
	lsFormat string

	// verbose sets whether full table output should be shown for labels
	verbose bool

	// CLI subcommands (clauses)
	nodeAdd  *kingpin.CmdClause
	nodeList *kingpin.CmdClause
}

// Initialize allows NodeCommand to plug itself into the CLI parser
func (c *NodeCommand) Initialize(app *kingpin.Application, config *servicecfg.Config) {
	c.config = config

	// add node command
	nodes := app.Command("nodes", "Issue invites for other nodes to join the cluster.")
	c.nodeAdd = nodes.Command("add", "Generate a node invitation token.")
	c.nodeAdd.Flag("roles", "Comma-separated list of roles for the new node to assume [node]").Default("node").StringVar(&c.roles)
	c.nodeAdd.Flag("ttl", "Time to live for a generated token").Default(defaults.ProvisioningTokenTTL.String()).DurationVar(&c.ttl)
	c.nodeAdd.Flag("token", "Override the default random generated token with a specified value").StringVar(&c.token)
	c.nodeAdd.Flag("format", "Output format, 'text' or 'json'").Hidden().Default(teleport.Text).StringVar(&c.format)
	c.nodeAdd.Alias(AddNodeHelp)

	c.nodeList = nodes.Command("ls", "List all active SSH nodes within the cluster.")
	c.nodeList.Flag("namespace", "Namespace of the nodes").Default(apidefaults.Namespace).StringVar(&c.namespace)
	c.nodeList.Flag("format", "Output format, 'text', or 'yaml'").Default(teleport.Text).StringVar(&c.lsFormat)
	c.nodeList.Flag("verbose", "Verbose table output, shows full label output").Short('v').BoolVar(&c.verbose)
	c.nodeList.Alias(ListNodesHelp)
	c.nodeList.Arg("labels", labelHelp).StringVar(&c.labels)
	c.nodeList.Flag("search", searchHelp).StringVar(&c.searchKeywords)
	c.nodeList.Flag("query", queryHelp).StringVar(&c.predicateExpr)
}

// TryRun takes the CLI command as an argument (like "nodes ls") and executes it.
func (c *NodeCommand) TryRun(ctx context.Context, cmd string, client auth.ClientI) (match bool, err error) {
	switch cmd {
	case c.nodeAdd.FullCommand():
		err = c.Invite(ctx, client)
	case c.nodeList.FullCommand():
		err = c.ListActive(ctx, client)

	default:
		return false, nil
	}
	return true, trace.Wrap(err)
}

const trustedClusterMessage = `The cluster invite token: %v
This token will expire in %d minutes

Use this token when defining a trusted cluster resource on a remote cluster.
`

var nodeMessageTemplate = template.Must(template.New("node").Parse(`The invite token: {{.token}}
This token will expire in {{.minutes}} minutes.

Run this on the new node to join the cluster:

> teleport start \
   --roles={{.roles}} \
   --token={{.token}} \{{range .ca_pins}}
   --ca-pin={{.}} \{{end}}
   --auth-server={{.auth_server}}

Please note:

  - This invitation token will expire in {{.minutes}} minutes
  - {{.auth_server}} must be reachable from the new node
`))

// Invite generates a token which can be used to add another SSH node
// to a cluster
func (c *NodeCommand) Invite(ctx context.Context, client auth.ClientI) error {
	// parse --roles flag
	roles, err := types.ParseTeleportRoles(c.roles)
	if err != nil {
		return trace.Wrap(err)
	}

	token := c.token
	if c.token == "" {
		token, err = utils.CryptoRandomHex(defaults.TokenLenBytes)
		if err != nil {
			return trace.WrapWithMessage(err, "generating token value")
		}
	}
	expires := time.Now().Add(c.ttl)
	pt, err := types.NewProvisionToken(token, roles, expires)
	if err != nil {
		return trace.Wrap(err)
	}
	if err := client.CreateToken(ctx, pt); err != nil {
		if trace.IsAlreadyExists(err) {
			return trace.AlreadyExists(
				"failed to create token (%q already exists), please use another name",
				pt.GetName(),
			)
		}
		return trace.Wrap(err, "creating token")
	}

	// Calculate the CA pins for this cluster. The CA pins are used by the
	// client to verify the identity of the Auth Server.
	localCAResponse, err := client.GetClusterCACert(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	caPins, err := tlsca.CalculatePins(localCAResponse.TLSCA)
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

	// output format switch:
	if c.format == teleport.Text {
		if roles.Include(types.RoleTrustedCluster) {
			fmt.Printf(trustedClusterMessage, token, int(c.ttl.Minutes()))
		} else {
			authServer := authServers[0].GetAddr()

			pingResponse, err := client.Ping(ctx)
			if err != nil {
				log.Debugf("unable to ping auth client: %s.", err.Error())
			}

			if err == nil && pingResponse.GetServerFeatures().Cloud {
				proxies, err := client.GetProxies()
				if err != nil {
					return trace.Wrap(err)
				}

				if len(proxies) != 0 {
					authServer = proxies[0].GetPublicAddr()
				}
			}
			return nodeMessageTemplate.Execute(os.Stdout, map[string]interface{}{
				"token":       token,
				"minutes":     int(c.ttl.Minutes()),
				"roles":       strings.ToLower(roles.String()),
				"ca_pins":     caPins,
				"auth_server": authServer,
			})
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

// ListActive retrieves the list of nodes who recently sent heartbeats to
// to a cluster and prints it to stdout
func (c *NodeCommand) ListActive(ctx context.Context, clt auth.ClientI) error {
	labels, err := libclient.ParseLabelSpec(c.labels)
	if err != nil {
		return trace.Wrap(err)
	}

	nodes, err := client.GetAllResources[types.Server](ctx, clt, &proto.ListResourcesRequest{
		ResourceType:        types.KindNode,
		Namespace:           c.namespace,
		Labels:              labels,
		PredicateExpression: c.predicateExpr,
		SearchKeywords:      libclient.ParseSearchKeywords(c.searchKeywords, ','),
	})
	if err != nil {
		if utils.IsPredicateError(err) {
			return trace.Wrap(utils.PredicateError{Err: err})
		}
		return trace.Wrap(err)
	}

	coll := &serverCollection{servers: nodes}
	switch c.lsFormat {
	case teleport.Text:
		if err := coll.writeText(os.Stdout, c.verbose); err != nil {
			return trace.Wrap(err)
		}
	case teleport.YAML:
		if err := coll.writeYAML(os.Stdout); err != nil {
			return trace.Wrap(err)
		}
	case teleport.JSON:
		if err := coll.writeJSON(os.Stdout); err != nil {
			return trace.Wrap(err)
		}
	default:
		return trace.Errorf("Invalid format %s, only text, json and yaml are supported", c.lsFormat)
	}
	return nil
}
