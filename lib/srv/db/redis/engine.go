/*
Copyright 2022 Gravitational, Inc.

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

package redis

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/go-redis/redis/v8"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/srv/db/common"
	"github.com/gravitational/teleport/lib/srv/db/common/role"
	"github.com/gravitational/teleport/lib/srv/db/redis/protocol"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/trace"
)

func init() {
	common.RegisterEngine(newEngine, defaults.ProtocolRedis)
}

// newEngine create new Redis engine.
func newEngine(ec common.EngineConfig) common.Engine {
	return &Engine{
		EngineConfig: ec,
	}
}

// Engine implements common.Engine.
type Engine struct {
	// EngineConfig is the common database engine configuration.
	common.EngineConfig
	// clientConn is a client connection.
	clientConn net.Conn
	// clientReader is a go-redis wrapper for Redis client connection.
	clientReader *redis.Reader
	// sessionCtx is current session context.
	sessionCtx *common.Session
}

// InitializeConnection initializes the database connection.
func (e *Engine) InitializeConnection(clientConn net.Conn, sessionCtx *common.Session) error {
	e.clientConn = clientConn
	e.clientReader = redis.NewReader(clientConn)
	e.sessionCtx = sessionCtx

	// Use Redis default user named "default" if a user is not provided.
	if e.sessionCtx.DatabaseUser == "" {
		e.sessionCtx.DatabaseUser = defaults.DefaultRedisUsername
	}

	return nil
}

// authorizeConnection does authorization check for Redis connection about
// to be established.
func (e *Engine) authorizeConnection(ctx context.Context) error {
	ap, err := e.Auth.GetAuthPreference(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	mfaParams := services.AccessMFAParams{
		Verified:       e.sessionCtx.Identity.MFAVerified != "",
		AlwaysRequired: ap.GetRequireSessionMFA(),
	}

	dbRoleMatchers := role.DatabaseRoleMatchers(
		e.sessionCtx.Database.GetProtocol(),
		e.sessionCtx.DatabaseUser,
		e.sessionCtx.DatabaseName,
	)
	err = e.sessionCtx.Checker.CheckAccess(
		e.sessionCtx.Database,
		mfaParams,
		dbRoleMatchers...,
	)
	if err != nil {
		e.Audit.OnSessionStart(e.Context, e.sessionCtx, err)
		return trace.Wrap(err)
	}
	return nil
}

// SendError sends error message to connected client.
func (e *Engine) SendError(redisErr error) {
	if redisErr == nil || utils.IsOKNetworkError(redisErr) {
		return
	}

	if err := e.sendToClient(redisErr); err != nil {
		e.Log.Errorf("Failed to send message to the client: %v.", err)
		return
	}
}

// sendToClient sends a command to connected Redis client.
func (e *Engine) sendToClient(vals interface{}) error {
	if vals == nil {
		return nil
	}

	buf := &bytes.Buffer{}
	wr := redis.NewWriter(buf)

	if err := protocol.WriteCmd(wr, vals); err != nil {
		return trace.BadParameter("failed to convert error to a message: %v", err)
	}

	if _, err := e.clientConn.Write(buf.Bytes()); err != nil {
		return trace.ConnectionProblem(err, "failed to send message to the client")
	}

	return nil
}

// HandleConnection is responsible for connecting to a Redis instance/cluster.
func (e *Engine) HandleConnection(ctx context.Context, sessionCtx *common.Session) error {
	// Check that the user has access to the database.
	err := e.authorizeConnection(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	tlsConfig, err := e.Auth.GetTLSConfig(ctx, sessionCtx)
	if err != nil {
		return trace.Wrap(err)
	}

	connectionOptions, err := ParseRedisAddress(sessionCtx.Database.GetURI())
	if err != nil {
		return trace.BadParameter("Redis connection string is incorrect %q: %v", sessionCtx.Database.GetURI(), err)
	}

	var (
		redisConn      redis.UniversalClient
		connectionAddr = fmt.Sprintf("%s:%s", connectionOptions.address, connectionOptions.port)
	)

	// TODO(jakub): Use system CA bundle if connecting to AWS.
	// TODO(jakub): Investigate Redis Sentinel.
	switch connectionOptions.mode {
	case Standalone:
		redisConn = redis.NewClient(&redis.Options{
			Addr:      connectionAddr,
			TLSConfig: tlsConfig,
		})
	case Cluster:
		redisConn = redis.NewClusterClient(&redis.ClusterOptions{
			Addrs:     []string{connectionAddr},
			TLSConfig: tlsConfig,
		})
	default:
		// We've checked that while validating the config, but checking again can help with regression.
		return trace.BadParameter("incorrect connection mode %s", connectionOptions.mode)
	}

	defer func() {
		if err := redisConn.Close(); err != nil {
			e.Log.Errorf("Failed to close Redis connection: %v.", err)
		}
	}()

	e.Audit.OnSessionStart(e.Context, sessionCtx, nil)
	defer e.Audit.OnSessionEnd(e.Context, sessionCtx)

	if err := e.process(ctx, redisConn); err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// process is the main processing function for Redis. It reads commands passed from client and passes them to
// a Redis instance. It's also responsible for audit.
func (e *Engine) process(ctx context.Context, redisClient redis.UniversalClient) error {
	for {
		// Read commands from client.
		cmd, err := e.readClientCmd(ctx)
		if err != nil {
			return trace.Wrap(err)
		}

		// send valid commands to Redis instance/cluster.
		err = e.processCmd(ctx, redisClient, cmd)

		// extract server response from
		vals, err := serverResponseToValue(cmd, err)
		if err != nil {
			return trace.Wrap(err)
		}

		// Send response back to the client.
		if err := e.sendToClient(vals); err != nil {
			return trace.Wrap(err)
		}
	}
}

// readClientCmd reads commands from connected Redis client.
func (e *Engine) readClientCmd(ctx context.Context) (*redis.Cmd, error) {
	cmd := &redis.Cmd{}
	if err := cmd.ReadReply(e.clientReader); err != nil {
		return nil, trace.Wrap(err)
	}

	val, ok := cmd.Val().([]interface{})
	if !ok {
		return nil, trace.BadParameter("failed to cast Redis value to a slice, got %T", cmd.Val())
	}

	return redis.NewCmd(ctx, val...), nil
}

// serverResponseToValue takes server response and an error and return a message that should be propagated back
// to connected client as the first value and errors that should terminate the connection as the second one.
// Some examples:
// * Server errors are returned as the first value. They should be propagated back to the connected client
//   instead of handled by Teleport.
// * Go's context.DeadlineExceeded is returned as the first value as "connection timeout", as returning
//   context deadline exceeded to a user is confusing.
// * Connection errors (EOF, closed network) are returned as an errors, as in this case we want to terminate the client connection.
func serverResponseToValue(cmd *redis.Cmd, err error) (interface{}, error) {
	var vals interface{}

	if err == nil {
		vals, err = cmd.Result()
		if err != nil {
			// Propagate the server error to the client. In this case we don't want to return the error
			// as the second value from this function, as this would terminate the connection.
			vals = err
		}

		return vals, nil
	}

	switch {
	case errors.Is(err, context.DeadlineExceeded):
		// Do not return Deadline Exceeded to the client as it's not very self-explanatory.
		// Return "connection timeout" as this is what most likely happened.
		vals = trace.ConnectionProblem(err, "connection timeout")
	case utils.IsConnectionRefused(err):
		// "connection refused" is returned when we fail to connect to the DB or a connection
		// has been lost. Replace with more meaningful error.
		vals = trace.ConnectionProblem(err, "failed to connect to the target database")
	case utils.IsOKNetworkError(err):
		// Terminate connection only on connection errors.
		// Other errors should be propagated back to the client.
		return nil, trace.Wrap(err)
	default:
		vals = err
	}

	return vals, nil
}
