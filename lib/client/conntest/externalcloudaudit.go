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

package conntest

import (
	"context"

	"github.com/google/uuid"
	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth"
)

// ExternalAuditStorageConnectionTesterConfig defines the config fields for ExternalAuditStorageConnectionTester.
type ExternalAuditStorageConnectionTesterConfig struct {
	// UserClient is an auth client that has a User's identity.
	UserClient auth.ClientI
}

// ExternalAuditStorageConnectionTester implements the ConnectionTester interface for testing External Audit Storage access.
type ExternalAuditStorageConnectionTester struct {
	cfg ExternalAuditStorageConnectionTesterConfig
}

// NewDatabaseConnectionTester returns a new DatabaseConnectionTester.
func NewExternalAuditStorageConnectionTester(cfg ExternalAuditStorageConnectionTesterConfig) (*ExternalAuditStorageConnectionTester, error) {
	return &ExternalAuditStorageConnectionTester{
		cfg,
	}, nil
}

// TestConnection tests the current configured ExternalCloudAudit draft by:
// * Uploading a dummy file to both the audit events and session recordings S3 Buckets.
// * Tests get object on the session recordings bucket.
// * Tests the retrieval of the Glue table.
// * Runs a test query against the audit events bucket through Athena.
func (s *ExternalAuditStorageConnectionTester) TestConnection(ctx context.Context, req TestConnectionRequest) (types.ConnectionDiagnostic, error) {
	if req.ResourceKind != types.KindExternalCloudAudit {
		return nil, trace.BadParameter("invalid value for ResourceKind, expected %q got %q", types.KindExternalCloudAudit, req.ResourceKind)
	}

	connectionDiagnosticID := uuid.NewString()
	connectionDiagnostic, err := types.NewConnectionDiagnosticV1(
		connectionDiagnosticID,
		map[string]string{},
		types.ConnectionDiagnosticSpecV1{
			// We start with a failed state so that we don't need to set it to each return statement once an error is returned.
			// if the test reaches the end, we force the test to be a success by calling
			// 	connectionDiagnostic.SetMessage(types.DiagnosticMessageSuccess)
			//	connectionDiagnostic.SetSuccess(true)
			Message: types.DiagnosticMessageFailed,
		},
	)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := s.cfg.UserClient.CreateConnectionDiagnostic(ctx, connectionDiagnostic); err != nil {
		return nil, trace.Wrap(err)
	}

	// Test Connection to S3 Buckets
	diag, diagErr, err := s.handleBucketsTest(ctx, connectionDiagnosticID)
	if err != nil || diagErr != nil {
		return diag, diagErr
	}

	// Test Connection to Glue Table
	diag, diagErr, err = s.handleGlueTest(ctx, connectionDiagnosticID)
	if err != nil || diagErr != nil {
		return diag, diagErr
	}

	// Test Connection to Athena
	diag, diagErr, err = s.handleAthenaTest(ctx, connectionDiagnosticID)
	if err != nil || diagErr != nil {
		return diag, diagErr
	}

	traceType := types.ConnectionDiagnosticTrace_CONNECTIVITY
	const message = "External Audit Storage draft permissions are configured correctly."
	connDiag, err := s.appendDiagnosticTrace(ctx, connectionDiagnosticID, traceType, message, nil)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	connDiag.SetMessage(types.DiagnosticMessageSuccess)
	connDiag.SetSuccess(true)

	if err := s.cfg.UserClient.UpdateConnectionDiagnostic(ctx, connDiag); err != nil {
		return nil, trace.Wrap(err)
	}

	return connDiag, nil
}

func (s ExternalAuditStorageConnectionTester) handleBucketsTest(ctx context.Context, connectionDiagnosticID string) (types.ConnectionDiagnostic, error, error) {
	client := s.cfg.UserClient.ExternalCloudAuditClient()

	if err := client.TestDraftExternalCloudAuditBuckets(ctx); err != nil {
		const message = "Failed to test connection to storage buckets."
		traceType := types.ConnectionDiagnosticTrace_CONNECTIVITY
		diag, diagErr := s.appendDiagnosticTrace(ctx, connectionDiagnosticID, traceType, message, err)
		if diagErr != nil {
			return diag, trace.Wrap(diagErr), err
		}

		return diag, nil, err
	}

	const message = "Connection to storage buckets were successful."
	traceType := types.ConnectionDiagnosticTrace_CONNECTIVITY
	diag, diagErr := s.appendDiagnosticTrace(ctx, connectionDiagnosticID, traceType, message, nil)
	return diag, trace.Wrap(diagErr), nil
}

func (s ExternalAuditStorageConnectionTester) handleGlueTest(ctx context.Context, connectionDiagnosticID string) (types.ConnectionDiagnostic, error, error) {
	client := s.cfg.UserClient.ExternalCloudAuditClient()

	if err := client.TestDraftExternalCloudAuditGlue(ctx); err != nil {
		const message = "Failed to test connection to glue table."
		traceType := types.ConnectionDiagnosticTrace_CONNECTIVITY
		diag, diagErr := s.appendDiagnosticTrace(ctx, connectionDiagnosticID, traceType, message, err)
		if diagErr != nil {
			return diag, trace.Wrap(diagErr), err
		}

		return diag, nil, err
	}

	const message = "Connection to glue table was successful."
	traceType := types.ConnectionDiagnosticTrace_CONNECTIVITY
	diag, diagErr := s.appendDiagnosticTrace(ctx, connectionDiagnosticID, traceType, message, nil)
	return diag, trace.Wrap(diagErr), nil
}

func (s ExternalAuditStorageConnectionTester) handleAthenaTest(ctx context.Context, connectionDiagnosticID string) (types.ConnectionDiagnostic, error, error) {
	client := s.cfg.UserClient.ExternalCloudAuditClient()

	if err := client.TestDraftExternalCloudAuditAthena(ctx); err != nil {
		const message = "Failed to perform athena test query."
		traceType := types.ConnectionDiagnosticTrace_CONNECTIVITY
		diag, diagErr := s.appendDiagnosticTrace(ctx, connectionDiagnosticID, traceType, message, err)
		if err != nil {
			return diag, trace.Wrap(diagErr), err
		}

		return diag, nil, err
	}

	const message = "Athena test query was successful."
	traceType := types.ConnectionDiagnosticTrace_CONNECTIVITY
	diag, diagErr := s.appendDiagnosticTrace(ctx, connectionDiagnosticID, traceType, message, nil)
	return diag, trace.Wrap(diagErr), nil
}

func (s ExternalAuditStorageConnectionTester) appendDiagnosticTrace(ctx context.Context, connectionDiagnosticID string, traceType types.ConnectionDiagnosticTrace_TraceType, message string, err error) (types.ConnectionDiagnostic, error) {
	connDiag, err := s.cfg.UserClient.AppendDiagnosticTrace(
		ctx,
		connectionDiagnosticID,
		types.NewTraceDiagnosticConnection(
			traceType,
			message,
			err,
		))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return connDiag, nil
}
