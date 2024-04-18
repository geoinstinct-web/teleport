/*
 * Teleport
 * Copyright (C) 2024  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package auth

import (
	"context"
	"crypto/x509"
	"log/slog"

	"github.com/google/go-attestation/attest"
	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/modules"
	"github.com/gravitational/teleport/lib/tpm"
)

func (a *Server) RegisterUsingTPMMethod(
	ctx context.Context,
	initReq *proto.RegisterUsingTPMMethodInitialRequest,
	solveChallenge client.RegisterTPMChallengeResponseFunc,
) (*proto.Certs, error) {
	// First, check the specified token exists, and is a TPM-type join token.
	if err := initReq.JoinRequest.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	pt, err := a.checkTokenJoinRequestCommon(ctx, initReq.JoinRequest)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	ptv2 := pt.(*types.ProvisionTokenV2)
	if ptv2.Spec.JoinMethod != types.JoinMethodTPM {
		return nil, trace.AccessDenied("specified join token is not for `tpm` method")
	}

	if modules.GetModules().BuildType() != modules.BuildEnterprise {
		return nil, trace.AccessDenied("tpm joining requires Teleport Enterprise")
	}

	// Convert configured CAs to a CAPool
	var certPool *x509.CertPool
	if len(ptv2.Spec.TPM.EKCertAllowedCAs) > 0 {
		certPool = x509.NewCertPool()
		for i, ca := range ptv2.Spec.TPM.EKCertAllowedCAs {
			if ok := certPool.AppendCertsFromPEM([]byte(ca)); !ok {
				return nil, trace.BadParameter(
					"failed to append ekcert_allowed_cas[%d] to cert pool", i,
				)
			}
		}
	}

	validatedEK, err := a.tpmValidator(ctx, slog.Default(), tpm.ValidateParams{
		EKCert:       initReq.GetEkCert(),
		EKKey:        initReq.GetEkKey(),
		AttestParams: tpm.AttestationParametersFromProto(initReq.AttestationParams),
		AllowedCAs:   certPool,
		Solve: func(ec *attest.EncryptedCredential) ([]byte, error) {
			solution, err := solveChallenge(tpm.EncryptedCredentialToProto(ec))
			if err != nil {
				return nil, trace.Wrap(err)
			}
			return solution.Solution, nil
		},
	})
	if err != nil {
		return nil, trace.Wrap(err, "validating TPM EK")
	}

	if err := checkTPMAllowRules(validatedEK, ptv2.Spec.TPM.Allow); err != nil {
		return nil, trace.Wrap(err)
	}

	if initReq.JoinRequest.Role == types.RoleBot {
		certs, err := a.generateCertsBot(
			ctx, ptv2, initReq.JoinRequest, validatedEK,
		)
		return certs, trace.Wrap(err, "generating certs for bot")
	}
	certs, err := a.generateCerts(
		ctx, ptv2, initReq.JoinRequest, validatedEK,
	)
	return certs, trace.Wrap(err, "generating certs for host")
}

func checkTPMAllowRules(tpm *tpm.ValidatedTPM, rules []*types.ProvisionTokenSpecV2TPM_Rule) error {
	// If a single rule passes, accept the TPM
	for _, rule := range rules {
		if rule.EKPublicHash != "" && tpm.EKPubHash != rule.EKPublicHash {
			continue
		}
		if rule.EKCertificateSerial != "" && tpm.EKCertSerial != rule.EKCertificateSerial {
			continue
		}

		// All rules met.
		return nil
	}
	return trace.AccessDenied("validated tpm attributes did not match any allow rules")
}
