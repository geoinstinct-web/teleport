/*
Copyright 2023 Gravitational, Inc.

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

package awsoidc

import (
	"context"
	"fmt"
	"strconv"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2Types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/google/go-cmp/cmp"
	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"
)

type mockListEC2ICEClient struct {
	pageSize  int
	accountID string
	ec2ICEs   []ec2Types.Ec2InstanceConnectEndpoint
}

// Returns information about ec2 instances.
// This API supports pagination.
func (m mockListEC2ICEClient) DescribeInstanceConnectEndpoints(ctx context.Context, params *ec2.DescribeInstanceConnectEndpointsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstanceConnectEndpointsOutput, error) {
	requestedPage := 1

	totalEndpoints := len(m.ec2ICEs)

	if params.NextToken != nil {
		currentMarker, err := strconv.Atoi(*params.NextToken)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		requestedPage = currentMarker
	}

	sliceStart := m.pageSize * (requestedPage - 1)
	sliceEnd := m.pageSize * requestedPage
	if sliceEnd > totalEndpoints {
		sliceEnd = totalEndpoints
	}

	ret := &ec2.DescribeInstanceConnectEndpointsOutput{
		InstanceConnectEndpoints: m.ec2ICEs[sliceStart:sliceEnd],
	}

	if sliceEnd < totalEndpoints {
		nextToken := strconv.Itoa(requestedPage + 1)
		ret.NextToken = &nextToken
	}

	return ret, nil
}

func TestListEC2ICE(t *testing.T) {
	ctx := context.Background()

	noErrorFunc := func(err error) bool {
		return err == nil
	}

	const pageSize = 100
	t.Run("pagination", func(t *testing.T) {
		totalEC2ICEs := 203

		allEndpoints := make([]ec2Types.Ec2InstanceConnectEndpoint, 0, totalEC2ICEs)
		for i := 0; i < totalEC2ICEs; i++ {
			allEndpoints = append(allEndpoints, ec2Types.Ec2InstanceConnectEndpoint{
				SubnetId:                  aws.String(fmt.Sprintf("subnet-%d", i)),
				InstanceConnectEndpointId: aws.String("ice-name"),
				State:                     "create-complete",
			})
		}

		mockListClient := &mockListEC2ICEClient{
			pageSize:  pageSize,
			accountID: "123456789012",
			ec2ICEs:   allEndpoints,
		}

		// First page must return pageSize number of Endpoints
		resp, err := ListEC2ICE(ctx, mockListClient, ListEC2ICERequest{
			VPCID:     "vpc-123",
			NextToken: "",
		})
		require.NoError(t, err)
		require.NotEmpty(t, resp.NextToken)
		require.Len(t, resp.EC2ICEs, pageSize)
		nextPageToken := resp.NextToken
		require.Equal(t, resp.EC2ICEs[0].SubnetID, "subnet-0")

		// Second page must return pageSize number of Endpoints
		resp, err = ListEC2ICE(ctx, mockListClient, ListEC2ICERequest{
			VPCID:     "vpc-abc",
			NextToken: nextPageToken,
		})
		require.NoError(t, err)
		require.NotEmpty(t, resp.NextToken)
		require.Len(t, resp.EC2ICEs, pageSize)
		nextPageToken = resp.NextToken
		require.Equal(t, resp.EC2ICEs[0].SubnetID, "subnet-100")

		// Third page must return only the remaining Endpoints and an empty nextToken
		resp, err = ListEC2ICE(ctx, mockListClient, ListEC2ICERequest{
			VPCID:     "vpc-abc",
			NextToken: nextPageToken,
		})
		require.NoError(t, err)
		require.Empty(t, resp.NextToken)
		require.Len(t, resp.EC2ICEs, 3)
		require.Equal(t, resp.EC2ICEs[0].SubnetID, "subnet-200")
	})

	for _, tt := range []struct {
		name          string
		req           ListEC2ICERequest
		mockEndpoints []ec2Types.Ec2InstanceConnectEndpoint
		errCheck      func(error) bool
		respCheck     func(*testing.T, *ListEC2ICEResponse)
	}{
		{
			name: "valid for listing instances",
			req: ListEC2ICERequest{
				VPCID:     "vpc-abcd",
				NextToken: "",
			},
			mockEndpoints: []ec2Types.Ec2InstanceConnectEndpoint{{
				SubnetId:                  aws.String("subnet-123"),
				InstanceConnectEndpointId: aws.String("ice-name"),
				State:                     "create-complete",
			},
			},
			respCheck: func(t *testing.T, ldr *ListEC2ICEResponse) {
				require.Len(t, ldr.EC2ICEs, 1, "expected 1 endpoint, got %d", len(ldr.EC2ICEs))
				require.Empty(t, ldr.NextToken, "expected an empty NextToken")

				endpoint := EC2InstanceConnectEndpoint{
					Name:     "ice-name",
					State:    "create-complete",
					SubnetID: "subnet-123",
				}
				require.Empty(t, cmp.Diff(endpoint, ldr.EC2ICEs[0]))
			},
			errCheck: noErrorFunc,
		},
		{
			name:     "no vpc id",
			req:      ListEC2ICERequest{},
			errCheck: trace.IsBadParameter,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mockListClient := &mockListEC2ICEClient{
				pageSize:  pageSize,
				accountID: "123456789012",
				ec2ICEs:   tt.mockEndpoints,
			}
			resp, err := ListEC2ICE(ctx, mockListClient, tt.req)
			require.True(t, tt.errCheck(err), "unexpected err: %v", err)
			if tt.respCheck != nil {
				tt.respCheck(t, resp)
			}
		})
	}
}
