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

package aws

import (
	"regexp"
	"strings"

	"github.com/gravitational/trace"
)

// IsValidAccountID checks whether the accountID is a valid AWS Account ID
//
// https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-identifiers.html
func IsValidAccountID(accountID string) error {
	if len(accountID) != 12 {
		return trace.BadParameter("must be 12-digit")
	}
	for _, d := range accountID {
		if d < '0' || d > '9' {
			return trace.BadParameter("must be 12-digit")
		}
	}

	return nil
}

// IsValidIAMRoleName checks whether the role name is a valid AWS IAM Role identifier.
//
// > Length Constraints: Minimum length of 1. Maximum length of 64.
// > Pattern: [\w+=,.@-]+
// https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateRole.html
func IsValidIAMRoleName(roleName string) error {
	if len(roleName) == 0 || len(roleName) > 64 || !matchRoleName(roleName) {
		return trace.BadParameter("role is invalid")
	}

	return nil
}

// IsValidRegion ensures the region looks to be valid.
// It does not do a full validation, because AWS doesn't provide documentation for that.
// However, they usually only have the following chars: [a-z0-9\-]
func IsValidRegion(region string) error {
	if matchRegion.MatchString(region) {
		return nil
	}
	return trace.BadParameter("region %q is invalid", region)
}

const (
	arnDelimiter    = ":"
	arnPrefix       = "arn:"
	arnSections     = 6
	sectionService  = 2 // arn:<partition>:<service>:...
	sectionAccount  = 4 // arn:<partition>:<service>:<region>:<accountid>:...
	sectionResource = 5 // arn:<partition>:<service>:<region>:<accountid>:<resource>
	iamServiceName  = "iam"
)

// CheckRoleARN returns whether a string is a valid IAM Role ARN.
// Example role ARN: arn:aws:iam::123456789012:role/some-role-name
func CheckRoleARN(arn string) error {
	if !strings.HasPrefix(arn, arnPrefix) {
		return trace.BadParameter("arn: invalid prefix: %q", arn)
	}

	sections := strings.SplitN(arn, arnDelimiter, arnSections)
	if len(sections) != arnSections {
		return trace.BadParameter("arn: not enough sections: %q", arn)
	}

	resourceParts := strings.SplitN(sections[sectionResource], "/", 2)

	if resourceParts[0] != "role" || sections[sectionService] != iamServiceName {
		return trace.BadParameter("%q is not an AWS IAM role ARN", arn)
	}

	if len(resourceParts) < 2 || resourceParts[1] == "" {
		return trace.BadParameter("%q is missing AWS IAM role name", arn)
	}

	if err := IsValidAccountID(sections[sectionAccount]); err != nil {
		return trace.BadParameter("%q invalid account ID: %v", arn, err)
	}

	return nil
}

var (
	// matchRoleName is a regex that matches against AWS IAM Role Names.
	matchRoleName = regexp.MustCompile(`^[\w+=,.@-]+$`).MatchString

	// matchRegion is a regex that defines the format of AWS regions.
	//
	// The regex matches the following from left to right:
	// - starts with 2 lower case letters that represents a geo region like a
	//   country code
	// - optional -gov, -iso, -isob for corresponding partitions
	// - a word that should be a direction like "east", "west", etc.
	// - a number counter
	//
	// Reference:
	// https://github.com/aws/aws-sdk-go-v2/blob/main/codegen/smithy-aws-go-codegen/src/main/resources/software/amazon/smithy/aws/go/codegen/endpoints.json
	matchRegion = regexp.MustCompile(`^[a-z]{2}(-gov|-iso|-isob)?-\w+-\d+$`)
)
